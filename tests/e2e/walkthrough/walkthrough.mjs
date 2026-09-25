// Card U-1/U-2: the robot that walks the product's screens before the owner
// does.
//
// The Go stand (tests/integration/postgres/u1_walkthrough_test.go) starts the
// local synthetic environment, serves the real web interface and passes the
// stand URL here. For an owner-facing stand the same script is started directly
// with KNOWVAULT_WALKTHROUGH_TARGET=stand; then it signs in with the login from
// a credentials file and walks the read-only scenario. It writes the per-step
// report with screenshots, timings, 5xx responses, console errors and the text
// of every answer.
//
// Environment:
//   KNOWVAULT_WALKTHROUGH_BASE_URL      stand origin (required)
//   KNOWVAULT_WALKTHROUGH_REPORT_DIR    output directory (default: ./baseline)
//   KNOWVAULT_WALKTHROUGH_SCENARIO      local | read-only (default: local)
//   KNOWVAULT_WALKTHROUGH_CREDENTIALS   credentials file read at run time
//   KNOWVAULT_WALKTHROUGH_USER          test user, if the file has no username
//   KNOWVAULT_WALKTHROUGH_QUESTION      chat question, local scenario only
//
// It exits 0 only when every step passed. The password from the credentials
// file never reaches the report, the logs or a screenshot.

import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { readCredentials, redactSecrets } from "./credentials.mjs";
import { buildReport, Walkthrough, writeReport } from "./report.mjs";
import { SCENARIOS } from "./scenarios.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
// The browser tool is test infrastructure only; the module is resolved at run
// time so a machine that keeps Playwright outside the repository can point at
// it. The product never imports this package.
const playwrightModule = (process.env.KNOWVAULT_PLAYWRIGHT_MODULE ?? "playwright").trim();
const { chromium } = await import(playwrightModule);

function required(name) {
  const value = process.env[name];
  if (value === undefined || value.trim() === "") {
    throw new Error(`${name} is required`);
  }
  return value.trim();
}

const baseURL = required("KNOWVAULT_WALKTHROUGH_BASE_URL").replace(/\/+$/, "");
const reportDir = (process.env.KNOWVAULT_WALKTHROUGH_REPORT_DIR ?? path.join(here, "baseline")).trim();
const question = process.env.KNOWVAULT_WALKTHROUGH_QUESTION ?? "что ты знаешь?";
const scenarioName = (process.env.KNOWVAULT_WALKTHROUGH_SCENARIO ?? "local").trim();
const scenario = SCENARIOS[scenarioName];
if (scenario === undefined) {
  throw new Error(`KNOWVAULT_WALKTHROUGH_SCENARIO=${scenarioName}, want one of ${Object.keys(SCENARIOS).join(", ")}`);
}
const command = "bash tests/e2e/walkthrough/run-walkthrough.sh";

// The login is read at run time, kept in memory, and passed nowhere else. Only
// the file path appears in the environment and in a command line.
const credentialsPath = (process.env.KNOWVAULT_WALKTHROUGH_CREDENTIALS ?? "").trim();
let credentials = null;
if (credentialsPath !== "") {
  credentials = await readCredentials(credentialsPath);
  if (credentials.username === "") {
    credentials.username = (process.env.KNOWVAULT_WALKTHROUGH_USER ?? "").trim();
  }
  if (credentials.username === "") {
    throw new Error("set KNOWVAULT_WALKTHROUGH_USER or put a username in the credentials file");
  }
}
const secrets = credentials === null ? [] : [credentials.password];
const redact = (value) => redactSecrets(value, secrets);

async function run() {
  const screenshotsDir = path.join(reportDir, "screenshots");
  await mkdir(screenshotsDir, { recursive: true });

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext({
    viewport: { width: 1440, height: 900 },
    ignoreHTTPSErrors: true,
    locale: "ru-RU",
  });
  const page = await context.newPage();
  // The product asks for explicit consent before a confirmation and before a
  // few destructive-looking actions. The robot is the operator, so it accepts.
  page.on("dialog", (dialog) => void dialog.accept());
  const walk = new Walkthrough(page, { screenshotDir: screenshotsDir, origin: baseURL, redact });
  const startedAt = new Date();

  try {
    await scenario(page, walk, { baseURL, credentials, question });
  } finally {
    await context.close();
    await browser.close();
  }

  const report = buildReport({
    baseURL,
    command,
    scenario: scenarioName,
    startedAt,
    finishedAt: new Date(),
    steps: walk.steps,
    redact,
  });
  const { markdownPath, jsonPath } = await writeReport(reportDir, report);
  console.log(`walkthrough ${report.passed ? "PASS" : "FAIL"}: ${report.step_count} steps, ${report.failed_step_count} failed`);
  console.log(`report ${markdownPath}`);
  console.log(`report ${jsonPath}`);
  if (!report.passed) {
    for (const step of report.steps.filter((item) => item.status === "failed")) {
      console.log(`failed step: ${step.name}${step.error !== null ? ` (${step.error})` : ""}`);
    }
    process.exitCode = 1;
  }
}

run().catch((error) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  console.error(redact(message));
  process.exitCode = 1;
});
