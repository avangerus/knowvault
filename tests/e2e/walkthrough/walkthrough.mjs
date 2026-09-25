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
// Card U-3 adds the screen comparison. Every step's screenshot is measured
// against the approved reference picture of that step:
//   local runs   enforce: a step beyond the threshold fails and the run fails;
//   stand runs   report: the difference is reported, the stand's data is not a
//                build regression, so the step is not failed;
//   update run   update: KNOWVAULT_WALKTHROUGH_UPDATE_REFERENCES=1 replaces the
//                approved references and the report names every one that changed.
// An ordinary run never writes inside the reference directory.
//
// Environment:
//   KNOWVAULT_WALKTHROUGH_BASE_URL      stand origin (required)
//   KNOWVAULT_WALKTHROUGH_REPORT_DIR    output directory (default: ./baseline)
//   KNOWVAULT_WALKTHROUGH_SCENARIO      local | read-only (default: local)
//   KNOWVAULT_WALKTHROUGH_CREDENTIALS   credentials file read at run time
//   KNOWVAULT_WALKTHROUGH_USER          test user, if the file has no username
//   KNOWVAULT_WALKTHROUGH_QUESTION      chat question, local scenario only
//   KNOWVAULT_WALKTHROUGH_REVISION      commit the local stand was built from;
//                                       the local scenario asserts its short
//                                       form is on screen (card W-4)
//   KNOWVAULT_WALKTHROUGH_REFERENCE_DIR approved reference pictures; defaults
//                                       to references/<scenario> next to this
//                                       file; required outside the repository
//                                       when a stand run replaces references
//   KNOWVAULT_WALKTHROUGH_UPDATE_REFERENCES  1 replaces the approved references
//                                       with this run's screenshots
//
// It exits 0 only when every step passed. The password from the credentials
// file never reaches the report, the logs or a screenshot.

import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { readCredentials, redactSecrets } from "./credentials.mjs";
import { buildReport, formatPercent, Walkthrough, writeReport } from "./report.mjs";
import { SCENARIOS } from "./scenarios.mjs";
import { DEFAULT_DIFFERENCE_THRESHOLD, DEFAULT_PIXEL_TOLERANCE } from "./visual.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(here, "..", "..", "..");
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

// isInside reports whether a path lies inside a directory. It decides whether a
// reference directory would put data into the repository.
function isInside(directory, candidate) {
  const relative = path.relative(directory, path.resolve(candidate));
  return relative !== "" && !relative.startsWith("..") && !path.isAbsolute(relative);
}

// labelFor renders a path for the report: relative to the repository when it is
// inside it, absolute otherwise.
function labelFor(candidate) {
  const absolute = path.resolve(candidate);
  return isInside(repositoryRoot, absolute) ? path.relative(repositoryRoot, absolute).split(path.sep).join("/") : path.resolve(absolute).split(path.sep).join("/");
}

const target = (process.env.KNOWVAULT_WALKTHROUGH_TARGET ?? "local").trim();
const baseURL = required("KNOWVAULT_WALKTHROUGH_BASE_URL").replace(/\/+$/, "");
const reportDir = (process.env.KNOWVAULT_WALKTHROUGH_REPORT_DIR ?? path.join(here, "baseline")).trim();
const question = process.env.KNOWVAULT_WALKTHROUGH_QUESTION ?? "что ты знаешь?";
const revision = (process.env.KNOWVAULT_WALKTHROUGH_REVISION ?? "").trim();
const scenarioName = (process.env.KNOWVAULT_WALKTHROUGH_SCENARIO ?? "local").trim();
const scenario = SCENARIOS[scenarioName];
if (scenario === undefined) {
  throw new Error(`KNOWVAULT_WALKTHROUGH_SCENARIO=${scenarioName}, want one of ${Object.keys(SCENARIOS).join(", ")}`);
}
const command = "bash tests/e2e/walkthrough/run-walkthrough.sh";

// Card U-3: which references, and what a difference means.
const updateReferences = (process.env.KNOWVAULT_WALKTHROUGH_UPDATE_REFERENCES ?? "").trim() === "1";
const referenceDirEnv = (process.env.KNOWVAULT_WALKTHROUGH_REFERENCE_DIR ?? "").trim();
const referenceDir = referenceDirEnv !== "" ? referenceDirEnv : path.join(here, "references", scenarioName === "read-only" ? "read-only" : "local");
const referenceLabel = labelFor(referenceDir);
let visualMode;
if (updateReferences) {
  visualMode = "update";
} else if (scenarioName === "read-only") {
  visualMode = "report";
} else {
  visualMode = "enforce";
}
if (updateReferences && target === "stand" && isInside(repositoryRoot, referenceDir)) {
  // A stand holds owner data; its references are never committed. The default
  // reference directory is inside the repository, so a stand update must name
  // one outside it.
  throw new Error(`refusing to replace references inside the repository for the stand target: ${referenceLabel}`);
}
const thresholdValue = (process.env.KNOWVAULT_WALKTHROUGH_DIFFERENCE_THRESHOLD ?? "").trim();
const differenceThreshold = thresholdValue === "" ? DEFAULT_DIFFERENCE_THRESHOLD : Number(thresholdValue);
if (!Number.isFinite(differenceThreshold) || differenceThreshold < 0) {
  throw new Error(`KNOWVAULT_WALKTHROUGH_DIFFERENCE_THRESHOLD=${thresholdValue}, want a number >= 0`);
}

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

// How long a toast lives into the next step depends on how fast that step ran,
// and a webfont or a CSS transition that lands between two screenshots moves
// text by a few pixels. Both are exactly the kind of between-runs change the
// comparison must not count, so before every picture the robot waits for the
// transient overlay to go, for the fonts to be ready and for running
// animations to finish. This only delays the screenshot: it changes no action
// and, on a stand, no request.
async function settleScreen(page) {
  await page
    .locator(".toast-host")
    .waitFor({ state: "detached", timeout: 8_000 })
    .catch(() => {});
  await page
    .evaluate(async () => {
      if (document.fonts && document.fonts.ready) await document.fonts.ready;
      if (document.getAnimations) {
        await Promise.race([
          Promise.all(document.getAnimations().map((animation) => animation.finished.catch(() => undefined))),
          new Promise((resolve) => setTimeout(resolve, 1_000)),
        ]);
      }
    })
    .catch(() => {});
  await page.waitForTimeout(100);
}

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
  const walk = new Walkthrough(page, {
    screenshotDir: screenshotsDir,
    origin: baseURL,
    redact,
    visualMode,
    referenceDir,
    referenceLabel,
    differenceDir: path.join(reportDir, "differences"),
    differenceThreshold,
    pixelTolerance: DEFAULT_PIXEL_TOLERANCE,
    beforeScreenshot: settleScreen,
  });
  const startedAt = new Date();

  try {
    await scenario(page, walk, { baseURL, credentials, question, revision });
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
    visual: {
      mode: visualMode,
      threshold: differenceThreshold,
      pixelTolerance: DEFAULT_PIXEL_TOLERANCE,
      referenceLabel,
    },
  });
  const { markdownPath, jsonPath } = await writeReport(reportDir, report);
  console.log(`walkthrough ${report.passed ? "PASS" : "FAIL"}: ${report.step_count} steps, ${report.failed_step_count} failed`);
  if (report.visual.mode !== "off") {
    console.log(
      `screen comparison ${report.visual.mode}: ${report.visual.compared_step_count} compared, ` +
        `${report.visual.differing_step_count} above ${formatPercent(report.visual.difference_threshold)}, ` +
        `largest ${formatPercent(report.visual.max_difference_ratio)}, ${report.visual.missing_reference_count} without a reference`,
    );
  }
  for (const update of report.visual.references_updated) {
    const measured = typeof update.difference_ratio === "number" ? ` (was ${formatPercent(update.difference_ratio)} different)` : "";
    console.log(`reference ${update.change}: ${update.reference}${measured}`);
  }
  console.log(`report ${markdownPath}`);
  console.log(`report ${jsonPath}`);
  if (!report.passed) {
    for (const step of report.steps.filter((item) => item.status === "failed")) {
      const reason = step.visual_failure ?? step.error;
      console.log(`failed step: ${step.name}${reason !== null && reason !== undefined ? ` (${reason})` : ""}`);
    }
    process.exitCode = 1;
  }
}

run().catch((error) => {
  const message = error instanceof Error ? error.stack ?? error.message : String(error);
  console.error(redact(message));
  process.exitCode = 1;
});
