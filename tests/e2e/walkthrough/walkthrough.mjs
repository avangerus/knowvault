// Card U-1: the robot that walks the product's screens before the owner does.
//
// The Go stand (tests/integration/postgres/u1_walkthrough_test.go) starts the
// local synthetic environment, serves the real web interface and passes the
// stand URL here. This script drives a real headless browser through the card's
// scenario in order and writes the per-step report with screenshots, timings,
// 5xx responses and console errors.
//
// Environment:
//   KNOWVAULT_WALKTHROUGH_BASE_URL  stand origin (required)
//   KNOWVAULT_WALKTHROUGH_REPORT_DIR output directory (default: ./baseline)
//   KNOWVAULT_WALKTHROUGH_QUESTION   chat question (default: что ты знаешь?)
//
// It exits 0 only when every step passed.

import { mkdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Walkthrough, buildReport, writeReport } from "./report.mjs";

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
const command = "bash tests/e2e/walkthrough/run-walkthrough.sh";

async function waitForHeading(page, name) {
  await page.getByRole("heading", { name, exact: true }).first().waitFor({ state: "visible", timeout: 30_000 });
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
  const walk = new Walkthrough(page, { screenshotDir: screenshotsDir });
  const startedAt = new Date();

  try {
    await walk.step("sign in as the test user", async () => {
      await page.goto(`${baseURL}/`, { waitUntil: "domcontentloaded", timeout: 30_000 });
      const signIn = page.locator('a[href="/auth/login"]').first();
      await signIn.waitFor({ state: "visible", timeout: 30_000 });
      await signIn.click();
      await page.locator("nav.rail").waitFor({ state: "visible", timeout: 30_000 });
    });

    await walk.step("open Sources and confirm the synthetic database tables", async () => {
      await page.locator('nav.rail button[aria-label="Sources"]').click();
      await waitForHeading(page, "Sources");
      const confirmButtons = page.locator("button.source-confirm-batch-action");
      await confirmButtons.first().waitFor({ state: "visible", timeout: 30_000 });
      // Confirm every connection's awaiting tables. A successful confirmation
      // removes that card's control when the source list refreshes. The click
      // target is captured as an element handle, so waiting for it to detach
      // waits for that exact card rather than for whichever control happens to
      // be first after the refresh. A refusal leaves the button in place and
      // the wait times out, which is exactly the failure the card reports.
      let rounds = 0;
      for (;;) {
        await page
          .locator('p.evidence-state:has-text("Loading sources")')
          .waitFor({ state: "detached", timeout: 5_000 })
          .catch(() => {});
        if ((await confirmButtons.count()) === 0) {
          // A refresh may not have started yet when the count was taken; a
          // short settle distinguishes "all confirmed" from "mid-refresh".
          await page.waitForTimeout(500);
          if ((await confirmButtons.count()) === 0) break;
          continue;
        }
        if (++rounds > 20) {
          throw new Error("still tables awaiting confirmation after 20 rounds");
        }
        const handle = await confirmButtons.first().elementHandle();
        await handle.click();
        await handle.waitForElementState("hidden", { timeout: 30_000 });
      }
      await page.locator("p.source-confirm-batch-summary").first().waitFor({ state: "visible", timeout: 30_000 });
    });

    await walk.step("open the model settings and save a change", async () => {
      await page.locator('nav.rail button[aria-label="Settings"]').click();
      await waitForHeading(page, "Workspace model context");
      const description = page.locator("section#model-context-panel-description textarea");
      await description.waitFor({ state: "visible", timeout: 30_000 });
      const before = await description.inputValue();
      await description.fill(`${before} (U-1 walkthrough change)`);
      await page.locator(".model-context-head button.primary-button").click();
      await page.getByText("Model context saved.").first().waitFor({ state: "visible", timeout: 30_000 });
    });

    await walk.step("ask the question in the chat and get an answer", async () => {
      await page.locator('nav.rail button[aria-label="Search"]').click();
      const composer = page.locator("textarea#ask-question");
      await composer.waitFor({ state: "visible", timeout: 30_000 });
      await composer.fill(question);
      await page.locator('button[aria-label="Ask"]').click();
      // The answer is rendered as a turn that carries at least one citation
      // control: a footnote mark woven into the text, or a basis row when the
      // server returned a citation the answer text did not reference.
      await page.locator("article.turn").first().waitFor({ state: "visible", timeout: 180_000 });
      await page.locator("button.fn, button.basis").first().waitFor({ state: "visible", timeout: 30_000 });
    });

    await walk.step("open the evidence of that answer", async () => {
      await page.locator("button.fn, button.basis").first().click();
      await page.waitForFunction(
        () => {
          const header = document.querySelector('aside[aria-label="Answer evidence"] .evi-h');
          return header !== null && (header.textContent ?? "").includes("observed");
        },
        undefined,
        { timeout: 30_000 },
      );
    });
  } finally {
    await context.close();
    await browser.close();
  }

  const report = buildReport({ baseURL, command, startedAt, finishedAt: new Date(), steps: walk.steps });
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
  console.error(error instanceof Error ? error.stack ?? error.message : String(error));
  process.exitCode = 1;
});
