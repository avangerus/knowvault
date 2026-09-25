// Card U-1 walkthrough report: one record per screen step with its own
// screenshot, duration, HTTP responses, and browser console errors.
//
// The recorder is transport-agnostic: a step fails when its own action threw,
// when any request it caused answered 5xx (with the request path), or when the
// browser raised an uncaught error while it was the active step. Console
// errors are always recorded and rendered, even when the step still passes:
// Chromium reports every failed HTTP response as a console error, and a
// signed-out session probe is a 401 the product expects, not a step failure.
// Nothing here touches product code.

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";

export const REPORT_SCHEMA_VERSION = "walkthrough-report-v1";

// requestPathOf reduces an absolute request URL to the origin-relative request
// path, which is what a reader can act on. A non-URL value is returned as-is.
export function requestPathOf(rawURL) {
  try {
    const parsed = new URL(rawURL);
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return String(rawURL ?? "");
  }
}

// stepFailed is the one classification rule: an action error, any 5xx response
// seen during the step, or any uncaught browser error seen during it.
export function stepFailed(step) {
  return Boolean(step.error) || step.httpErrors.length > 0 || step.pageErrors.length > 0;
}

export function slug(value) {
  return String(value)
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 60) || "step";
}

export class Walkthrough {
  constructor(page, options = {}) {
    this.page = page;
    this.screenshotDir = options.screenshotDir ?? null;
    this.steps = [];
    this.current = null;
    page.on("response", (response) => {
      const step = this.current;
      if (step === null) return;
      const status = response.status();
      if (status < 400) return;
      const entry = {
        status,
        method: response.request().method(),
        path: requestPathOf(response.url()),
        code: null,
        body: null,
      };
      (status >= 500 ? step.httpErrors : step.httpClientErrors).push(entry);
      // The body is read asynchronously and lands in the entry the report
      // already holds, so a server error code is visible without blocking the
      // step. A response without a readable body leaves both fields null.
      response
        .text()
        .then((body) => {
          entry.body = body.slice(0, 300);
          try {
            entry.code = JSON.parse(body)?.error?.code ?? null;
          } catch {
            entry.code = null;
          }
        })
        .catch(() => {});
    });
    page.on("console", (message) => {
      if (this.current === null || message.type() !== "error") return;
      this.current.consoleErrors.push(message.text());
    });
    page.on("pageerror", (error) => {
      if (this.current === null) return;
      const text = error instanceof Error ? error.message : String(error);
      this.current.pageErrors.push(text);
      this.current.consoleErrors.push(text);
    });
  }

  async step(name, action) {
    const step = {
      name,
      status: "passed",
      started_at: new Date().toISOString(),
      seconds: 0,
      screenshot: null,
      httpErrors: [],
      httpClientErrors: [],
      consoleErrors: [],
      pageErrors: [],
      error: null,
      page_excerpt: null,
    };
    this.current = step;
    const started = process.hrtime.bigint();
    try {
      await action();
    } catch (error) {
      step.error = error instanceof Error ? error.message : String(error);
    } finally {
      step.seconds = Number(process.hrtime.bigint() - started) / 1e9;
      this.current = null;
    }
    if (this.screenshotDir !== null) {
      const file = `${String(this.steps.length + 1).padStart(2, "0")}-${slug(name)}.png`;
      try {
        await this.page.screenshot({ path: path.join(this.screenshotDir, file), fullPage: true });
        step.screenshot = path.posix.join("screenshots", file);
      } catch (error) {
        step.screenshotError = error instanceof Error ? error.message : String(error);
      }
    }
    step.status = stepFailed(step) ? "failed" : "passed";
    if (step.status === "failed") {
      // A failing step records what the screen actually said, so the report
      // explains the failure without a second reproduction.
      try {
        step.page_excerpt = (await this.page.evaluate(() => (document.body ? document.body.innerText : ""))).slice(0, 2000);
      } catch {
        step.page_excerpt = null;
      }
    }
    this.steps.push(step);
    return step;
  }
}

export function buildReport({ baseURL, command, startedAt, finishedAt, steps }) {
  const failed = steps.filter((step) => step.status === "failed");
  return {
    schema_version: REPORT_SCHEMA_VERSION,
    command,
    base_url: baseURL,
    started_at: startedAt.toISOString(),
    finished_at: finishedAt.toISOString(),
    total_seconds: Math.round(((finishedAt.getTime() - startedAt.getTime()) / 1000) * 1000) / 1000,
    passed: failed.length === 0,
    step_count: steps.length,
    failed_step_count: failed.length,
    failed_steps: failed.map((step) => step.name),
    steps,
  };
}

function bulletList(values) {
  if (values.length === 0) return "- none\n";
  return values.map((value) => `- ${value}\n`).join("");
}

function httpLine(error) {
  const code = error.code !== null && error.code !== undefined ? ` (${error.code})` : "";
  return `${error.method} ${error.path} -> ${error.status}${code}`;
}

export function renderMarkdown(report) {
  const lines = [];
  lines.push("# Walkthrough report (card U-1)\n\n");
  lines.push("A robot walked the real web interface of the local synthetic stand.\n\n");
  lines.push(`- Command: \`${report.command}\`\n`);
  lines.push(`- Stand: ${report.base_url}\n`);
  lines.push(`- Started: ${report.started_at}\n`);
  lines.push(`- Finished: ${report.finished_at}\n`);
  lines.push(`- Total: ${report.total_seconds} s\n`);
  lines.push(`- Result: **${report.passed ? "PASS" : "FAIL"}** (${report.step_count} steps, ${report.failed_step_count} failed)\n\n`);
  lines.push("## Steps\n\n");
  report.steps.forEach((step, index) => {
    lines.push(`### ${index + 1}. ${step.name} — ${step.status} (${step.seconds.toFixed(2)} s)\n\n`);
    if (step.screenshot !== null) {
      lines.push(`![${step.name}](${step.screenshot})\n\n`);
    }
    if (step.error !== null) {
      lines.push(`Failure: ${step.error}\n\n`);
    }
    if (step.screenshotError !== undefined) {
      lines.push(`Screenshot error: ${step.screenshotError}\n\n`);
    }
    lines.push(`HTTP responses >= 500 (${step.httpErrors.length}):\n\n`);
    lines.push(bulletList(step.httpErrors.map(httpLine)));
    lines.push(`\nBrowser console errors (${step.consoleErrors.length}):\n\n`);
    lines.push(bulletList(step.consoleErrors));
    if (step.httpClientErrors.length > 0) {
      lines.push(`\nHTTP responses 400-499 (${step.httpClientErrors.length}):\n\n`);
      lines.push(bulletList(step.httpClientErrors.map(httpLine)));
    }
    if (step.page_excerpt !== null && step.page_excerpt !== undefined) {
      lines.push("\nScreen text at failure:\n\n```text\n");
      lines.push(step.page_excerpt);
      lines.push("\n```\n");
    }
    lines.push("\n");
  });
  return lines.join("");
}

export async function writeReport(reportDir, report) {
  await mkdir(reportDir, { recursive: true });
  const markdownPath = path.join(reportDir, "report.md");
  const jsonPath = path.join(reportDir, "report.json");
  await writeFile(markdownPath, renderMarkdown(report), "utf8");
  await writeFile(jsonPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  return { markdownPath, jsonPath };
}
