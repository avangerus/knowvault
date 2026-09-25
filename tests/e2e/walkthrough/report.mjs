// Card U-1 walkthrough report: one record per screen step with its own
// screenshot, duration, HTTP responses, and browser console errors.
//
// Card U-2 adds three things to the same report shape:
//   - the text of every answer the robot waited for, so the stand report shows
//     what the product actually said, not only that a step passed;
//   - the mutating HTTP requests each step caused, so a read-only scenario can
//     prove it changed nothing in the workspace;
//   - a redaction hook every recorded string passes through, so a password
//     read from the credentials file can never reach the report.
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

export const REPORT_SCHEMA_VERSION = "walkthrough-report-v2";

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

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

// redactValue applies the walkthrough's redactor to every string a report may
// contain, at any depth. It is the final gate before a report is written.
function redactValue(value, redact) {
  if (typeof value === "string") return redact(value);
  if (Array.isArray(value)) return value.map((item) => redactValue(item, redact));
  if (value !== null && typeof value === "object") {
    const result = {};
    for (const [key, item] of Object.entries(value)) result[key] = redactValue(item, redact);
    return result;
  }
  return value;
}

export class Walkthrough {
  constructor(page, options = {}) {
    this.page = page;
    this.screenshotDir = options.screenshotDir ?? null;
    this.origin = typeof options.origin === "string" ? options.origin.replace(/\/+$/, "") : "";
    this.redact = typeof options.redact === "function" ? options.redact : (value) => value;
    this.steps = [];
    this.current = null;
    page.on("request", (request) => {
      const step = this.current;
      if (step === null) return;
      const method = request.method().toUpperCase();
      if (SAFE_METHODS.has(method)) return;
      step.writes.push({ method, path: requestPathOf(request.url()) });
    });
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
          // The code is parsed from the raw body; the stored copy is redacted.
          try {
            entry.code = JSON.parse(body)?.error?.code ?? null;
          } catch {
            entry.code = null;
          }
          entry.body = this.redact(body.slice(0, 300));
        })
        .catch(() => {});
    });
    page.on("console", (message) => {
      if (this.current === null || message.type() !== "error") return;
      this.current.consoleErrors.push(this.redact(message.text()));
    });
    page.on("pageerror", (error) => {
      if (this.current === null) return;
      const text = error instanceof Error ? error.message : String(error);
      this.current.pageErrors.push(this.redact(text));
      this.current.consoleErrors.push(this.redact(text));
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
      writes: [],
      answers: [],
      error: null,
      page_excerpt: null,
    };
    this.current = step;
    const started = process.hrtime.bigint();
    try {
      await action();
    } catch (error) {
      step.error = this.redact(error instanceof Error ? error.message : String(error));
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
        step.screenshotError = this.redact(error instanceof Error ? error.message : String(error));
      }
    }
    step.status = stepFailed(step) ? "failed" : "passed";
    if (step.status === "failed") {
      // A failing step records what the screen actually said, so the report
      // explains the failure without a second reproduction.
      try {
        const excerpt = await this.page.evaluate(() => (document.body ? document.body.innerText : ""));
        step.page_excerpt = this.redact(excerpt.slice(0, 2000));
      } catch {
        step.page_excerpt = null;
      }
    }
    this.steps.push(step);
    return step;
  }

  // answer records the text the product produced for one question inside the
  // active step. The caller reads it from the screen; the recorder redacts it.
  answer(question, text) {
    if (this.current === null) {
      throw new Error("an answer must be recorded inside a walkthrough step");
    }
    this.current.answers.push({
      question: this.redact(String(question ?? "")),
      text: this.redact(String(text ?? "")),
    });
  }

  // observedWrites returns every mutating request the walkthrough saw, once
  // each, in the order it saw them. Paths include the query string.
  observedWrites() {
    const seen = new Set();
    const writes = [];
    for (const step of this.steps) {
      for (const write of step.writes) {
        const key = `${write.method} ${write.path}`;
        if (seen.has(key)) continue;
        seen.add(key);
        writes.push(write);
      }
    }
    return writes;
  }
}

function bulletList(values) {
  if (values.length === 0) return "- none\n";
  return values.map((value) => `- ${value}\n`).join("");
}

function httpLine(error) {
  const code = error.code !== null && error.code !== undefined ? ` (${error.code})` : "";
  return `${error.method} ${error.path} -> ${error.status}${code}`;
}

export function buildReport({ baseURL, command, scenario, startedAt, finishedAt, steps, redact }) {
  const redactor = typeof redact === "function" ? redact : (value) => value;
  const redactedSteps = redactValue(steps, redactor);
  const failed = redactedSteps.filter((step) => step.status === "failed");
  const answers = [];
  for (const step of redactedSteps) {
    for (const answer of step.answers) {
      answers.push({ step: step.name, question: answer.question, text: answer.text });
    }
  }
  return {
    schema_version: REPORT_SCHEMA_VERSION,
    command,
    scenario: scenario ?? null,
    base_url: baseURL,
    started_at: startedAt.toISOString(),
    finished_at: finishedAt.toISOString(),
    total_seconds: Math.round(((finishedAt.getTime() - startedAt.getTime()) / 1000) * 1000) / 1000,
    passed: failed.length === 0,
    step_count: redactedSteps.length,
    failed_step_count: failed.length,
    failed_steps: failed.map((step) => step.name),
    answers,
    steps: redactedSteps,
  };
}

export function renderMarkdown(report) {
  const lines = [];
  lines.push("# Walkthrough report\n\n");
  if (report.scenario === "read-only") {
    lines.push("A robot walked the real web interface of a stand in read-only mode.\n");
    lines.push("It opened screens and asked questions; it confirmed nothing, saved nothing and added no source.\n\n");
  } else {
    lines.push("A robot walked the real web interface of the local synthetic stand.\n\n");
  }
  lines.push(`- Command: \`${report.command}\`\n`);
  lines.push(`- Scenario: ${report.scenario ?? "local"}\n`);
  lines.push(`- Stand: ${report.base_url}\n`);
  lines.push(`- Started: ${report.started_at}\n`);
  lines.push(`- Finished: ${report.finished_at}\n`);
  lines.push(`- Total: ${report.total_seconds} s\n`);
  lines.push(`- Result: **${report.passed ? "PASS" : "FAIL"}** (${report.step_count} steps, ${report.failed_step_count} failed)\n\n`);
  lines.push(`## Answers (${report.answers.length})\n\n`);
  if (report.answers.length === 0) {
    lines.push("- none\n\n");
  }
  for (const answer of report.answers) {
    lines.push(`### ${answer.question}\n\n`);
    lines.push(`${answer.text}\n\n`);
  }
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
    if (step.answers.length > 0) {
      lines.push(`Answer texts (${step.answers.length}):\n\n`);
      for (const answer of step.answers) {
        lines.push(`> ${answer.question}\n>\n> ${answer.text.replace(/\n/g, "\n> ")}\n\n`);
      }
    }
    lines.push(`Mutating requests (${step.writes.length}):\n\n`);
    lines.push(bulletList(step.writes.map((write) => `${write.method} ${write.path}`)));
    lines.push(`\nHTTP responses >= 500 (${step.httpErrors.length}):\n\n`);
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
