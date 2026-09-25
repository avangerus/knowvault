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
// Card U-3 adds the visual record: after its screenshot every step is compared
// with the approved reference picture of that step. The report states, per
// step, the share of the screen that differs, the threshold that share is
// measured against, and — when it is beyond the threshold — a picture that
// highlights the differing pixels. In `enforce` mode such a step fails and the
// run fails; in `report` mode (the read-only stand run) the difference is
// reported without failing; in `update` mode the reference is replaced and the
// report lists which references changed. An ordinary run never writes to the
// reference directory.
//
// Card U-4 adds the interface review to the same report shape: after its
// screenshot every step is judged by a vision model against the numbered rules
// of docs/UI-PRINCIPLES.md, and the report states, per screen, the remarks with
// their rule number and their place on the screen. A screen the model finds
// nothing wrong with is recorded as having no remarks, and a review that did
// not happen — no key file, an unreachable model, a refused key — is recorded
// with its reason without failing the run. The review is information, never a
// pass/fail gate.
//
// The recorder is transport-agnostic: a step fails when its own action threw,
// when any request it caused answered 5xx (with the request path), when the
// browser raised an uncaught error while it was the active step, or when its
// screen differed beyond the threshold in `enforce` mode. Console errors are
// always recorded and rendered, even when the step still passes: Chromium
// reports every failed HTTP response as a console error, and a signed-out
// session probe is a 401 the product expects, not a step failure. Nothing here
// touches product code.

import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";

import { comparePngs, DEFAULT_DIFFERENCE_THRESHOLD, DEFAULT_PIXEL_TOLERANCE } from "./visual.mjs";
import { pngDimensions } from "./png.mjs";
import { summariseReview } from "./review.mjs";

export const REPORT_SCHEMA_VERSION = "walkthrough-report-v4";

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
// seen during the step, any uncaught browser error seen during it, or a screen
// that differs from its approved reference in `enforce` mode.
export function stepFailed(step) {
  return (
    Boolean(step.error) ||
    step.visual_failed === true ||
    step.httpErrors.length > 0 ||
    step.pageErrors.length > 0
  );
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
    // Card U-3 visual comparison. `off` is the default so a caller that only
    // wants the old report shape is unaffected. `referenceDir` is where the
    // approved pictures live; it is read in `enforce` and `report` mode and is
    // the only place written in `update` mode.
    this.visualMode = options.visualMode ?? "off";
    this.referenceDir = options.referenceDir ?? null;
    this.referenceLabel = options.referenceLabel ?? options.referenceDir ?? null;
    this.differenceDir = options.differenceDir ?? null;
    this.differenceThreshold = options.differenceThreshold ?? DEFAULT_DIFFERENCE_THRESHOLD;
    this.pixelTolerance = options.pixelTolerance ?? DEFAULT_PIXEL_TOLERANCE;
    // An optional hook awaited just before every screenshot. The walkthrough
    // uses it to let a transient result toast go away, so a picture never
    // depends on how fast the previous action's notification faded.
    this.beforeScreenshot = typeof options.beforeScreenshot === "function" ? options.beforeScreenshot : null;
    // Card U-4: the optional interface reviewer. When it is null every step
    // records that the review did not happen and why, and the run is unaffected.
    this.reviewer = options.reviewer ?? null;
    this.reviewDisabledReason = options.reviewDisabledReason ?? null;
    // In-flight HTTP requests. The screen is only photographed once the page
    // has stopped fetching, so a picture cannot catch the application halfway
    // through loading its workspace.
    this.inFlightRequests = 0;
    this.steps = [];
    this.current = null;
    page.on("request", () => {
      this.inFlightRequests += 1;
    });
    page.on("requestfinished", () => {
      this.inFlightRequests = Math.max(0, this.inFlightRequests - 1);
    });
    page.on("requestfailed", () => {
      this.inFlightRequests = Math.max(0, this.inFlightRequests - 1);
    });
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
      visual: null,
      visual_failed: false,
      reference_update: null,
      review: null,
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
      let picture = null;
      try {
        await this.waitForQuiet();
        if (this.beforeScreenshot !== null) await this.beforeScreenshot(this.page, step);
        // `caret: "hide"` keeps the blinking text cursor out of the picture, so
        // a focused field cannot fail a step on its own.
        picture = await this.page.screenshot({
          path: path.join(this.screenshotDir, file),
          fullPage: true,
          caret: "hide",
        });
        step.screenshot = path.posix.join("screenshots", file);
        await this.compareWithReference(step, file, picture);
      } catch (error) {
        step.screenshotError = this.redact(error instanceof Error ? error.message : String(error));
      }
      // Card U-4: the screenshot is the review's input. It runs after the
      // screen comparison so a review problem can never be mistaken for a
      // comparison problem, and it never changes the step's status.
      await this.reviewScreenshot(step, picture);
    } else {
      step.review = {
        status: "not_run",
        reason: this.reviewDisabledReason ?? "the walkthrough records no screenshots",
        remarks: [],
        remark_count: 0,
        cost_usd: null,
        usage: null,
      };
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

  // compareWithReference is the card U-3 rule for one step. It reads the
  // approved picture of the step, measures the difference and stores the
  // result on the step. `enforce` fails a differing step, `report` only
  // records it, and `update` replaces the approved picture and records what
  // changed. Only `update` ever writes inside the reference directory.
  async compareWithReference(step, file, picture) {
    if (this.visualMode === "off" || this.referenceDir === null) return;
    const referencePath = path.join(this.referenceDir, file);
    let reference = null;
    let readError = null;
    try {
      reference = await readFile(referencePath);
    } catch (error) {
      readError = error;
    }
    if (readError !== null && readError.code !== "ENOENT") {
      step.visual = {
        status: "unreadable",
        reference: path.posix.join(this.referenceLabel ?? "", file),
        error: this.redact(`cannot read ${referencePath}: ${readError.message}`),
        threshold: this.differenceThreshold,
        pixel_tolerance: this.pixelTolerance,
      };
      if (this.visualMode === "enforce") {
        step.visual_failed = true;
        step.visual_failure = `the approved reference picture is unreadable: ${readError.message}`;
      }
      return;
    }

    if (this.visualMode === "update") {
      let change = "added";
      let measured = null;
      if (reference !== null) {
        change = reference.equals(picture) ? "unchanged" : "replaced";
        if (change === "replaced") {
          try {
            measured = comparePngs(reference, picture, {
              threshold: this.differenceThreshold,
              pixelTolerance: this.pixelTolerance,
            });
          } catch {
            // A picture whose size changed is still replaced; only the
            // "difference before replacement" note is unavailable.
            measured = null;
          }
        }
      }
      if (change !== "unchanged") {
        await mkdir(this.referenceDir, { recursive: true });
        await writeFile(referencePath, picture);
      }
      step.reference_update = {
        reference: path.posix.join(this.referenceLabel ?? "", file),
        change,
        difference_ratio: measured === null ? null : measured.difference_ratio,
        different_pixels: measured === null ? null : measured.different_pixels,
        diff_image: measured === null ? null : await this.writeDifference(file, measured),
      };
      return;
    }

    if (reference === null) {
      step.visual = {
        status: "missing",
        reference: path.posix.join(this.referenceLabel ?? "", file),
        threshold: this.differenceThreshold,
        pixel_tolerance: this.pixelTolerance,
      };
      if (this.visualMode === "enforce") {
        step.visual_failed = true;
        step.visual_failure = "no approved reference picture for this step";
      }
      return;
    }

    let measured;
    try {
      measured = comparePngs(reference, picture, {
        threshold: this.differenceThreshold,
        pixelTolerance: this.pixelTolerance,
      });
    } catch (error) {
      step.visual = {
        status: "unreadable",
        reference: path.posix.join(this.referenceLabel ?? "", file),
        error: this.redact(error instanceof Error ? error.message : String(error)),
        threshold: this.differenceThreshold,
        pixel_tolerance: this.pixelTolerance,
      };
      if (this.visualMode === "enforce") {
        step.visual_failed = true;
        step.visual_failure = `the screen comparison could not run: ${error.message}`;
      }
      return;
    }
    step.visual = {
      status: measured.beyond_threshold ? "differs" : "same",
      reference: path.posix.join(this.referenceLabel ?? "", file),
      difference_ratio: measured.difference_ratio,
      different_pixels: measured.different_pixels,
      total_pixels: measured.total_pixels,
      size_mismatch: measured.size_mismatch,
      difference_box: measured.difference_box,
      threshold: measured.threshold,
      pixel_tolerance: measured.pixel_tolerance,
      diff_image: measured.beyond_threshold ? await this.writeDifference(file, measured) : null,
    };
    if (measured.beyond_threshold && this.visualMode === "enforce") {
      step.visual_failed = true;
      step.visual_failure = `the screen differs from its approved reference by ${formatPercent(measured.difference_ratio)}, above the ${formatPercent(measured.threshold)} threshold`;
    }
  }

  // writeDifference stores the highlight picture next to the report and returns
  // its report-relative path, or null when the caller configured no directory.
  async writeDifference(file, measured) {
    if (this.differenceDir === null || measured.diff === null) return null;
    await mkdir(this.differenceDir, { recursive: true });
    await writeFile(path.join(this.differenceDir, file), measured.diff);
    return path.posix.join("differences", file);
  }

  // reviewScreenshot is the card U-4 rule for one step: send this step's own
  // screenshot bytes to the vision model and store what it saw. No configuration
  // and no model failure changes the step's status; the record explains itself.
  async reviewScreenshot(step, picture) {
    if (this.reviewer === null) {
      step.review = {
        status: "not_run",
        reason: this.reviewDisabledReason ?? "the interface review is not configured",
        remarks: [],
        remark_count: 0,
        cost_usd: null,
        usage: null,
      };
      return;
    }
    if (picture === null || picture === undefined) {
      step.review = {
        status: "skipped",
        reason: this.redact(step.screenshotError ?? "no screenshot for this step"),
        remarks: [],
        remark_count: 0,
        cost_usd: null,
        usage: null,
      };
      return;
    }
    try {
      const { width, height } = pngDimensions(picture);
      const result = await this.reviewer.review({ step: step.name, screenshot: picture, width, height });
      const remarks = Array.isArray(result.remarks) ? result.remarks : [];
      step.review = {
        status: result.status,
        reason: result.reason === null || result.reason === undefined ? null : this.redact(String(result.reason)),
        remarks: remarks.map((remark) => ({
          rule: remark.rule,
          rule_title: this.redact(String(remark.rule_title ?? "")),
          where: this.redact(String(remark.where ?? "")),
          note: this.redact(String(remark.note ?? "")),
        })),
        remark_count: remarks.length,
        cost_usd: typeof result.cost_usd === "number" ? result.cost_usd : null,
        usage: result.usage ?? null,
      };
    } catch (error) {
      step.review = {
        status: "failed",
        reason: this.redact(error instanceof Error ? error.message : String(error)),
        remarks: [],
        remark_count: 0,
        cost_usd: null,
        usage: null,
      };
    }
  }

  // waitForQuiet blocks until no request has been in flight for a short window,
  // so the screenshot is of a screen that finished loading. A request that
  // never finishes cannot hang the walkthrough: the wait is bounded.
  async waitForQuiet({ quietMs = 250, timeoutMs = 8_000 } = {}) {
    const deadline = Date.now() + timeoutMs;
    let quietSince = null;
    for (;;) {
      if (this.inFlightRequests === 0) {
        quietSince = quietSince ?? Date.now();
        if (Date.now() - quietSince >= quietMs) return;
      } else {
        quietSince = null;
      }
      if (Date.now() > deadline) return;
      await new Promise((resolve) => setTimeout(resolve, 50));
    }
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

// formatPercent renders a share of the screen for a person, with the precision
// the threshold needs: the noise floor of an unchanged screen lives in the
// third decimal of a percent.
export function formatPercent(ratio) {
  if (typeof ratio !== "number" || !Number.isFinite(ratio)) return "n/a";
  return `${(ratio * 100).toFixed(3)}%`;
}

// summariseVisual rolls the per-step visual records up into the report header:
// how many steps were compared, how many differed, which references an update
// command replaced.
function summariseVisual(steps, options = {}) {
  const mode = options.mode ?? "off";
  const compared = steps.filter(
    (step) => step.visual !== null && step.visual !== undefined && (step.visual.status === "same" || step.visual.status === "differs"),
  );
  const differing = compared.filter((step) => step.visual.status === "differs");
  const missing = steps.filter((step) => step.visual?.status === "missing");
  const unreadable = steps.filter((step) => step.visual?.status === "unreadable");
  const failedVisual = steps.filter((step) => step.visual_failed === true);
  const updates = [];
  for (const step of steps) {
    if (step.reference_update !== null && step.reference_update !== undefined) {
      updates.push({ step: step.name, ...step.reference_update });
    }
  }
  const ratios = [
    ...compared.map((step) => step.visual.difference_ratio),
    ...updates.map((update) => update.difference_ratio),
  ].filter((ratio) => typeof ratio === "number" && Number.isFinite(ratio));
  // An update run has no per-step comparison record; every reference it looked
  // at is a comparison, and a "replaced" one is the one that differed.
  const comparedCount = mode === "update" ? updates.length : compared.length;
  const differingCount =
    mode === "update" ? updates.filter((update) => update.change === "replaced").length : differing.length;
  return {
    mode,
    difference_threshold: options.threshold ?? DEFAULT_DIFFERENCE_THRESHOLD,
    pixel_tolerance: options.pixelTolerance ?? DEFAULT_PIXEL_TOLERANCE,
    reference_dir: options.referenceLabel ?? null,
    compared_step_count: comparedCount,
    differing_step_count: differingCount,
    failed_step_count: failedVisual.length,
    missing_reference_count: missing.length,
    unreadable_reference_count: unreadable.length,
    max_difference_ratio: ratios.length === 0 ? null : Math.max(...ratios),
    references_updated: updates,
    references_changed_count: updates.filter((update) => update.change !== "unchanged").length,
    references_unchanged_count: updates.filter((update) => update.change === "unchanged").length,
  };
}

export function buildReport({ baseURL, command, scenario, startedAt, finishedAt, steps, redact, visual, review }) {
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
    visual: summariseVisual(redactedSteps, visual),
    review: summariseReview(redactedSteps, review),
    answers,
    steps: redactedSteps,
  };
}

// formatUsd renders a dollar amount for a person, or "unknown" when the review
// did not report enough to compute one.
function formatUsd(value) {
  if (typeof value !== "number" || !Number.isFinite(value)) return "unknown";
  return `$${value.toFixed(4)}`;
}

function oneLine(value) {
  return String(value ?? "").replace(/\s+/g, " ").trim();
}

function remarkLines(remarks) {
  const lines = [];
  for (const remark of remarks) {
    const title = oneLine(remark.rule_title) === "" ? "" : ` (${oneLine(remark.rule_title)})`;
    const where = oneLine(remark.where) === "" ? "place not stated" : oneLine(remark.where);
    lines.push(`- **Rule ${remark.rule}**${title} — ${where}: ${oneLine(remark.note)}\n`);
  }
  return lines;
}

// renderReviewSection writes the card U-4 report section: what the vision model
// saw on every screen, and, when the review did not happen, why.
function renderReviewSection(review, steps) {
  const lines = ["## Interface review (vision model)\n\n"];
  if (review === null) {
    lines.push("Review did not happen: the report holds no review record.\n\n");
    return lines;
  }
  if (review.status === "not_reviewed") {
    lines.push(`Review did not happen: ${oneLine(review.reason) || "no reason recorded"}.\n\n`);
    return lines;
  }
  if (review.model !== null) {
    const endpoint = review.endpoint === null ? "" : ` at \`${review.endpoint}\``;
    lines.push(`- Model: \`${review.model}\`${endpoint}\n`);
  }
  lines.push(`- Rules: \`${review.rules_source}\`${review.rule_count === null ? "" : ` (${review.rule_count} rules)`}\n`);
  lines.push(`- Screens reviewed: ${review.reviewed_step_count} (${review.not_reviewed_step_count} not reviewed)\n`);
  lines.push(`- Screens with no remarks: ${review.no_remark_step_count}\n`);
  lines.push(`- Remarks: ${review.remark_count}\n`);
  lines.push(`- Review cost: ${formatUsd(review.cost_usd)} (ceiling ${formatUsd(review.cost_limit_usd)}${review.price_window === null ? "" : `, ${review.price_window} prices`})\n`);
  if (review.status === "partial") {
    lines.push(`- Some screens were not reviewed: ${oneLine(review.reason)}\n`);
  }
  lines.push("\n");
  steps.forEach((step, index) => {
    lines.push(`### ${index + 1}. ${step.name}\n\n`);
    const stepReview = step.review ?? null;
    if (stepReview === null || stepReview.status !== "reviewed") {
      lines.push(`Review did not happen: ${oneLine(stepReview?.reason) || "no reason recorded"}.\n\n`);
      return;
    }
    if (stepReview.remark_count === 0) {
      lines.push("No remarks.\n\n");
      return;
    }
    lines.push(`Remarks (${stepReview.remark_count}):\n\n`);
    lines.push(...remarkLines(stepReview.remarks));
    lines.push("\n");
  });
  return lines;
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
  const visual = report.visual ?? { mode: "off" };
  if (visual.mode !== "off") {
    lines.push(`## Screen comparison (${visual.mode})\n\n`);
    lines.push(`- Approved references: \`${visual.reference_dir ?? "none"}\`\n`);
    lines.push(`- Steps compared: ${visual.compared_step_count}\n`);
    lines.push(`- Steps with a differing screen: ${visual.differing_step_count}\n`);
    lines.push(`- Steps failed on the comparison: ${visual.failed_step_count}\n`);
    lines.push(`- Steps without an approved reference: ${visual.missing_reference_count}\n`);
    lines.push(`- Largest difference: ${formatPercent(visual.max_difference_ratio)} (threshold ${formatPercent(visual.difference_threshold)}, per-pixel tolerance ${visual.pixel_tolerance})\n\n`);
    if (visual.references_updated.length > 0) {
      const changed = visual.references_updated.filter((update) => update.change !== "unchanged");
      lines.push(`### Approved references replaced (${changed.length})\n\n`);
      for (const update of visual.references_updated) {
        const measured =
          typeof update.difference_ratio === "number" ? `, difference before replacement ${formatPercent(update.difference_ratio)}` : "";
        lines.push(`- ${update.change}: \`${update.reference}\`${measured}\n`);
      }
      lines.push("\n");
      lines.push(`Unchanged references: ${visual.references_unchanged_count}\n\n`);
    }
  }
  lines.push(...renderReviewSection(report.review ?? null, report.steps));
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
    if (step.visual !== null && step.visual !== undefined) {
      const ratio = step.visual.status === "same" || step.visual.status === "differs" ? formatPercent(step.visual.difference_ratio) : step.visual.status;
      lines.push(`Screen comparison: **${step.visual.status}** — ${ratio} of the screen differs (threshold ${formatPercent(step.visual.threshold)})\n\n`);
      if (step.visual.reference) {
        lines.push(`Approved reference: \`${step.visual.reference}\`\n\n`);
      }
      if (step.visual.error) {
        lines.push(`Comparison error: ${step.visual.error}\n\n`);
      }
      if (step.visual.diff_image) {
        lines.push(`![difference of ${step.name}](${step.visual.diff_image})\n\n`);
      }
    }
    if (step.reference_update !== null && step.reference_update !== undefined) {
      const update = step.reference_update;
      const measured = typeof update.difference_ratio === "number" ? ` (was ${formatPercent(update.difference_ratio)} different)` : "";
      lines.push(`Reference ${update.change}: \`${update.reference}\`${measured}\n\n`);
    }
    if (step.review !== null && step.review !== undefined) {
      if (step.review.status === "reviewed") {
        const summary = step.review.remark_count === 0 ? "no remarks" : `${step.review.remark_count} remarks`;
        lines.push(`Interface review: ${summary} (${formatUsd(step.review.cost_usd)})\n`);
        lines.push(...remarkLines(step.review.remarks));
        lines.push("\n");
      } else {
        lines.push(`Interface review: did not happen — ${oneLine(step.review.reason) || "no reason recorded"}\n\n`);
      }
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
