// Card U-4: judge every walkthrough screenshot with a vision model against the
// numbered interface rules of docs/UI-PRINCIPLES.md.
//
// The walkthrough already proves that each step works and that a screen did not
// change unexpectedly. This module adds the missing judgement: after a step's
// screenshot is taken it is sent, with the rules as a checklist, to a vision
// model, and every remark the model returns is recorded with the rule number
// and the place on the screen. Remarks inform; they never fail a step.
//
// Three properties shape the code:
//   - the review is optional infrastructure. Without a key file, with an
//     unreachable model or with a model that refuses the key, the run still
//     passes and the report says the review did not happen and why;
//   - the key is read from a file at run time, kept in memory and never put
//     into the prompt, the report, a log line or the repository;
//   - one local run has a stated cost ceiling. The model reports its token
//     usage, the cost is computed from the published DeepSeek Flash prices, and
//     a call is only made while the accumulated cost plus a conservative
//     reservation stays below the ceiling.
//
// Nothing here touches product code, and the product never imports this file.

import { readFile } from "node:fs/promises";
import path from "node:path";

// INTERFACE_RULES_REPOSITORY_PATH is the checklist the review judges against.
// It is read from the repository at run time so the rules cannot drift from the
// document a person edits.
export const INTERFACE_RULES_REPOSITORY_PATH = "docs/UI-PRINCIPLES.md";

// REVIEW_COST_LIMIT_USD is the most one local run's review may cost. The card
// states the ceiling; the reviewer stops calling the model when the next call
// could cross it.
export const REVIEW_COST_LIMIT_USD = 0.05;

export const DEFAULT_REVIEW_ENDPOINT = "https://api.deepseek.com";
export const DEFAULT_REVIEW_MODEL = "deepseek-flash";
export const DEFAULT_REVIEW_MAX_TOKENS = 1600;
export const DEFAULT_REVIEW_TIMEOUT_MS = 120_000;

// REVIEW_MAX_INPUT_TOKENS is a conservative ceiling on what one review sends:
// the provider bounds an image at 1024 tokens and the checklist and the
// instructions add a few hundred. It is used only to reserve budget before a
// call, never to compute the reported cost.
export const REVIEW_MAX_INPUT_TOKENS = 4_000;

// REVIEW_PRICING is the published DeepSeek price list, per one million tokens.
// Peak hours are 01:00-04:00 and 06:00-10:00 UTC, Monday to Friday; every other
// hour is off-peak. The report marks which list was used.
export const REVIEW_PRICING = Object.freeze({
  "deepseek-flash": Object.freeze({
    input_cache_hit: Object.freeze({ peak: 0.006, off_peak: 0.003 }),
    input_cache_miss: Object.freeze({ peak: 0.3, off_peak: 0.15 }),
    output: Object.freeze({ peak: 1.2, off_peak: 0.6 }),
  }),
});

// parseInterfaceRules reads the numbered rules out of the principles document:
// a line of the form `12. **Title.** Rest of the rule`, followed by any indented
// continuation lines that wrap the rule. The prose sections that carry no number
// are ignored.
export function parseInterfaceRules(markdown) {
  const rules = [];
  let current = null;
  for (const rawLine of String(markdown ?? "").split(/\r?\n/)) {
    const match = rawLine.match(/^(\d+)\.\s+\*\*(.+?)\*\*\s*(.*)$/);
    if (match !== null) {
      current = { number: Number(match[1]), title: match[2].trim(), text: match[3].trim() };
      rules.push(current);
      continue;
    }
    if (current === null) continue;
    if (/^\s+\S/.test(rawLine)) {
      current.text = `${current.text} ${rawLine.trim()}`.trim();
      continue;
    }
    // A blank line, a heading or a new list ends the wrapped rule.
    current = null;
  }
  return rules.map((rule) => ({
    number: rule.number,
    title: rule.title,
    text: rule.text.replace(/\s+/g, " ").trim(),
  }));
}

// loadInterfaceRules reads the checklist from the repository. A missing or
// unreadable document is a configuration failure the caller reports as "the
// review did not happen", never a thrown run.
export async function loadInterfaceRules(root) {
  const file = path.join(root, INTERFACE_RULES_REPOSITORY_PATH);
  const markdown = await readFile(file, "utf8");
  const rules = parseInterfaceRules(markdown);
  if (rules.length === 0) {
    throw new Error(`${INTERFACE_RULES_REPOSITORY_PATH} holds no numbered rules`);
  }
  return rules;
}

// isPeakHour applies the provider's published peak window to a moment.
export function isPeakHour(at) {
  const day = at.getUTCDay();
  if (day === 0 || day === 6) return false;
  const hour = at.getUTCHours() + at.getUTCMinutes() / 60;
  return (hour >= 1 && hour < 4) || (hour >= 6 && hour < 10);
}

// priceList returns the three per-million prices for a model at a moment, or
// null when the model has no published price in this file.
export function priceList(model, at) {
  const prices = REVIEW_PRICING[model];
  if (prices === undefined) return null;
  const window = isPeakHour(at) ? "peak" : "off_peak";
  return {
    window,
    input_cache_hit: prices.input_cache_hit[window],
    input_cache_miss: prices.input_cache_miss[window],
    output: prices.output[window],
  };
}

// costOfUsage turns the provider's reported token usage into dollars. It uses
// the cache-hit and cache-miss input counts separately when the provider
// reports them, and falls back to the plain prompt count otherwise. A model
// without a published price, or a response without usage, costs null: the
// report then says the cost is unknown instead of inventing a number.
export function costOfUsage(usage, options = {}) {
  if (usage === null || usage === undefined || typeof usage !== "object") return null;
  const model = options.model ?? DEFAULT_REVIEW_MODEL;
  const at = options.at ?? new Date();
  const prices = priceList(model, at);
  if (prices === null) return null;
  const hasSplit = typeof usage.prompt_cache_hit_tokens === "number" || typeof usage.prompt_cache_miss_tokens === "number";
  const hit = typeof usage.prompt_cache_hit_tokens === "number" ? usage.prompt_cache_hit_tokens : 0;
  const miss = hasSplit
    ? typeof usage.prompt_cache_miss_tokens === "number"
      ? usage.prompt_cache_miss_tokens
      : 0
    : typeof usage.prompt_tokens === "number"
      ? usage.prompt_tokens
      : 0;
  const output = typeof usage.completion_tokens === "number" ? usage.completion_tokens : 0;
  const dollars =
    (hit * prices.input_cache_hit + miss * prices.input_cache_miss + output * prices.output) / 1_000_000;
  return Number.isFinite(dollars) ? dollars : null;
}

// buildReviewPrompt is the whole instruction the model receives besides the
// picture. The screenshot's own pixel size is stated so the size rules (11, 12,
// 15) can be judged on the image instead of guessed.
export function buildReviewPrompt({ rules, step, width, height }) {
  const checklist = rules.map((rule) => `${rule.number}. ${rule.title} ${rule.text}`.trim()).join("\n");
  return [
    "Ты — ревьюер интерфейса продукта KnowVault. Тебе дают скриншот ОДНОГО экрана и чек-лист правил интерфейса.",
    `Экран: ${step}.`,
    `Размер скриншота: ${width}×${height} CSS px, масштаб 1:1.`,
    "Проверь только то, что реально видно на этом скриншоте; не выдумывай нарушений, которых не видно.",
    "По известному размеру изображения оцени в пикселях высоту кнопок и полей и размер основного текста — это нужно для правил 11, 12 и 15.",
    "Для каждого нарушения верни номер правила, место на экране (например «шапка страницы, справа», «над полем вопроса», «нижний правый угол панели») и краткое описание по-русски.",
    "Если нарушений не видно, верни пустой список.",
    'Ответь строго JSON вида {"remarks":[{"rule":<номер>,"rule_title":"<название правила>","where":"<место на экране>","note":"<что не так>"}]}.',
    "",
    "Правила:",
    checklist,
  ].join("\n");
}

function stripCodeFence(text) {
  const trimmed = String(text ?? "").trim();
  const match = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/);
  return match === null ? trimmed : match[1].trim();
}

// parseRemarks reads the model's JSON answer. A remark without a usable rule
// number or without any text is dropped rather than reported as a broken one;
// an answer that is not JSON at all is an error the caller records as a failed
// review.
export function parseRemarks(content) {
  let parsed;
  try {
    parsed = JSON.parse(stripCodeFence(content));
  } catch {
    throw new Error("the review model did not answer with JSON");
  }
  const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.remarks) ? parsed.remarks : null;
  if (list === null) {
    throw new Error("the review model answered without a remarks list");
  }
  const remarks = [];
  for (const item of list) {
    if (item === null || typeof item !== "object") continue;
    const rule = Number(item.rule);
    if (!Number.isInteger(rule) || rule < 1) continue;
    const where = typeof item.where === "string" ? item.where.trim() : "";
    const note = typeof item.note === "string" ? item.note.trim() : "";
    if (where === "" && note === "") continue;
    const ruleTitle = typeof item.rule_title === "string" ? item.rule_title.trim() : "";
    remarks.push({ rule, rule_title: ruleTitle, where, note });
  }
  return remarks;
}

// ReviewHttpError carries only the status and the provider's machine-readable
// error type. The response body and the request headers (and therefore the key)
// never travel with the error.
export class ReviewHttpError extends Error {
  constructor(status, type) {
    const suffix = type === "" ? "" : ` (${type})`;
    super(`the review model answered HTTP ${status}${suffix}`);
    this.name = "ReviewHttpError";
    this.status = status;
    this.type = type;
  }

  get retryable() {
    return this.status === 429 || this.status >= 500;
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// isRetryable decides whether another attempt could succeed: a rate limit, a
// server error, or a transport failure. An authentication failure is not
// retried.
function isRetryable(error) {
  if (error instanceof ReviewHttpError) return error.retryable;
  return String(error?.message ?? "").startsWith("the review model could not be reached:");
}

function providerErrorType(body) {
  try {
    const parsed = JSON.parse(body);
    const type = parsed?.error?.type ?? parsed?.error?.code ?? "";
    return typeof type === "string" ? type : "";
  } catch {
    return "";
  }
}

// createInterfaceReviewer builds the reviewer used by one walkthrough run. The
// caller supplies the key; the reviewer never logs it and never puts it into a
// result.
export function createInterfaceReviewer(options = {}) {
  const rules = Array.isArray(options.rules) ? options.rules : [];
  const model = options.model ?? DEFAULT_REVIEW_MODEL;
  const endpoint = String(options.endpoint ?? DEFAULT_REVIEW_ENDPOINT).replace(/\/+$/, "");
  const apiKey = String(options.apiKey ?? "");
  const fetchImpl = options.fetchImpl ?? fetch;
  const timeoutMs = options.timeoutMs ?? DEFAULT_REVIEW_TIMEOUT_MS;
  const maxTokens = options.maxTokens ?? DEFAULT_REVIEW_MAX_TOKENS;
  const costLimitUsd = options.costLimitUsd ?? REVIEW_COST_LIMIT_USD;
  const maxRetries = options.maxRetries ?? 1;
  const now = typeof options.now === "function" ? options.now : () => new Date();
  let spentUsd = 0;
  let reviewedCount = 0;
  let failedCount = 0;
  let skippedCount = 0;
  let remarkCount = 0;
  let noRemarkCount = 0;

  // Reserve the worst case of one call at peak prices. A run therefore cannot
  // cross the ceiling even if every token a call can spend is spent.
  const reservation = costOfUsage(
    { prompt_cache_miss_tokens: REVIEW_MAX_INPUT_TOKENS, completion_tokens: maxTokens },
    { model, at: new Date(Date.UTC(2026, 0, 5, 2, 0, 0)) },
  );

  async function requestOnce(prompt, screenshot) {
    const body = {
      model,
      messages: [
        {
          role: "user",
          content: [
            { type: "text", text: prompt },
            {
              type: "image_url",
              image_url: { url: `data:image/png;base64,${screenshot.toString("base64")}`, detail: "original" },
            },
          ],
        },
      ],
      max_tokens: maxTokens,
      thinking: { type: "disabled" },
      response_format: { type: "json_object" },
    };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    try {
      response = await fetchImpl(`${endpoint}/chat/completions`, {
        method: "POST",
        headers: { Authorization: `Bearer ${apiKey}`, "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal: controller.signal,
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`the review model could not be reached: ${message}`);
    } finally {
      clearTimeout(timer);
    }
    if (!response.ok) {
      let bodyText = "";
      try {
        bodyText = await response.text();
      } catch {
        bodyText = "";
      }
      throw new ReviewHttpError(response.status, providerErrorType(bodyText));
    }
    let payload;
    try {
      payload = await response.json();
    } catch {
      throw new Error("the review model answered with a body that is not JSON");
    }
    const content = payload?.choices?.[0]?.message?.content;
    if (typeof content !== "string" || content.trim() === "") {
      throw new Error("the review model answered without remarks text");
    }
    return { content, usage: payload?.usage ?? null };
  }

  return {
    enabled: true,
    descriptor: {
      model,
      endpoint,
      rules_source: INTERFACE_RULES_REPOSITORY_PATH,
      rule_count: rules.length,
      cost_limit_usd: costLimitUsd,
      max_tokens: maxTokens,
    },
    get spent_usd() {
      return Number(spentUsd.toFixed(6));
    },
    get counts() {
      return {
        reviewed: reviewedCount,
        failed: failedCount,
        skipped: skippedCount,
        remarks: remarkCount,
        without_remarks: noRemarkCount,
      };
    },
    // review sends one step's own screenshot bytes to the model and returns the
    // recorded result. It never throws: a failure is a record, so the run keeps
    // its result and the report can explain what happened.
    async review({ step, screenshot, width, height }) {
      if (screenshot === null || screenshot === undefined) {
        skippedCount += 1;
        return { status: "skipped", reason: "no screenshot for this step", remarks: [], remark_count: 0, cost_usd: null, usage: null };
      }
      if (reservation !== null && spentUsd + reservation > costLimitUsd) {
        skippedCount += 1;
        return {
          status: "skipped",
          reason: `the review cost ceiling of $${costLimitUsd.toFixed(2)} would be crossed`,
          remarks: [],
          remark_count: 0,
          cost_usd: null,
          usage: null,
        };
      }
      const prompt = buildReviewPrompt({ rules, step, width, height });
      const at = now();
      let attempt = 0;
      for (;;) {
        try {
          const { content, usage } = await requestOnce(prompt, screenshot);
          const remarks = parseRemarks(content);
          const cost = costOfUsage(usage, { model, at });
          if (cost !== null) spentUsd += cost;
          reviewedCount += 1;
          remarkCount += remarks.length;
          if (remarks.length === 0) noRemarkCount += 1;
          return {
            status: "reviewed",
            reason: null,
            remarks,
            remark_count: remarks.length,
            cost_usd: cost,
            usage: usage ?? null,
          };
        } catch (error) {
          if (isRetryable(error) && attempt < maxRetries) {
            attempt += 1;
            await sleep(500 * attempt);
            continue;
          }
          failedCount += 1;
          return {
            status: "failed",
            reason: error instanceof Error ? error.message : String(error),
            remarks: [],
            remark_count: 0,
            cost_usd: null,
            usage: null,
          };
        }
      }
    },
  };
}

// loadReviewKey reads the key file at run time. The error text names the file
// only; its content is never read into the message, and an unreadable or empty
// file is reported as a reason the review did not happen.
export async function loadReviewKey(filePath, options = {}) {
  const readFileImpl = options.readFile ?? readFile;
  if (typeof filePath !== "string" || filePath.trim() === "") {
    throw new Error("no key file is configured");
  }
  let body;
  try {
    body = await readFileImpl(filePath, "utf8");
  } catch (error) {
    const reason = error !== null && typeof error === "object" && "code" in error ? error.code : error.message;
    throw new Error(`the key file ${filePath} could not be read: ${reason}`);
  }
  const key = body.replace(/^\uFEFF/, "").trim();
  if (key === "") {
    throw new Error(`the key file ${filePath} is empty`);
  }
  return key;
}

// createReviewFromEnvironment turns the environment into a reviewer plus the
// reason it is absent. It never throws: a missing key, an unreadable key file
// or a missing rules document all become a stated reason, so an ordinary run
// still passes and the report says the review did not happen.
export async function createReviewFromEnvironment(env = {}, options = {}) {
  const root = options.root ?? process.cwd();
  const readFileImpl = options.readFile;
  const fetchImpl = options.fetchImpl;
  const disabled = (reason) => ({ reviewer: null, reason, key: null });

  if (String(env.KNOWVAULT_WALKTHROUGH_REVIEW ?? "").trim() === "0") {
    return disabled("the interface review is switched off (KNOWVAULT_WALKTHROUGH_REVIEW=0)");
  }
  const keyFile = String(env.KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE ?? "").trim();
  if (keyFile === "") {
    return disabled("no key file is given (KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE)");
  }
  let key;
  try {
    key = await loadReviewKey(keyFile, readFileImpl === undefined ? {} : { readFile: readFileImpl });
  } catch (error) {
    return disabled(error instanceof Error ? error.message : String(error));
  }
  let rules;
  try {
    rules = await loadInterfaceRules(root);
  } catch (error) {
    return disabled(`the interface rules could not be read: ${error instanceof Error ? error.message : String(error)}`);
  }
  const model = String(env.KNOWVAULT_WALKTHROUGH_REVIEW_MODEL ?? "").trim() || DEFAULT_REVIEW_MODEL;
  const endpoint = String(env.KNOWVAULT_WALKTHROUGH_REVIEW_BASE_URL ?? "").trim() || DEFAULT_REVIEW_ENDPOINT;
  const costValue = String(env.KNOWVAULT_WALKTHROUGH_REVIEW_MAX_COST_USD ?? "").trim();
  const costLimitUsd = costValue === "" ? REVIEW_COST_LIMIT_USD : Number(costValue);
  if (!Number.isFinite(costLimitUsd) || costLimitUsd <= 0) {
    return disabled(`KNOWVAULT_WALKTHROUGH_REVIEW_MAX_COST_USD=${costValue}, want a number > 0`);
  }
  const reviewer = createInterfaceReviewer({
    rules,
    model,
    endpoint,
    apiKey: key,
    costLimitUsd,
    ...(fetchImpl === undefined ? {} : { fetchImpl }),
  });
  return { reviewer, reason: null, key };
}

// summariseReview folds the per-step review records into the report header.
export function summariseReview(steps, options = {}) {
  const reviewer = options.reviewer ?? null;
  const disabledReason = options.disabledReason ?? null;
  const reviewable = steps.filter((step) => step.screenshot !== null && step.screenshot !== undefined);
  const records = steps.map((step) => step.review).filter((record) => record !== null && record !== undefined);
  const reviewed = records.filter((record) => record.status === "reviewed");
  const failed = records.filter((record) => record.status === "failed");
  const skipped = records.filter((record) => record.status === "skipped");
  const noRemarks = reviewed.filter((record) => record.remark_count === 0);
  const costs = reviewed.map((record) => record.cost_usd).filter((cost) => typeof cost === "number" && Number.isFinite(cost));
  const descriptor = reviewer === null ? null : reviewer.descriptor;
  const at = options.at ?? new Date();
  const prices = descriptor === null ? null : priceList(descriptor.model, at);

  let status;
  let reason = null;
  if (reviewer === null) {
    status = "not_reviewed";
    reason = disabledReason ?? "the interface review is not configured";
  } else if (reviewed.length === 0) {
    status = "not_reviewed";
    reason = (failed[0] ?? skipped[0])?.reason ?? "the interface review did not run";
  } else if (reviewed.length < reviewable.length || failed.length > 0 || skipped.length > 0) {
    status = "partial";
    reason = `${failed.length + skipped.length} of ${reviewable.length} screens were not reviewed: ${(failed[0] ?? skipped[0])?.reason ?? "unknown reason"}`;
  } else {
    status = "reviewed";
  }

  return {
    status,
    reason,
    model: descriptor?.model ?? null,
    endpoint: descriptor?.endpoint ?? null,
    rules_source: descriptor?.rules_source ?? INTERFACE_RULES_REPOSITORY_PATH,
    rule_count: descriptor?.rule_count ?? null,
    price_window: prices?.window ?? null,
    cost_usd: costs.length === 0 ? null : Number(costs.reduce((sum, cost) => sum + cost, 0).toFixed(6)),
    cost_limit_usd: descriptor?.cost_limit_usd ?? REVIEW_COST_LIMIT_USD,
    reviewed_step_count: reviewed.length,
    not_reviewed_step_count: reviewable.length - reviewed.length,
    failed_step_count: failed.length,
    skipped_step_count: skipped.length,
    remark_count: reviewed.reduce((sum, record) => sum + record.remark_count, 0),
    no_remark_step_count: noRemarks.length,
  };
}
