// Card U-4 proof for the vision interface review.
//
// The unit tests cover the checklist parser, the price arithmetic, the answer
// parser and the reviewer's behaviour against a local fake model endpoint.
// They prove:
//   - the image the model receives is the bytes of the step's own screenshot,
//     one review per step, with a cost above zero;
//   - a screen the model finds nothing wrong with is reported as having no
//     remarks, and a run in which every screen gets remarks still passes with
//     every step passed;
//   - a run with no key file, a run with a dummy key and a run whose model
//     address has nothing listening all pass, say the review did not happen and
//     why, and never carry the key file's content into the report;
//   - the review never fails a step.
//
// Two tests are marked `live` and need the real vision model: they review the
// chat screenshot from before the duplicated «Sources» control was removed
// (found in the walkthrough baseline history) and a screenshot the test makes
// deliberately bad by shrinking controls far below the readable size. They run
// when KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE (or the card's key file path)
// exists.

import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import http from "node:http";
import { once } from "node:events";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { chromium } from "playwright";

import { pngDimensions } from "./png.mjs";
import { buildReport, Walkthrough, writeReport } from "./report.mjs";
import {
  costOfUsage,
  createInterfaceReviewer,
  createReviewFromEnvironment,
  DEFAULT_REVIEW_ENDPOINT,
  isPeakHour,
  loadInterfaceRules,
  loadReviewKey,
  parseInterfaceRules,
  parseRemarks,
  REVIEW_COST_LIMIT_USD,
} from "./review.mjs";
import { signIn } from "./signin.mjs";
import { startStubStand } from "./stub-stand.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(here, "..", "..", "..");
const CREDENTIALS = { username: "stub-user", password: "stub-password" };
const PRE_DEDUP_SCREENSHOT = path.join(here, "review-fixtures", "chat-before-sources-dedup.png");

// The card names the key file; the environment variable follows the same
// convention as the other walkthrough options.
const liveKeyFile = (
  process.env.KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE ?? "C:/Users/dants/.deepseek/api_key"
).trim();
const liveSkipReason = existsSync(liveKeyFile)
  ? false
  : `no review key file at ${liveKeyFile} (set KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE)`;

const rules = await loadInterfaceRules(repositoryRoot);

const artifactRoot = (process.env.KNOWVAULT_WALKTHROUGH_TEST_ARTIFACTS ?? "").trim();

async function testRoot(t, name) {
  if (artifactRoot !== "") {
    const directory = path.join(artifactRoot, `review-${name}`);
    await rm(directory, { recursive: true, force: true });
    await mkdir(directory, { recursive: true });
    return directory;
  }
  const directory = await mkdtemp(path.join(os.tmpdir(), `kv-review-${name}-`));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

const DEFAULT_USAGE = {
  prompt_tokens: 1200,
  completion_tokens: 120,
  total_tokens: 1320,
  prompt_cache_hit_tokens: 0,
  prompt_cache_miss_tokens: 1200,
};

function modelPayload(remarks, usage = DEFAULT_USAGE) {
  return {
    model: "deepseek-flash",
    choices: [{ message: { role: "assistant", content: JSON.stringify({ remarks }) }, finish_reason: "stop" }],
    usage,
  };
}

// startFakeModel is a local OpenAI-compatible endpoint that records every
// request, the image bytes it carried and the scripted answer it returned. It
// lets the tests prove what the reviewer sent without reaching the real model.
async function startFakeModel(respond) {
  const requests = [];
  const server = http.createServer(async (request, response) => {
    const chunks = [];
    for await (const chunk of request) chunks.push(chunk);
    let body = null;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      body = null;
    }
    const parts = Array.isArray(body?.messages?.[0]?.content) ? body.messages[0].content : [];
    const imagePart = parts.find((part) => part?.type === "image_url");
    const match = String(imagePart?.image_url?.url ?? "").match(/^data:image\/png;base64,([\s\S]*)$/);
    const image = match === null ? null : Buffer.from(match[1], "base64");
    const record = { body, image, authorization: request.headers.authorization ?? "" };
    requests.push(record);
    await respond({ request, response, body, image, index: requests.length - 1, record });
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  return {
    requests,
    baseURL: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

function sendJson(response, status, payload) {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(payload));
}

async function filesUnder(directory) {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) result.push(...(await filesUnder(full)));
    else result.push(full);
  }
  return result;
}

// filesContaining returns the files under a directory whose bytes hold a
// string. It is how "no part of the key file's content reached the report" is
// checked on the bytes, not on a summary.
async function filesContaining(directory, needle) {
  const matches = [];
  const target = Buffer.from(needle, "utf8");
  for (const file of await filesUnder(directory)) {
    if ((await readFile(file)).includes(target)) matches.push(file);
  }
  return matches;
}

// trackedFilesContaining lists repository files tracked by git that hold a
// string. A random per-run key cannot appear in a committed file; this proves
// it.
function trackedFilesContaining(needle) {
  try {
    const output = execFileSync("git", ["grep", "-l", "-F", "-e", needle], {
      cwd: repositoryRoot,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    });
    return output.trim().split("\n").filter(Boolean);
  } catch (error) {
    if (error !== null && typeof error === "object" && error.status === 1) return [];
    return null;
  }
}

// runStubScenario walks four screens of the dummy stand with the real recorder
// and the real report writer, with whatever reviewer the caller configured.
async function runStubScenario({ stand, credentials, reportDir, reviewer, disabledReason }) {
  await mkdir(reportDir, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ viewport: { width: 1000, height: 720 }, locale: "ru-RU" });
    const page = await context.newPage();
    page.on("dialog", (dialog) => void dialog.accept());
    const walk = new Walkthrough(page, {
      screenshotDir: path.join(reportDir, "screenshots"),
      visualMode: "off",
      referenceDir: null,
      differenceDir: null,
      reviewer,
      reviewDisabledReason: disabledReason,
    });
    const startedAt = new Date();
    await walk.step("sign in as the test user", async () => {
      await signIn(page, { baseURL: stand.baseURL, credentials });
    });
    await walk.step("open the sources screen", async () => {
      await page.locator("#nav-sources").click();
      await page.locator("#view-sources h2").waitFor({ state: "visible", timeout: 30_000 });
    });
    await walk.step("open the settings screen", async () => {
      await page.locator("#nav-settings").click();
      await page.locator("#view-settings h2").waitFor({ state: "visible", timeout: 30_000 });
    });
    await walk.step("open the chat screen", async () => {
      await page.locator("#nav-search").click();
      await page.locator("#ask-question").waitFor({ state: "visible", timeout: 30_000 });
    });
    const report = buildReport({
      baseURL: stand.baseURL,
      command: "node --test tests/e2e/walkthrough/review.test.mjs",
      scenario: "local",
      startedAt,
      finishedAt: new Date(),
      steps: walk.steps,
      visual: { mode: "off" },
      review: { reviewer, disabledReason },
    });
    await writeReport(reportDir, report);
    return report;
  } finally {
    await browser.close();
  }
}

async function withStubStand(run) {
  const stand = await startStubStand(CREDENTIALS);
  try {
    return await run(stand);
  } finally {
    await stand.close();
  }
}

test("the checklist is the numbered rules of the principles document", () => {
  assert.equal(rules.length, 15);
  assert.deepEqual(
    rules.map((rule) => rule.number),
    Array.from({ length: 15 }, (_, index) => index + 1),
  );
  const duplication = rules.find((rule) => rule.number === 2);
  assert.match(duplication.title, /Ничего дважды/);
  assert.match(duplication.text, /Sources/);
  const readable = rules.find((rule) => rule.number === 12);
  assert.match(readable.title, /Читаемый размер/);
  assert.match(readable.text, /36 px/);
  // The prose section that describes how the rules are checked is not a rule.
  assert.equal(parseInterfaceRules("## Как проверяется\n\n- Модель со зрением...").length, 0);
});

test("the cost uses the published peak and off-peak prices and the reported cache split", () => {
  // Monday 02:00 UTC is inside the peak window; Sunday is off-peak.
  assert.equal(isPeakHour(new Date("2026-01-05T02:00:00Z")), true);
  assert.equal(isPeakHour(new Date("2026-01-05T05:00:00Z")), false);
  assert.equal(isPeakHour(new Date("2026-01-04T02:00:00Z")), false);

  const peak = costOfUsage(
    { prompt_cache_hit_tokens: 0, prompt_cache_miss_tokens: 1_000_000, completion_tokens: 1_000_000 },
    { model: "deepseek-flash", at: new Date("2026-01-05T02:00:00Z") },
  );
  assert.equal(Number(peak.toFixed(4)), Number((0.3 + 1.2).toFixed(4)));

  const offPeak = costOfUsage(
    { prompt_cache_hit_tokens: 1_000_000, prompt_cache_miss_tokens: 0, completion_tokens: 0 },
    { model: "deepseek-flash", at: new Date("2026-01-04T02:00:00Z") },
  );
  assert.equal(Number(offPeak.toFixed(4)), 0.003);

  // A response without usage, or a model without a published price, is unknown.
  assert.equal(costOfUsage(null, { model: "deepseek-flash" }), null);
  assert.equal(costOfUsage(DEFAULT_USAGE, { model: "some-other-model" }), null);
});

test("the answer parser keeps usable remarks and rejects anything else", () => {
  const parsed = parseRemarks(
    JSON.stringify({
      remarks: [
        { rule: 2, where: "правая панель вверху", note: "Счётчик Sources показан дважды" },
        { rule: "12", where: "панель навигации", note: "Кнопки ниже 36 px" },
        { rule: 0, where: "x", note: "no rule" },
        { where: "nowhere", note: "no rule number" },
        { rule: 3, where: "", note: "" },
      ],
    }),
  );
  assert.equal(parsed.length, 2);
  assert.deepEqual(parsed.map((remark) => remark.rule), [2, 12]);

  const fenced = parseRemarks('```json\n{"remarks":[{"rule":9,"where":"шапка","note":"нет версии"}]}\n```');
  assert.equal(fenced.length, 1);
  assert.throws(() => parseRemarks("not json at all"), /did not answer with JSON/);
  assert.throws(() => parseRemarks('{"other":true}'), /without a remarks list/);
});

test("the png header reader returns the size the review states in its prompt", async () => {
  const bytes = await readFile(PRE_DEDUP_SCREENSHOT);
  assert.deepEqual(pngDimensions(bytes), { width: 1440, height: 900 });
  assert.throws(() => pngDimensions(Buffer.from("not a png")), /not a PNG/);
});

test("a review sends the given screenshot bytes and reports its cost", async () => {
  const model = await startFakeModel(({ response }) => sendJson(response, 200, modelPayload([{ rule: 2, where: "верх", note: "дубль" }])));
  const reviewer = createInterfaceReviewer({
    rules,
    apiKey: "test-key-not-a-secret",
    endpoint: model.baseURL,
    fetchImpl: fetch,
    maxRetries: 0,
    now: () => new Date("2026-01-04T02:00:00Z"),
  });
  try {
    const screenshot = await readFile(PRE_DEDUP_SCREENSHOT);
    const result = await reviewer.review({ step: "chat", screenshot, width: 1440, height: 900 });
    assert.equal(result.status, "reviewed");
    assert.equal(result.remark_count, 1);
    assert.equal(model.requests.length, 1);
    assert.ok(model.requests[0].image.equals(screenshot), "the model did not receive the step's own screenshot bytes");
    assert.equal(model.requests[0].body.model, "deepseek-flash");
    assert.equal(model.requests[0].body.thinking.type, "disabled");
    assert.match(model.requests[0].body.messages[0].content[0].text, /Ничего дважды/);
    assert.ok(result.cost_usd > 0, `cost ${result.cost_usd}`);
    assert.equal(reviewer.spent_usd, result.cost_usd);
  } finally {
    await model.close();
  }
});

test("a screen the model finds nothing wrong with is reviewed with no remarks", async () => {
  const model = await startFakeModel(({ response }) => sendJson(response, 200, modelPayload([])));
  const reviewer = createInterfaceReviewer({
    rules,
    apiKey: "test-key-not-a-secret",
    endpoint: model.baseURL,
    maxRetries: 0,
  });
  try {
    const result = await reviewer.review({ step: "settings", screenshot: Buffer.from(await readFile(PRE_DEDUP_SCREENSHOT)), width: 1440, height: 900 });
    assert.equal(result.status, "reviewed");
    assert.equal(result.remark_count, 0);
    assert.deepEqual(result.remarks, []);
    assert.equal(reviewer.counts.without_remarks, 1);
  } finally {
    await model.close();
  }
});

test("a model failure is a recorded review failure, never a throw", async () => {
  const model = await startFakeModel(({ response }) => sendJson(response, 500, { error: { type: "server_error" } }));
  const reviewer = createInterfaceReviewer({
    rules,
    apiKey: "test-key-not-a-secret",
    endpoint: model.baseURL,
    maxRetries: 0,
  });
  try {
    const result = await reviewer.review({ step: "chat", screenshot: await readFile(PRE_DEDUP_SCREENSHOT), width: 1440, height: 900 });
    assert.equal(result.status, "failed");
    assert.match(result.reason, /HTTP 500/);
    assert.deepEqual(result.remarks, []);
  } finally {
    await model.close();
  }
});

test("a refused key is reported once, without the key, and is not retried", async () => {
  const key = "dummy-key-0123456789abcdef";
  const model = await startFakeModel(({ response }) =>
    sendJson(response, 401, { error: { message: "Authentication Fails", type: "authentication_error" } }),
  );
  const reviewer = createInterfaceReviewer({ rules, apiKey: key, endpoint: model.baseURL });
  try {
    const result = await reviewer.review({ step: "chat", screenshot: await readFile(PRE_DEDUP_SCREENSHOT), width: 1440, height: 900 });
    assert.equal(result.status, "failed");
    assert.match(result.reason, /HTTP 401/);
    assert.match(result.reason, /authentication_error/);
    assert.ok(!result.reason.includes(key), "the key reached the reason");
    assert.equal(model.requests.length, 1);
  } finally {
    await model.close();
  }
});

test("the reviewer stops calling the model once the cost ceiling would be crossed", async () => {
  const model = await startFakeModel(({ response }) => sendJson(response, 200, modelPayload([])));
  const reviewer = createInterfaceReviewer({
    rules,
    apiKey: "test-key-not-a-secret",
    endpoint: model.baseURL,
    maxRetries: 0,
    costLimitUsd: 0.0001,
  });
  try {
    const result = await reviewer.review({ step: "chat", screenshot: await readFile(PRE_DEDUP_SCREENSHOT), width: 1440, height: 900 });
    assert.equal(result.status, "skipped");
    assert.match(result.reason, /cost ceiling/);
    assert.equal(model.requests.length, 0);
  } finally {
    await model.close();
  }
});

test("the environment decides whether the review runs", async (t) => {
  const root = await testRoot(t, "env");

  const noKey = await createReviewFromEnvironment({}, { root: repositoryRoot });
  assert.equal(noKey.reviewer, null);
  assert.match(noKey.reason, /KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE/);

  const switchedOff = await createReviewFromEnvironment(
    { KNOWVAULT_WALKTHROUGH_REVIEW: "0", KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE: "C:/does/not/exist" },
    { root: repositoryRoot },
  );
  assert.equal(switchedOff.reviewer, null);
  assert.match(switchedOff.reason, /switched off/);

  const missing = await createReviewFromEnvironment(
    { KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE: path.join(root, "absent") },
    { root: repositoryRoot },
  );
  assert.equal(missing.reviewer, null);
  assert.match(missing.reason, /could not be read/);

  const emptyFile = path.join(root, "empty");
  await writeFile(emptyFile, "   \n");
  const empty = await createReviewFromEnvironment({ KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE: emptyFile }, { root: repositoryRoot });
  assert.equal(empty.reviewer, null);
  assert.match(empty.reason, /is empty/);

  const keyFile = path.join(root, "key");
  await writeFile(keyFile, "dummy-key-0123456789abcdef\n");
  const ready = await createReviewFromEnvironment(
    { KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE: keyFile, KNOWVAULT_WALKTHROUGH_REVIEW_BASE_URL: "http://127.0.0.1:1" },
    { root: repositoryRoot },
  );
  assert.notEqual(ready.reviewer, null);
  assert.equal(ready.key, "dummy-key-0123456789abcdef");
  assert.equal(ready.reviewer.descriptor.model, "deepseek-flash");
});

test("a full run reviews every screen: one review per step, the step's own screenshot, a cost above zero", async (t) => {
  const root = await testRoot(t, "every-step");
  const reportDir = path.join(root, "report");
  const model = await startFakeModel(({ response }) =>
    sendJson(response, 200, modelPayload([{ rule: 2, where: "верхняя панель", note: "дубль" }])),
  );
  const reviewer = createInterfaceReviewer({ rules, apiKey: "test-key-not-a-secret", endpoint: model.baseURL, maxRetries: 0 });
  try {
    const report = await withStubStand((stand) =>
      runStubScenario({ stand, credentials: CREDENTIALS, reportDir, reviewer }),
    );
    assert.equal(report.passed, true, JSON.stringify(report.failed_steps));
    assert.equal(report.review.status, "reviewed");
    assert.equal(report.review.reviewed_step_count, report.step_count);
    assert.equal(model.requests.length, report.step_count, "the reviewer did not send one review per step");
    assert.ok(report.review.cost_usd > 0, `cost ${report.review.cost_usd}`);
    assert.ok(report.review.cost_usd <= REVIEW_COST_LIMIT_USD);

    // Result 1: every review carried that step's own screenshot bytes.
    for (const [index, step] of report.steps.entries()) {
      const onDisk = await readFile(path.join(reportDir, step.screenshot));
      assert.ok(model.requests[index].image.equals(onDisk), `review ${index} did not send ${step.name}'s screenshot`);
    }

    const markdown = await readFile(path.join(reportDir, "report.md"), "utf8");
    for (const [index, step] of report.steps.entries()) {
      assert.ok(markdown.includes(`### ${index + 1}. ${step.name}\n`), `no review section for ${step.name}`);
    }
    assert.match(markdown, /## Interface review \(vision model\)/);
  } finally {
    await model.close();
  }
});

test("a screen with no remarks is reported as having none, and a run full of remarks still passes", async (t) => {
  const root = await testRoot(t, "no-remarks");
  const reportDir = path.join(root, "report");
  const model = await startFakeModel(({ response, index }) =>
    sendJson(
      response,
      200,
      modelPayload(index === 1 ? [] : [{ rule: 12, where: "панель навигации", note: "кнопки ниже 36 px" }]),
    ),
  );
  const reviewer = createInterfaceReviewer({ rules, apiKey: "test-key-not-a-secret", endpoint: model.baseURL, maxRetries: 0 });
  try {
    const report = await withStubStand((stand) =>
      runStubScenario({ stand, credentials: CREDENTIALS, reportDir, reviewer }),
    );
    assert.equal(report.passed, true, JSON.stringify(report.failed_steps));
    assert.equal(report.failed_step_count, 0);
    for (const step of report.steps) assert.equal(step.status, "passed", `${step.name} failed`);
    assert.equal(report.review.status, "reviewed");
    assert.equal(report.review.no_remark_step_count, 1);
    const quiet = report.steps[1];
    assert.equal(quiet.review.status, "reviewed");
    assert.equal(quiet.review.remark_count, 0);
    assert.deepEqual(quiet.review.remarks, []);
    assert.equal(report.steps[0].review.remark_count, 1);

    const markdown = await readFile(path.join(reportDir, "report.md"), "utf8");
    assert.match(markdown, /No remarks\./);
    assert.match(markdown, /Rule 12/);
  } finally {
    await model.close();
  }
});

test("a run with no key file passes and says the review did not happen", async (t) => {
  const root = await testRoot(t, "no-key-run");
  const reportDir = path.join(root, "report");
  const setup = await createReviewFromEnvironment({}, { root: repositoryRoot });
  assert.equal(setup.reviewer, null);
  const report = await withStubStand((stand) =>
    runStubScenario({ stand, credentials: CREDENTIALS, reportDir, reviewer: setup.reviewer, disabledReason: setup.reason }),
  );
  assert.equal(report.passed, true, JSON.stringify(report.failed_steps));
  assert.equal(report.review.status, "not_reviewed");
  assert.match(report.review.reason, /KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE/);
  const markdown = await readFile(path.join(reportDir, "report.md"), "utf8");
  assert.match(markdown, /Review did not happen:/);
  await assertNoReviewItDidNotRun(report, reportDir);
});

test("a run whose key is refused passes and says the review did not happen, without the key", async (t) => {
  const root = await testRoot(t, "dummy-key-run");
  const reportDir = path.join(root, "report");
  const dummyKey = `dummy-key-${Date.now()}-0123456789abcdef`;
  const keyFile = path.join(root, "dummy.key");
  await writeFile(keyFile, `${dummyKey}\n`);
  const model = await startFakeModel(({ response }) =>
    sendJson(response, 401, { error: { message: "Authentication Fails", type: "authentication_error" } }),
  );
  try {
    const setup = await createReviewFromEnvironment(
      { KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE: keyFile, KNOWVAULT_WALKTHROUGH_REVIEW_BASE_URL: model.baseURL },
      { root: repositoryRoot },
    );
    assert.notEqual(setup.reviewer, null);
    const report = await withStubStand((stand) =>
      runStubScenario({ stand, credentials: CREDENTIALS, reportDir, reviewer: setup.reviewer, disabledReason: setup.reason }),
    );
    assert.equal(report.passed, true, JSON.stringify(report.failed_steps));
    assert.equal(report.review.status, "not_reviewed");
    assert.match(report.review.reason, /HTTP 401/);

    // Result 4: no part of the key file's content is in the report or any file
    // the run wrote.
    assert.deepEqual(await filesContaining(reportDir, dummyKey), []);
    assert.ok(!JSON.stringify(report).includes(dummyKey), "the key reached the report");
    const tracked = trackedFilesContaining(dummyKey);
    assert.deepEqual(tracked ?? [], [], `the key reached a tracked file: ${tracked}`);
    await assertNoReviewItDidNotRun(report, reportDir);
  } finally {
    await model.close();
  }
});

test("a run whose model address has nothing listening passes and says the review did not happen", async (t) => {
  const root = await testRoot(t, "dead-model-run");
  const reportDir = path.join(root, "report");
  const keyFile = path.join(root, "key");
  await writeFile(keyFile, "dummy-key-0123456789abcdef\n");
  // Bind a port, learn it, release it: nothing listens there afterwards.
  const probe = http.createServer(() => {});
  probe.listen(0, "127.0.0.1");
  await once(probe, "listening");
  const deadPort = probe.address().port;
  await new Promise((resolve) => probe.close(resolve));

  const setup = await createReviewFromEnvironment(
    {
      KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE: keyFile,
      KNOWVAULT_WALKTHROUGH_REVIEW_BASE_URL: `http://127.0.0.1:${deadPort}`,
    },
    { root: repositoryRoot },
  );
  assert.notEqual(setup.reviewer, null);
  const report = await withStubStand((stand) =>
    runStubScenario({ stand, credentials: CREDENTIALS, reportDir, reviewer: setup.reviewer, disabledReason: setup.reason }),
  );
  assert.equal(report.passed, true, JSON.stringify(report.failed_steps));
  assert.equal(report.review.status, "not_reviewed");
  assert.match(report.review.reason, /could not be reached/);
  await assertNoReviewItDidNotRun(report, reportDir);
});

async function assertNoReviewItDidNotRun(report, reportDir) {
  for (const step of report.steps) {
    assert.ok(
      ["failed", "not_run", "skipped"].includes(step.review.status),
      `${step.name}: ${JSON.stringify(step.review)}`,
    );
    assert.ok(step.review.reason, `${step.name} has no review reason`);
  }
  const markdown = await readFile(path.join(reportDir, "report.md"), "utf8");
  assert.match(markdown, /Review did not happen:/);
}

// reviewUntil asks the model for a fresh judgement until the predicate holds.
// The vision model is a stochastic reader, so the live tests look for the
// named violation in a small number of independent reviews of the same
// deliberately bad picture instead of betting on one sample. The picture and
// the question never change; only the sample does.
async function reviewUntil(reviewer, screen, predicate, attempts = 3) {
  let last = null;
  for (let index = 0; index < attempts; index += 1) {
    last = await reviewer.review(screen);
    if (last.status === "reviewed" && predicate(last)) return last;
  }
  return last;
}

async function liveReviewer(options = {}) {
  const key = await loadReviewKey(liveKeyFile);
  return createInterfaceReviewer({ rules, apiKey: key, endpoint: DEFAULT_REVIEW_ENDPOINT, ...options });
}

test(
  "live: the pre-change chat screenshot is told to have the duplicated Sources control under rule 2",
  { skip: liveSkipReason },
  async () => {
    const screenshot = await readFile(PRE_DEDUP_SCREENSHOT);
    const reviewer = await liveReviewer();
    const result = await reviewUntil(
      reviewer,
      { step: "chat, before the duplicated Sources control was removed", screenshot, width: 1440, height: 900 },
      (review) => review.remarks.some((remark) => remark.rule === 2 && /sources/i.test(`${remark.where} ${remark.note}`)),
    );
    assert.equal(result.status, "reviewed", JSON.stringify(result));
    const duplication = result.remarks.find((remark) => remark.rule === 2);
    assert.ok(duplication, `no rule 2 remark: ${JSON.stringify(result.remarks)}`);
    assert.match(`${duplication.where} ${duplication.note}`, /sources/i);
    assert.ok(duplication.where.length > 0, "rule 2 has no place on the screen");
    assert.ok(result.cost_usd > 0);
  },
);

// badControlsScreenshot renders the dummy stand with its controls shrunk far
// below the readable size. Only the test injects that stylesheet; web/src is
// untouched.
async function badControlsScreenshot(directory) {
  const stand = await startStubStand(CREDENTIALS);
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ viewport: { width: 1000, height: 720 }, locale: "ru-RU" });
    const page = await context.newPage();
    page.on("dialog", (dialog) => void dialog.accept());
    await signIn(page, { baseURL: stand.baseURL, credentials: CREDENTIALS });
    await page.locator("#nav-search").click();
    await page.locator("#ask-question").waitFor({ state: "visible", timeout: 30_000 });
    await page.addStyleTag({
      content:
        "button, input, textarea { height: 6px !important; min-height: 6px !important; font-size: 4px !important; padding: 0 2px !important; }",
    });
    const picture = await page.screenshot({ fullPage: true, caret: "hide" });
    await writeFile(path.join(directory, "controls-too-small.png"), picture);
    return picture;
  } finally {
    await browser.close();
    await stand.close();
  }
}

test(
  "live: a screenshot with controls shrunk below the readable size is told so under rule 12",
  { skip: liveSkipReason },
  async (t) => {
    const root = await testRoot(t, "bad-controls");
    const screenshot = await badControlsScreenshot(root);
    const reviewer = await liveReviewer();
    const result = await reviewUntil(
      reviewer,
      { step: "chat with controls shrunk far below the readable size", screenshot, width: 1000, height: 720 },
      (review) => review.remarks.some((remark) => remark.rule === 12),
    );
    assert.equal(result.status, "reviewed", JSON.stringify(result));
    const tooSmall = result.remarks.find((remark) => remark.rule === 12);
    assert.ok(tooSmall, `no rule 12 remark: ${JSON.stringify(result.remarks)}`);
    assert.ok(tooSmall.where.length > 0, "rule 12 has no place on the screen");
    assert.ok(result.cost_usd > 0);
  },
);
