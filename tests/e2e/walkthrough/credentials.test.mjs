// Card U-2 proof for the credentials-file option and the redaction gate.
//
// The end-to-end test starts a dummy stand (a Keycloak-shaped sign-in redirect
// and just enough product DOM), writes a credentials file into a temporary
// directory and runs the real walkthrough driver as a child process in the
// read-only scenario. It then checks that the run signed in, that it produced
// the report and the screenshots, that it did not touch the confirmation or
// save controls, and that no part of the password appears in the report, in the
// report JSON or in the driver's logs.
//
// The last test drives the real recorder with a secret that reached the screen
// and an answer, and proves the report is still clean.

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

import { chromium } from "playwright";

import { parseCredentials, redactSecrets } from "./credentials.mjs";
import { buildReport, renderMarkdown, Walkthrough } from "./report.mjs";
import { disallowedReadOnlyWrites } from "./scenarios.mjs";
import { startStubStand } from "./stub-stand.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(here, "..", "..", "..");

// secretParts returns the whole secret and every window of it, so a check can
// reject a fragment of a leaked password, not only the full string.
function secretParts(secret, width = 8) {
  const parts = new Set([secret]);
  for (let index = 0; index + width <= secret.length; index += 1) {
    parts.add(secret.slice(index, index + width));
  }
  return [...parts];
}

function assertNoSecret(text, secret, label) {
  const value = String(text ?? "");
  for (const part of secretParts(secret)) {
    assert.equal(value.includes(part), false, `${label} contains a part of the password: ${part}`);
  }
}

// runDriver starts the real driver as a child process. The stub stand lives in
// this process, so the child must run asynchronously: a blocking spawn would
// stop the event loop that answers the child's requests.
function runDriver(env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [path.join(here, "walkthrough.mjs")], { cwd: repositoryRoot, env });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => child.kill(), 180_000);
    child.on("close", (status) => {
      clearTimeout(timer);
      resolve({ status, stdout, stderr });
    });
  });
}

test("the credentials file accepts a bare password, keyed values and JSON", () => {
  assert.deepEqual(parseCredentials("hunter2hunter2\n"), { username: "", password: "hunter2hunter2" });
  assert.deepEqual(parseCredentials("username = stub-user\npassword = s3cret-value\n"), {
    username: "stub-user",
    password: "s3cret-value",
  });
  assert.deepEqual(parseCredentials('{"username":"stub-user","password":"s3cret-value"}'), {
    username: "stub-user",
    password: "s3cret-value",
  });
  assert.throws(() => parseCredentials(""));
  assert.throws(() => parseCredentials("# a comment only\n"));
});

test("redaction removes the secret and its URL-encoded forms", () => {
  const secret = "p@ss word&x";
  const text = `plain ${secret} encoded ${encodeURIComponent(secret)}`;
  const redacted = redactSecrets(text, [secret]);
  assert.equal(redacted.includes(secret), false);
  assert.equal(redacted.includes(encodeURIComponent(secret)), false);
  assert.ok(redacted.includes("[REDACTED]"));
});

test("the read-only guard accepts questions and sign-in and rejects a workspace change", () => {
  assert.deepEqual(disallowedReadOnlyWrites([]), []);
  assert.deepEqual(disallowedReadOnlyWrites([{ method: "POST", path: "/api/v1/workspaces/ws_001/questions" }]), []);
  assert.deepEqual(
    disallowedReadOnlyWrites([{ method: "POST", path: "/idp/authenticate" }]),
    [],
  );
  assert.deepEqual(
    disallowedReadOnlyWrites([{ method: "POST", path: "/realms/knowvault/login-actions/authenticate?session_code=x" }]),
    [],
  );
  assert.equal(
    disallowedReadOnlyWrites([
      { method: "POST", path: "/api/v1/workspaces/ws_001/managed-source-confirmations:batch" },
    ]).length,
    1,
  );
  assert.equal(
    disallowedReadOnlyWrites([{ method: "PUT", path: "/api/v1/workspaces/ws_001/model-context" }]).length,
    1,
  );
});

test("a credentials-file run signs in and leaves no part of the password in the report or the logs", async (t) => {
  const password = `kv-${randomBytes(12).toString("hex")}`;
  const dir = await mkdtemp(path.join(os.tmpdir(), "kv-walkthrough-credentials-"));
  t.after(() => rm(dir, { recursive: true, force: true }));
  const credentialsPath = path.join(dir, "stub-user.password");
  await writeFile(credentialsPath, `username = stub-user\npassword = ${password}\n`, "utf8");
  const reportDir = path.join(dir, "report");

  const stand = await startStubStand({ username: "stub-user", password });
  t.after(() => stand.close());

  const result = await runDriver({
    ...process.env,
    KNOWVAULT_WALKTHROUGH_BASE_URL: stand.baseURL,
    KNOWVAULT_WALKTHROUGH_SCENARIO: "read-only",
    KNOWVAULT_WALKTHROUGH_CREDENTIALS: credentialsPath,
    KNOWVAULT_WALKTHROUGH_USER: "stub-user",
    KNOWVAULT_WALKTHROUGH_REPORT_DIR: reportDir,
    KNOWVAULT_PLAYWRIGHT_MODULE: import.meta.resolve("playwright"),
  });
  const logs = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  assert.equal(result.status, 0, `the walkthrough driver failed:\n${logs}`);

  const markdown = await readFile(path.join(reportDir, "report.md"), "utf8");
  const report = JSON.parse(await readFile(path.join(reportDir, "report.json"), "utf8"));
  assert.equal(report.passed, true);
  assert.equal(report.scenario, "read-only");
  assert.equal(report.answers.length, 3);
  for (const answer of report.answers) {
    assert.ok(answer.text.trim() !== "", `empty answer text for ${answer.question}`);
  }
  const screenshots = await readdir(path.join(reportDir, "screenshots"));
  assert.ok(screenshots.length >= report.step_count, `screenshots ${screenshots.length} < steps ${report.step_count}`);

  assert.equal(stand.state.authenticated, 1);
  assert.equal(stand.state.failedLogins, 0);
  assert.equal(stand.state.confirmClicks, 0);
  assert.equal(stand.state.saveClicks, 0);

  assertNoSecret(logs, password, "the driver logs");
  assertNoSecret(markdown, password, "report.md");
  assertNoSecret(JSON.stringify(report), password, "report.json");
});

test("the report redacts a secret that reached the screen or an answer", async () => {
  const password = `screen-${randomBytes(8).toString("hex")}`;
  const redact = (value) => redactSecrets(value, [password]);
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage();
    const walk = new Walkthrough(page, { redact });
    await page.setContent(`<p>the stand leaked ${password}</p>`);
    const failed = await walk.step("a step that fails", async () => {
      throw new Error(`the error message carried ${password}`);
    });
    assert.equal(failed.status, "failed");
    await walk.step("an answer that carried the secret", async () => {
      walk.answer("вопрос", `ответ ${password}`);
    });
    const report = buildReport({
      baseURL: "http://stub.invalid",
      command: "stub",
      scenario: "local",
      startedAt: new Date(),
      finishedAt: new Date(),
      steps: walk.steps,
      redact,
    });
    assertNoSecret(failed.page_excerpt ?? "", password, "the page excerpt");
    assertNoSecret(failed.error ?? "", password, "the step error");
    assertNoSecret(renderMarkdown(report), password, "the rendered report");
    assertNoSecret(JSON.stringify(report), password, "the report JSON");
  } finally {
    await browser.close();
  }
});
