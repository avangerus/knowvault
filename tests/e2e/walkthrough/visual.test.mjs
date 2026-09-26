// Card U-3 proof for the screen comparison.
//
// The unit tests cover the decoder, the encoder, the difference rule on
// hand-built pictures, and the clock normalization that keeps a wall-clock
// reading from being mistaken for a screen change. The end-to-end tests drive
// the real Walkthrough, the real report writer and a real headless browser
// against the dummy stand, and move one control with a stylesheet injected
// inside the test — never in web/src/. They prove:
//   - a run whose screens match the approved references passes and reports the
//     difference per step, and leaves every reference byte-identical;
//   - a deliberately moved control fails exactly its own step, produces a
//     picture that highlights the difference, and fails the run as a whole,
//     while the approved references are still byte-identical;
//   - the update command replaces the references and its report names the
//     replaced one, after which an ordinary run passes again;
//   - the read-only (stand) mode reports the same difference without failing;
//   - two runs of unchanged code on two different calendar days both pass,
//     because the wall-clock reading on the screen is pinned before the
//     screenshot (card U-3 return 1).

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { chromium } from "playwright";

import { CLOCK_TEXT_PLACEHOLDER, CLOCK_TIMESTAMP_PLACEHOLDER, normaliseClockText } from "./clock.mjs";
import { decodePng, encodePng } from "./png.mjs";
import { buildReport, Walkthrough, writeReport } from "./report.mjs";
import { signIn } from "./signin.mjs";
import { startStubStand } from "./stub-stand.mjs";
import { comparePngs, DEFAULT_DIFFERENCE_THRESHOLD } from "./visual.mjs";

const CREDENTIALS = { username: "stub-user", password: "stub-password" };

// A test-only artifact root. When KNOWVAULT_WALKTHROUGH_TEST_ARTIFACTS names a
// directory, these tests keep their screenshots, references and difference
// pictures there instead of a removed temporary directory, so a person can
// open the picture a deliberately broken screen produced.
const artifactRoot = (process.env.KNOWVAULT_WALKTHROUGH_TEST_ARTIFACTS ?? "").trim();

async function testRoot(t, name) {
  if (artifactRoot !== "") {
    const directory = path.join(artifactRoot, name);
    await rm(directory, { recursive: true, force: true });
    await mkdir(directory, { recursive: true });
    return directory;
  }
  const directory = await mkdtemp(path.join(os.tmpdir(), `kv-visual-${name}-`));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

function solid(width, height, [red, green, blue]) {
  const data = new Uint8Array(width * height * 4);
  for (let index = 0; index < data.length; index += 4) {
    data[index] = red;
    data[index + 1] = green;
    data[index + 2] = blue;
    data[index + 3] = 255;
  }
  return { width, height, data };
}

function paint(image, { x, y, width, height }, [red, green, blue]) {
  const data = image.data.slice();
  for (let row = y; row < y + height; row += 1) {
    for (let column = x; column < x + width; column += 1) {
      const index = (row * image.width + column) * 4;
      data[index] = red;
      data[index + 1] = green;
      data[index + 2] = blue;
      data[index + 3] = 255;
    }
  }
  return { width: image.width, height: image.height, data };
}

function redPixels(png) {
  const image = decodePng(png);
  let count = 0;
  for (let index = 0; index < image.data.length; index += 4) {
    if (image.data[index] > 200 && image.data[index + 1] < 80 && image.data[index + 2] < 80) count += 1;
  }
  return count;
}

test("the PNG codec round-trips RGBA pixels", () => {
  const image = paint(solid(8, 4, [255, 255, 255]), { x: 2, y: 1, width: 3, height: 2 }, [10, 20, 30]);
  const decoded = decodePng(encodePng(image));
  assert.equal(decoded.width, 8);
  assert.equal(decoded.height, 4);
  assert.deepEqual([...decoded.data], [...image.data]);
  assert.throws(() => decodePng(Buffer.from("not a png at all")), /not a PNG/);
});

test("identical pictures differ by nothing and get no difference picture", () => {
  const image = paint(solid(200, 100, [250, 250, 250]), { x: 10, y: 10, width: 40, height: 20 }, [0, 0, 0]);
  const result = comparePngs(encodePng(image), encodePng(image));
  assert.equal(result.different_pixels, 0);
  assert.equal(result.difference_ratio, 0);
  assert.equal(result.beyond_threshold, false);
  assert.equal(result.diff, null);
});

test("a moved control is beyond the threshold and the difference picture marks it", () => {
  const before = paint(solid(200, 100, [250, 250, 250]), { x: 10, y: 10, width: 40, height: 20 }, [0, 0, 0]);
  const after = paint(solid(200, 100, [250, 250, 250]), { x: 10, y: 70, width: 40, height: 20 }, [0, 0, 0]);
  const result = comparePngs(encodePng(before), encodePng(after));
  assert.equal(result.beyond_threshold, true);
  assert.ok(result.difference_ratio > DEFAULT_DIFFERENCE_THRESHOLD, `ratio ${result.difference_ratio}`);
  assert.notEqual(result.diff, null);
  // The old and the new position of the control are both marked.
  assert.ok(redPixels(result.diff) >= 40 * 20 * 2, "the difference picture does not mark both positions");
});

test("a picture of a different size is beyond any threshold", () => {
  const result = comparePngs(encodePng(solid(10, 10, [1, 2, 3])), encodePng(solid(20, 10, [1, 2, 3])));
  assert.equal(result.size_mismatch, true);
  assert.equal(result.difference_ratio, 1);
  assert.equal(result.beyond_threshold, true);
  assert.notEqual(result.diff, null);
});

test("the same screen on two different days normalises to the same clock text", () => {
  // The two shapes the product renders, on two different calendar days.
  const dayOne = "Last successful update: Sep 25, 11:58 PM · observed 2026-09-25T21:58:00Z";
  const dayTwo = "Last successful update: Sep 26, 12:04 AM · observed 2026-09-26T10:04:31+03:00";
  const normalised = normaliseClockText(dayOne);
  assert.equal(normalised, `Last successful update: ${CLOCK_TEXT_PLACEHOLDER} · observed ${CLOCK_TIMESTAMP_PLACEHOLDER}`);
  assert.equal(normaliseClockText(dayTwo), normalised);
  // Normalising an already normalised screen changes nothing.
  assert.equal(normaliseClockText(normalised), normalised);
  // A date without a time of day is content, not a clock reading.
  assert.equal(normaliseClockText("signed on 2025-01-15"), "signed on 2025-01-15");
  assert.equal(normaliseClockText("nothing time-shaped here"), "nothing time-shaped here");
});

// hashTree returns one sha256 per file under a directory, keyed by its relative
// path, so "the references did not change" is checked on the bytes.
async function hashTree(directory) {
  const result = {};
  const entries = await readdir(directory, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    const bytes = await readFile(path.join(directory, entry.name));
    result[entry.name] = createHash("sha256").update(bytes).digest("hex");
  }
  return result;
}

// runStubScenario walks four screens of the dummy stand with the real
// recorder. `move` injects a stylesheet that moves one control on the Sources
// screen; only the test does that, and only for the run that wants it. `clock`
// pins the browser's clock to one moment, so two calls can play the same stand
// on two different calendar days (card U-3 return 1).
async function runStubScenario({ stand, credentials, reportDir, referenceDir, visualMode, move = false, clock = null }) {
  await mkdir(reportDir, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ viewport: { width: 1000, height: 720 }, locale: "ru-RU" });
    if (typeof clock === "string") {
      // Keep every date-parsing path real; only "now" is pinned.
      await context.addInitScript(({ fixed }) => {
        const RealDate = Date;
        const fixedMilliseconds = RealDate.parse(fixed);
        class FixedDate extends RealDate {
          constructor(...args) {
            if (args.length === 0) super(fixedMilliseconds);
            else super(...args);
          }
          static now() {
            return fixedMilliseconds;
          }
        }
        FixedDate.parse = RealDate.parse;
        FixedDate.UTC = RealDate.UTC;
        globalThis.Date = FixedDate;
      }, { fixed: clock });
    }
    const page = await context.newPage();
    page.on("dialog", (dialog) => void dialog.accept());
    const walk = new Walkthrough(page, {
      screenshotDir: path.join(reportDir, "screenshots"),
      referenceDir,
      referenceLabel: referenceDir,
      visualMode,
      differenceDir: path.join(reportDir, "differences"),
      differenceThreshold: DEFAULT_DIFFERENCE_THRESHOLD,
      pixelTolerance: 16,
    });
    const startedAt = new Date();
    await walk.step("sign in as the test user", async () => {
      await signIn(page, { baseURL: stand.baseURL, credentials });
    });
    await walk.step("open the sources screen", async () => {
      await page.locator("#nav-sources").click();
      await page.locator("#view-sources h2").waitFor({ state: "visible", timeout: 30_000 });
      if (move) await page.addStyleTag({ content: "#confirm { transform: translateY(60px); }" });
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
      command: "node --test tests/e2e/walkthrough/visual.test.mjs",
      scenario: visualMode === "report" ? "read-only" : "local",
      startedAt,
      finishedAt: new Date(),
      steps: walk.steps,
      visual: { mode: visualMode, threshold: DEFAULT_DIFFERENCE_THRESHOLD, pixelTolerance: 16, referenceLabel: referenceDir },
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

test("two runs of unchanged code both pass and leave the approved references byte-identical", async (t) => {
  const root = await testRoot(t, "unchanged");
  const referenceDir = path.join(root, "references");
  await withStubStand(async (stand) => {
    const approved = await runStubScenario({
      stand,
      credentials: CREDENTIALS,
      reportDir: path.join(root, "update"),
      referenceDir,
      visualMode: "update",
    });
    assert.equal(approved.passed, true);
    assert.equal(approved.visual.references_changed_count, 4);
    const referencesAfterApproval = await hashTree(referenceDir);

    const first = await runStubScenario({
      stand,
      credentials: CREDENTIALS,
      reportDir: path.join(root, "run1"),
      referenceDir,
      visualMode: "enforce",
    });
    assert.equal(first.passed, true, JSON.stringify(first.failed_steps));
    assert.equal(first.visual.compared_step_count, 4);
    assert.equal(first.visual.differing_step_count, 0);
    for (const step of first.steps) {
      assert.equal(step.visual.status, "same", `${step.name}: ${JSON.stringify(step.visual)}`);
      assert.ok(step.visual.difference_ratio <= first.visual.difference_threshold);
    }

    const second = await runStubScenario({
      stand,
      credentials: CREDENTIALS,
      reportDir: path.join(root, "run2"),
      referenceDir,
      visualMode: "enforce",
    });
    assert.equal(second.passed, true, JSON.stringify(second.failed_steps));
    assert.equal(second.visual.differing_step_count, 0);
    assert.deepEqual(await hashTree(referenceDir), referencesAfterApproval);
  });
});

test("two runs of unchanged code on two different calendar days both pass", async (t) => {
  const root = await testRoot(t, "different-days");
  const referenceDir = path.join(root, "references");
  await withStubStand(async (stand) => {
    // Day one approves the references; the dummy stand renders the browser's own
    // clock, so the two runs show the differently dated text the real stand
    // shows on two days.
    const dayOne = await runStubScenario({
      stand,
      credentials: CREDENTIALS,
      reportDir: path.join(root, "day-one"),
      referenceDir,
      visualMode: "update",
      clock: "2026-01-01T12:00:00Z",
    });
    assert.equal(dayOne.passed, true);
    assert.equal(dayOne.visual.references_changed_count, 4);
    const approved = await hashTree(referenceDir);

    const dayTwo = await runStubScenario({
      stand,
      credentials: CREDENTIALS,
      reportDir: path.join(root, "day-two"),
      referenceDir,
      visualMode: "enforce",
      clock: "2026-06-15T12:00:00Z",
    });
    assert.equal(dayTwo.passed, true, JSON.stringify(dayTwo.failed_steps));
    assert.equal(dayTwo.visual.compared_step_count, 4);
    assert.equal(dayTwo.visual.differing_step_count, 0);
    for (const step of dayTwo.steps) {
      assert.equal(step.visual.status, "same", `${step.name}: ${JSON.stringify(step.visual)}`);
      assert.ok(step.visual.difference_ratio <= dayTwo.visual.difference_threshold);
    }
    // Result 4: the second day's ordinary run left the references byte-identical.
    assert.deepEqual(await hashTree(referenceDir), approved);
  });
});

test("a deliberately moved control fails its step with a difference picture, the others pass, and the references stay untouched", async (t) => {
  const root = await testRoot(t, "moved");
  const referenceDir = path.join(root, "references");
  await withStubStand(async (stand) => {
    await runStubScenario({
      stand,
      credentials: CREDENTIALS,
      reportDir: path.join(root, "update"),
      referenceDir,
      visualMode: "update",
    });
    const referencesBefore = await hashTree(referenceDir);

    const moved = await runStubScenario({
      stand,
      credentials: CREDENTIALS,
      reportDir: path.join(root, "moved"),
      referenceDir,
      visualMode: "enforce",
      move: true,
    });
    assert.equal(moved.passed, false, "the run with the moved control passed");
    assert.deepEqual(moved.failed_steps, ["open the sources screen"]);

    const failedStep = moved.steps[1];
    assert.equal(failedStep.status, "failed");
    assert.equal(failedStep.visual.status, "differs");
    assert.ok(failedStep.visual.difference_ratio > moved.visual.difference_threshold);
    assert.notEqual(failedStep.visual.diff_image, null);

    const differencePath = path.join(root, "moved", "differences", path.basename(failedStep.visual.diff_image));
    const differenceBytes = await readFile(differencePath);
    assert.ok(redPixels(differenceBytes) > 0, "the difference picture has no highlighted pixels");

    for (const step of [moved.steps[0], moved.steps[2], moved.steps[3]]) {
      assert.equal(step.status, "passed", `${step.name} failed`);
      assert.equal(step.visual.status, "same");
    }

    // Result 4: the failing run did not touch the approved references either.
    assert.deepEqual(await hashTree(referenceDir), referencesBefore);
  });
});

test("replacing the references after the move names the replaced reference, and the next run passes", async (t) => {
  const root = await testRoot(t, "update");
  const referenceDir = path.join(root, "references");
  await withStubStand(async (stand) => {
    await runStubScenario({
      stand,
      credentials: CREDENTIALS,
      reportDir: path.join(root, "update"),
      referenceDir,
      visualMode: "update",
    });
    await runStubScenario({
      stand,
      credentials: CREDENTIALS,
      reportDir: path.join(root, "moved"),
      referenceDir,
      visualMode: "enforce",
      move: true,
    });

    const replacement = await runStubScenario({
      stand,
      credentials: CREDENTIALS,
      reportDir: path.join(root, "approve"),
      referenceDir,
      visualMode: "update",
      move: true,
    });
    assert.equal(replacement.passed, true, JSON.stringify(replacement.failed_steps));
    assert.equal(replacement.visual.references_changed_count, 1);
    const replaced = replacement.visual.references_updated.filter((update) => update.change === "replaced");
    assert.equal(replaced.length, 1);
    assert.equal(replaced[0].step, "open the sources screen");
    assert.match(replaced[0].reference, /02-open-the-sources-screen\.png$/);
    assert.ok(replaced[0].difference_ratio > 0);
    // The other three references were already equal to this run's screens.
    assert.equal(replacement.visual.references_unchanged_count, 3);

    const final = await runStubScenario({
      stand,
      credentials: CREDENTIALS,
      reportDir: path.join(root, "final"),
      referenceDir,
      visualMode: "enforce",
      move: true,
    });
    assert.equal(final.passed, true, JSON.stringify(final.failed_steps));
    assert.equal(final.visual.differing_step_count, 0);
  });
});

test("the read-only stand mode reports a difference without failing a step", async (t) => {
  const root = await testRoot(t, "stand");
  const referenceDir = path.join(root, "references");
  await withStubStand(async (stand) => {
    await runStubScenario({
      stand,
      credentials: CREDENTIALS,
      reportDir: path.join(root, "update"),
      referenceDir,
      visualMode: "update",
    });

    const standRun = await runStubScenario({
      stand,
      credentials: CREDENTIALS,
      reportDir: path.join(root, "stand"),
      referenceDir,
      visualMode: "report",
      move: true,
    });
    assert.equal(standRun.passed, true, JSON.stringify(standRun.failed_steps));
    assert.equal(standRun.failed_step_count, 0);
    const step = standRun.steps[1];
    assert.equal(step.status, "passed");
    assert.equal(step.visual.status, "differs");
    assert.ok(step.visual.difference_ratio > standRun.visual.difference_threshold);
    assert.notEqual(step.visual.diff_image, null);
    assert.equal(standRun.visual.differing_step_count, 1);
    assert.equal(standRun.visual.failed_step_count, 0);
  });
});
