// Card U-2: the two screen scenarios the walkthrough can drive.
//
// `local` is the card U-1 scenario against the local synthetic stand: it
// confirms the synthetic tables and saves a model-context change, because that
// stand exists to be changed.
//
// `read-only` is the card U-2 scenario against an owner-facing stand: it walks
// the same screens but only reads them, asks the card's three questions and
// opens the evidence of one answer. A last step fails the run if any request
// other than asking a question or signing in was made, so the promise "it
// changes nothing in the workspace" is checked, not assumed.
//
// Everything here drives the real product interface through selectors and waits
// that do not use `page.waitForFunction`: the product's Content-Security-Policy
// forbids the string eval that waitForFunction relies on.

import { signIn } from "./signin.mjs";

// READ_ONLY_QUESTIONS is the card's question set for the stand screen check.
export const READ_ONLY_QUESTIONS = [
  "что ты знаешь?",
  "какие есть источники?",
  "что в базе данных можем посмотреть?",
];

// READ_ONLY_ALLOWED_WRITES is the only traffic a read-only run may generate:
// asking a question, and the sign-in exchange with the stand or its identity
// provider. Confirming a table, saving the model context or registering a
// source does not match any of these and therefore fails the run.
const READ_ONLY_ALLOWED_WRITES = [
  /\/questions(\?|$)/,
  /\/auth\//,
  /\/idp\//,
  /login-actions\//,
];

// disallowedReadOnlyWrites returns the mutating requests a read-only run may
// not make. It is exported so the rule itself is covered by a test.
export function disallowedReadOnlyWrites(writes) {
  return writes.filter((write) => !READ_ONLY_ALLOWED_WRITES.some((pattern) => pattern.test(write.path)));
}

async function waitForHeading(page, name) {
  await page.getByRole("heading", { name, exact: true }).first().waitFor({ state: "visible", timeout: 30_000 });
}

// BUILD_REVISION_SELECTOR is the quiet revision mark the application header
// shows on every screen (card W-4).
const BUILD_REVISION_SELECTOR = ".build-revision";

// waitForBuildRevision proves the interface names the running server's
// revision. When the stand's build is known, exactly its short form is
// accepted; otherwise the mark must still be present as a neutral mark or a
// revision, so an older stand cannot pass by showing nothing.
async function waitForBuildRevision(page, revision, timeoutMs = 30_000) {
  const expected = String(revision ?? "").trim().slice(0, 7);
  const mark = page.locator(BUILD_REVISION_SELECTOR);
  if (expected === "") {
    await mark.filter({ hasText: /—|[0-9a-fA-F]{4,40}/ }).first().waitFor({ state: "visible", timeout: timeoutMs });
    return ((await mark.first().textContent()) ?? "").trim();
  }
  await mark.filter({ hasText: expected }).first().waitFor({ state: "visible", timeout: timeoutMs });
  const shown = ((await mark.first().textContent()) ?? "").trim();
  if (shown !== expected) {
    throw new Error(`the interface shows revision ${JSON.stringify(shown)}, want ${JSON.stringify(expected)}`);
  }
  return shown;
}

// waitForPageSettled waits out the screen's own "loading" note, then waits for
// one of the shapes a loaded screen can have.
async function waitForPageSettled(page, loadedSelector) {
  await page
    .locator('p.evidence-state:has-text("Loading")')
    .waitFor({ state: "detached", timeout: 5_000 })
    .catch(() => {});
  await page.locator(loadedSelector).first().waitFor({ state: "visible", timeout: 30_000 });
}

// waitForAnswer polls the turn cards until the answer to `question` has arrived.
// It cannot use page.waitForFunction: the product's CSP blocks the eval that
// call needs.
async function waitForAnswer(page, question, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  for (;;) {
    const turns = page.locator("article.turn").filter({ hasText: question });
    if ((await turns.count()) > 0) {
      const turn = turns.last();
      const state = await turn
        .evaluate((node) => {
          const body = node.querySelector(".answer-body");
          const warning = node.querySelector(".msg-warning");
          const clone = (body ?? node).cloneNode(true);
          for (const element of clone.querySelectorAll("button, .badge, time, script, style")) element.remove();
          return {
            pending: node.classList.contains("turn-pending"),
            text: body !== null ? (clone.textContent ?? "").replace(/\s+/g, " ").trim() : "",
            warning: warning !== null ? (warning.textContent ?? "").replace(/\s+/g, " ").trim() : "",
          };
        })
        .catch((error) => {
          lastError = error;
          return null;
        });
      if (state !== null && !state.pending) {
        if (state.text !== "") return { text: state.text, turn };
        if (state.warning !== "") return { text: state.warning, turn };
      }
    }
    if (Date.now() > deadline) {
      const detail = lastError !== null ? ` (${lastError.message})` : "";
      throw new Error(`no answer to ${JSON.stringify(question)} within ${Math.round(timeoutMs / 1000)} s${detail}`);
    }
    await page.waitForTimeout(250);
  }
}

async function askQuestion(page, walk, question, timeoutMs = 240_000) {
  const composer = page.locator("textarea#ask-question");
  await composer.waitFor({ state: "visible", timeout: 30_000 });
  await composer.fill(question);
  await page.locator('button[aria-label="Ask"]').click();
  const answer = await waitForAnswer(page, question, timeoutMs);
  walk.answer(question, answer.text);
  return answer;
}

// openEvidence clicks a citation control of one answer and waits for the
// evidence panel to show that it observed the source.
async function openEvidence(page, turn, timeoutMs = 30_000) {
  const control = turn.locator("button.fn, button.basis").first();
  await control.waitFor({ state: "visible", timeout: timeoutMs });
  await control.click();
  await page
    .locator('aside[aria-label="Answer evidence"] .evi-h')
    .filter({ hasText: "observed" })
    .first()
    .waitFor({ state: "visible", timeout: timeoutMs });
}

// chatColumnWidth is the rendered width of the chat column in CSS pixels. Card
// W-6's width result — the collapsed chat is wider than the expanded one — is
// measured here, at the walkthrough's desktop viewport, on the real screen.
async function chatColumnWidth(page) {
  const box = await page.locator("section.talk").boundingBox();
  if (box === null) throw new Error("the chat column is not on screen");
  return box.width;
}

// conversationToggle is the chat screen's one conversation-list control, found
// by the label it shows in the wanted state: "Hide conversations" while the
// list is open, "Show conversations" while it is put away.
function conversationToggle(page, label) {
  return page.locator("button.conversations-toggle").filter({ hasText: label });
}

// runLocalScenario is the card U-1 walkthrough, unchanged in what it does.
export async function runLocalScenario(page, walk, options = {}) {
  const question = options.question ?? "что ты знаешь?";

  await walk.step("the interface shows the running server revision", async () => {
    await page.goto(`${options.baseURL}/`, { waitUntil: "domcontentloaded", timeout: 60_000 });
    const shown = await waitForBuildRevision(page, options.revision);
    console.log(`walkthrough revision mark: ${JSON.stringify(shown)}`);
  });

  await walk.step("sign in as the test user", async () => {
    await signIn(page, { baseURL: options.baseURL });
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
    const { turn } = await askQuestion(page, walk, question);
    // The answer is rendered as a turn that carries at least one citation
    // control: a footnote mark woven into the text, or a basis row when the
    // server returned a citation the answer text did not reference.
    await turn.locator("button.fn, button.basis").first().waitFor({ state: "visible", timeout: 30_000 });
    // Card W-5: the chat screen carries exactly one control for the
    // workspace's sources. Every source control belongs to the Ask surface,
    // whose header control and the composer control used to render the same
    // summary twice; the screenshot of this step shows the one that remains.
    const sourceControls = page.locator(".ask-surface .rely-summary");
    const sourceControlCount = await sourceControls.count();
    if (sourceControlCount !== 1) {
      throw new Error(`the chat screen shows ${sourceControlCount} sources controls, want exactly 1`);
    }
    await sourceControls.first().waitFor({ state: "visible", timeout: 30_000 });
  });

  // Card W-6: the conversation list can be put away with one action and brought
  // back with one action, and the chat and its answer take the freed width.
  // The two steps are deliberately separate so the report carries one
  // screenshot of each state after its own action.
  let collapsedChatWidth = 0;
  await walk.step("collapse the conversation list", async () => {
    const list = page.locator('section[aria-label="Conversations"]');
    await list.waitFor({ state: "visible", timeout: 30_000 });
    const expandedChatWidth = await chatColumnWidth(page);
    await conversationToggle(page, "Hide conversations").click();
    await list.waitFor({ state: "detached", timeout: 30_000 });
    await conversationToggle(page, "Show conversations").waitFor({ state: "visible", timeout: 30_000 });
    collapsedChatWidth = await chatColumnWidth(page);
    if (!(collapsedChatWidth > expandedChatWidth)) {
      throw new Error(
        `the collapsed chat column is ${collapsedChatWidth} px wide, the expanded one ${expandedChatWidth} px`,
      );
    }
    console.log(`walkthrough chat column px: expanded=${expandedChatWidth} collapsed=${collapsedChatWidth}`);
  });

  await walk.step("expand the conversation list again", async () => {
    await conversationToggle(page, "Show conversations").click();
    const list = page.locator('section[aria-label="Conversations"]');
    await list.waitFor({ state: "visible", timeout: 30_000 });
    await conversationToggle(page, "Hide conversations").waitFor({ state: "visible", timeout: 30_000 });
    const expandedChatWidth = await chatColumnWidth(page);
    if (!(collapsedChatWidth > expandedChatWidth)) {
      throw new Error(
        `the collapsed chat column is ${collapsedChatWidth} px wide, the expanded one ${expandedChatWidth} px`,
      );
    }
    console.log(`walkthrough chat column px: collapsed=${collapsedChatWidth} expanded-again=${expandedChatWidth}`);
  });

  await walk.step("open the evidence of that answer", async () => {
    const turn = page.locator("article.turn").last();
    await openEvidence(page, turn);
  });
}

// runReadOnlyScenario walks an owner-facing stand without changing it.
export async function runReadOnlyScenario(page, walk, options = {}) {
  const credentials = options.credentials ?? null;
  const questions = options.questions ?? READ_ONLY_QUESTIONS;

  await walk.step("sign in as the test user", async () => {
    await signIn(page, { baseURL: options.baseURL, credentials });
  });

  await walk.step("open Sources (read only)", async () => {
    await page.locator('nav.rail button[aria-label="Sources"]').click();
    await waitForHeading(page, "Sources");
    // The screen is loaded when the source list, the empty state or the draft
    // list is on screen. The confirmation controls are deliberately left
    // untouched.
    await waitForPageSettled(page, "ul.source-rows, .empty-runs, .source-drafts");
  });

  await walk.step("open the model settings (read only)", async () => {
    await page.locator('nav.rail button[aria-label="Settings"]').click();
    await waitForHeading(page, "Workspace model context");
    const description = page.locator("section#model-context-panel-description textarea");
    await description.waitFor({ state: "visible", timeout: 30_000 });
    // Read the current value so the screen is proven loaded; nothing is typed
    // and the save control is never touched.
    await description.inputValue();
  });

  let firstTurn = null;
  for (const question of questions) {
    await walk.step(`ask ${question} and get an answer`, async () => {
      const composer = page.locator("textarea#ask-question");
      if (!(await composer.isVisible().catch(() => false))) {
        await page.locator('nav.rail button[aria-label="Search"]').click();
      }
      const answer = await askQuestion(page, walk, question);
      firstTurn = firstTurn ?? answer.turn;
    });
  }

  await walk.step("open the evidence of one answer", async () => {
    if (firstTurn === null) {
      throw new Error("no answered question to open evidence for");
    }
    await openEvidence(page, firstTurn);
  });

  await walk.step("confirm the read-only run changed nothing", async () => {
    const disallowed = disallowedReadOnlyWrites(walk.observedWrites());
    if (disallowed.length > 0) {
      throw new Error(
        `workspace-changing requests: ${disallowed.map((write) => `${write.method} ${write.path}`).join(", ")}`,
      );
    }
  });
}

export const SCENARIOS = {
  local: runLocalScenario,
  "read-only": runReadOnlyScenario,
};
