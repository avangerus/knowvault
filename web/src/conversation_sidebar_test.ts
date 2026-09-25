// Card W-6 web probe: the chat screen's conversation list can be put away.
//
// Before this card the list of conversations always took a 224px column of the
// chat screen, and there was no way to give that width to the chat and its
// answer. This probe renders the REAL production AskSurface from main.tsx
// through react-dom/server (no test framework, no new dependency, matching
// chat_sources_control_test.ts and search_surface_test.ts) and checks the three
// card results:
//
//   1. the collapsed screen has no conversation list and offers the control
//      that expands it; the expanded screen has the list and the control that
//      collapses it;
//   2. the collapsed screen's layout carries the class that drops the list
//      column, so the chat and the answer take the freed width;
//   3. the choice is kept in local storage, so a re-render after a reload shows
//      the list exactly as the person left it.
//
// The card's width claim itself (collapsed chat wider than expanded) is
// measured in the real browser by the local screen walkthrough.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AskSurface, type WorkspaceDataState } from "./main";
import {
  CONVERSATIONS_COLLAPSED_STORAGE_KEY,
  askLayoutClass,
  conversationSidebarStorage,
  readConversationsCollapsed,
  writeConversationsCollapsed,
  type ConversationSidebarStorage,
} from "./conversation-sidebar";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

// memoryStorage is the in-memory double of the browser's localStorage: node has
// no local storage in the static-render harness, and the probe must prove the
// screen reads and writes through the real storage interface.
type MemoryStorage = ConversationSidebarStorage & { values: Map<string, string> };

function memoryStorage(initial: Record<string, string> = {}): MemoryStorage {
  const values = new Map(Object.entries(initial));
  return {
    values,
    getItem: (key) => (values.has(key) ? values.get(key) ?? null : null),
    setItem: (key, value) => {
      values.set(key, value);
    },
  };
}

// useStorage installs one storage double as the environment's local storage for
// the synchronous static render, exactly where the real browser would offer it.
function useStorage(storage: ConversationSidebarStorage | null): void {
  (globalThis as { localStorage?: ConversationSidebarStorage }).localStorage = storage ?? undefined;
}

const snapshot = { id: "workspace-1", name: "Operations", status: "ACTIVE", revision: 1, model_profiles: [] };
const state = {
  phase: "loaded",
  snapshot: { kind: "ok", value: snapshot },
  sources: { kind: "ok", value: { sources: [], confirmation_context: {} } },
} as unknown as WorkspaceDataState;

function renderChat(): string {
  return renderToStaticMarkup(createElement(AskSurface, {
    active: true,
    onOpenEvidence: () => {},
    onOpenSources: () => {},
    requestedWorkspaceID: "workspace-1",
    state,
  }));
}

const LIST = 'aria-label="Conversations"';
// The control's own visible label is its accessible name, so the probe reads
// the same words a person does.
const COLLAPSE_CONTROL = "<span>Hide conversations</span>";
const EXPAND_CONTROL = "<span>Show conversations</span>";

// Result 1, expanded (no stored choice): the list and the control that
// collapses it.
useStorage(memoryStorage());
const expanded = renderChat();
check(expanded.includes(LIST), "the expanded chat screen shows the conversation list");
check(expanded.includes(COLLAPSE_CONTROL), "the expanded chat screen offers the control that collapses the list");
check(!expanded.includes(EXPAND_CONTROL), "the expanded screen does not offer the expand control");
check(expanded.includes('class="conversations-toggle"'), "the one conversation-list toggle is on the expanded screen");
check(expanded.includes('aria-expanded="true"'), "the collapsing control reports the list as expanded");
check(expanded.includes('class="ask-layout"'), "the expanded screen uses the full three-column layout");
check(!expanded.includes("ask-layout-collapsed"), "the expanded screen does not drop the list column");

// Result 1, collapsed (the choice was stored): no list, and the control that
// expands it.
useStorage(memoryStorage({ [CONVERSATIONS_COLLAPSED_STORAGE_KEY]: "collapsed" }));
const collapsed = renderChat();
check(!collapsed.includes(LIST), "the collapsed chat screen has no conversation list");
check(collapsed.includes(EXPAND_CONTROL), "the collapsed chat screen offers the control that expands the list");
check(!collapsed.includes(COLLAPSE_CONTROL), "the collapsed screen does not offer the collapse control");
check(collapsed.includes('class="conversations-toggle"'), "the one conversation-list toggle is on the collapsed screen");
check(collapsed.includes('aria-expanded="false"'), "the expanding control reports the list as collapsed");
check(collapsed.includes("ask-layout-collapsed"), "the collapsed screen drops the list column");
// Result 2: the chat and its answer stay on screen and take the freed width.
check(collapsed.includes('class="talk"'), "the collapsed screen keeps the chat");

// Result 3: storing the choice and rendering again — as after a reload — keeps
// the list collapsed; the expanded choice is remembered just as well.
const persisted = memoryStorage();
useStorage(persisted);
check(renderChat().includes(LIST), "without a stored choice the list starts expanded");
writeConversationsCollapsed(persisted, true);
check(readConversationsCollapsed(persisted), "the collapsed choice is stored through the same storage the screen reads");
const afterCollapsedReload = renderChat();
check(!afterCollapsedReload.includes(LIST), "after a reload the stored collapsed choice keeps the list collapsed");
check(afterCollapsedReload.includes(EXPAND_CONTROL), "after that reload the expand control is the one on screen");
writeConversationsCollapsed(persisted, false);
check(persisted.values.get(CONVERSATIONS_COLLAPSED_STORAGE_KEY) === "expanded", "the expanded choice is stored too");
check(renderChat().includes(LIST), "after a reload the stored expanded choice shows the list again");

// Result 2, layout contract: only the collapsed screen drops the column.
check(askLayoutClass(false, false) === "ask-layout", "the expanded layout is the full screen layout");
check(askLayoutClass(false, true) === "ask-layout ask-layout-collapsed", "the collapsed layout drops the list column");
check(askLayoutClass(true, true) === "ask-layout ask-layout-full ask-layout-collapsed", "fullscreen evidence keeps its variant when collapsed");

// The preference is total: a missing or refusing storage must not break the
// screen, and must read as the pre-card default (expanded).
useStorage(null);
check(conversationSidebarStorage() === null, "a missing local storage reads as none");
check(readConversationsCollapsed(null) === false, "no storage reads as expanded");
check(renderChat().includes(LIST), "the screen renders expanded without local storage");
const refusing: ConversationSidebarStorage = {
  getItem: () => {
    throw new Error("storage denied");
  },
  setItem: () => {
    throw new Error("storage denied");
  },
};
check(readConversationsCollapsed(refusing) === false, "a refusing storage reads as expanded");
writeConversationsCollapsed(refusing, true);
check(true, "a refusing storage never throws out of the choice write");

if (failures !== 0) throw new Error(`${failures} conversation-sidebar assertion(s) failed`);
console.log("conversation sidebar probe: PASS");
