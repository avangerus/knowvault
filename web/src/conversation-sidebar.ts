// Card W-6: the chat screen's conversation list can be put away. The owner
// asked for the list to collapse because the chat screen carries too much, and
// for the choice to survive a page reload, so it must live in the browser's
// own storage rather than in component state alone.
//
// Every access here is total: a browser that has no local storage (the
// server-side static render), refuses reads, or refuses writes must still get a
// working chat screen. A missing or unreadable value reads as the default, the
// list expanded, exactly as the screen rendered before this card.

// CONVERSATIONS_COLLAPSED_STORAGE_KEY is the one stable key the choice is kept
// under. It is per person, not per workspace: the owner asked about the screen,
// not about one workspace's topics.
export const CONVERSATIONS_COLLAPSED_STORAGE_KEY = "knowvault.conversations.collapsed";

// ConversationSidebarStorage is the slice of the Storage interface this module
// needs, so a test can hand it an in-memory double.
export type ConversationSidebarStorage = {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
};

// conversationSidebarStorage returns the browser's local storage, or null when
// the environment has none or denies access to it. The lookup itself is
// guarded: reading the property can throw in a locked-down context.
export function conversationSidebarStorage(): ConversationSidebarStorage | null {
  try {
    const storage = (globalThis as { localStorage?: ConversationSidebarStorage }).localStorage;
    return storage ?? null;
  } catch {
    return null;
  }
}

// readConversationsCollapsed reads the stored choice. Only the exact stored
// value "collapsed" collapses the list; a missing value, an unknown value or a
// storage that throws reads as the default expanded list.
export function readConversationsCollapsed(storage: ConversationSidebarStorage | null): boolean {
  if (storage === null) return false;
  try {
    return storage.getItem(CONVERSATIONS_COLLAPSED_STORAGE_KEY) === "collapsed";
  } catch {
    return false;
  }
}

// writeConversationsCollapsed remembers the choice. A refused write is ignored:
// the screen still collapses for this visit, the preference is just not kept.
export function writeConversationsCollapsed(storage: ConversationSidebarStorage | null, collapsed: boolean): void {
  if (storage === null) return;
  try {
    storage.setItem(CONVERSATIONS_COLLAPSED_STORAGE_KEY, collapsed ? "collapsed" : "expanded");
  } catch {
    // Private mode or a full quota must never break the chat screen.
  }
}

// askLayoutClass is the class list of the chat screen's grid. Collapsed drops
// the conversation column, so the chat and the answer take its width; the
// fullscreen evidence variant keeps its own column set.
export function askLayoutClass(fullscreen: boolean, collapsed: boolean): string {
  return `ask-layout${fullscreen ? " ask-layout-full" : ""}${collapsed ? " ask-layout-collapsed" : ""}`;
}
