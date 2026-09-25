// Card U-3, return 1: the wall-clock reading on a screen is not a screen
// change.
//
// The approved references are compared pixel by pixel with a fresh screenshot,
// and the local synthetic stand stamps its data with the moment it is built.
// The date part of those stamps therefore rolls over at midnight, so a run on
// the day after the references were approved used to fail screens that had not
// changed at all: the reference showed "Sep 25", the fresh screen "Sep 26".
//
// Before a screenshot the walkthrough replaces every wall-clock reading the
// product has rendered into the page with one fixed reading. The product has
// exactly two shapes of such a reading:
//   - the "Sep 25, 11:58 PM" shape of its one date formatter (formatTime);
//   - a raw ISO-8601 timestamp ("2026-09-25T21:58:00Z"), which the evidence
//     panel prints exactly as the server stored it.
// Both become the same constant, so two runs of the same code on two different
// days render the same picture. Nothing else is touched: the labels and the
// values around the reading stay, and a date that is content rather than a
// clock reading (the synthetic contract date "2025-01-15", which has no time)
// is left alone. A moved control, a vanished panel or a changed label is still
// a difference.
//
// The replacement happens after the step's action and immediately before the
// screenshot, so a step still reads the real text while it runs.

// The two constants every clock reading becomes. They are deliberately obvious
// placeholders: a person looking at a reference picture can see that the value
// was pinned for the comparison, not read from the product.
export const CLOCK_TEXT_PLACEHOLDER = "Jan 01, 00:00 AM";
export const CLOCK_TIMESTAMP_PLACEHOLDER = "1970-01-01T00:00:00Z";

// FORMATTED_CLOCK_PATTERN is what `formatTime` in web/src/main.tsx emits:
// `toLocaleString("en-US", { day: "2-digit", month: "short", hour: "2-digit",
// minute: "2-digit" })` — for example "Sep 25, 11:58 PM". en-US prints the
// hour on a 12-hour clock, so the meridiem is part of the reading and is pinned
// with it.
export const FORMATTED_CLOCK_PATTERN =
  "\\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) \\d{2}, \\d{2}:\\d{2}(?:\\s?[AP]M)?\\b";

// ISO_CLOCK_PATTERN is a timestamp that carries a time of day. A date without a
// time (a contract's "2025-01-15") is data, not a clock reading, and stays.
export const ISO_CLOCK_PATTERN =
  "\\b\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}(?::\\d{2})?(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?\\b";

// normaliseClockText is the pure rule: every formatted clock reading and every
// full timestamp in a string becomes the fixed placeholder. It is idempotent,
// so normalising an already normalised screen changes nothing.
export function normaliseClockText(text) {
  return String(text)
    .replace(new RegExp(FORMATTED_CLOCK_PATTERN, "g"), CLOCK_TEXT_PLACEHOLDER)
    .replace(new RegExp(ISO_CLOCK_PATTERN, "g"), CLOCK_TIMESTAMP_PLACEHOLDER);
}

// stabiliseClockText rewrites the clock readings in the live page's text nodes.
// It never touches a script, a style, a form field or `contenteditable`, so it
// cannot change what the product does; it only changes what the next screenshot
// shows. A re-render between this call and the screenshot could restore the
// real reading, which is why the walkthrough calls it immediately before
// `page.screenshot`.
export async function stabiliseClockText(page) {
  await page.evaluate(
    ({ formatted, iso, formattedPlaceholder, timestampPlaceholder }) => {
      const patterns = [
        [new RegExp(formatted, "g"), formattedPlaceholder],
        [new RegExp(iso, "g"), timestampPlaceholder],
      ];
      const skip = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "TEXTAREA", "INPUT"]);
      const walker = document.createTreeWalker(document.body ?? document.documentElement, NodeFilter.SHOW_TEXT);
      const nodes = [];
      while (walker.nextNode()) nodes.push(walker.currentNode);
      for (const node of nodes) {
        const parent = node.parentElement;
        if (parent === null || skip.has(parent.tagName) || parent.isContentEditable) continue;
        const value = node.nodeValue;
        if (typeof value !== "string" || value === "") continue;
        let replaced = value;
        for (const [pattern, placeholder] of patterns) replaced = replaced.replace(pattern, placeholder);
        if (replaced !== value) node.nodeValue = replaced;
      }
    },
    {
      formatted: FORMATTED_CLOCK_PATTERN,
      iso: ISO_CLOCK_PATTERN,
      formattedPlaceholder: CLOCK_TEXT_PLACEHOLDER,
      timestampPlaceholder: CLOCK_TIMESTAMP_PLACEHOLDER,
    },
  );
}
