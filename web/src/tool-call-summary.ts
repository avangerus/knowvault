type ToolCallSummaryInput = {
  name: string;
  arguments?: unknown;
  outcome: string;
  result: { structured?: unknown };
};

function fields(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown> : null;
}

function bounded(value: string): string {
  const characters = Array.from(value.trim());
  return characters.length > 180 ? `${characters.slice(0, 180).join("")}…` : value.trim();
}

// The completed run has already passed the server's full trace disclosure gate.
// Select a short, readable projection instead of putting raw tool payloads in the answer.
export function toolCallSummary(call: ToolCallSummaryInput): { request: string | null; result: string } {
  const args = fields(call.arguments);
  const request = args && ["question", "query", "address", "fragment_id"]
    .map((key) => args[key]).find((value): value is string => typeof value === "string" && value.trim().length > 0);
  if (call.outcome !== "SUCCEEDED") return { request: request ? bounded(request) : null, result: "No result" };
  const result = fields(call.result.structured);
  const window = fields(result?.read_window);
  const rowCount = window?.returned_rows ?? result?.row_count;
  if (call.name === "knowvault_ask_live_data" && Number.isSafeInteger(rowCount) && (rowCount as number) >= 0) {
    return { request: request ? bounded(request) : null, result: `${rowCount} ${rowCount === 1 ? "row" : "rows"} returned` };
  }
  const matches = result?.results;
  if (call.name === "knowvault_search" && Array.isArray(matches)) {
    return { request: request ? bounded(request) : null, result: `${matches.length} ${matches.length === 1 ? "match" : "matches"} on this page` };
  }
  return { request: request ? bounded(request) : null, result: "Completed" };
}
