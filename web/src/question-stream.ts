/** The transport exposes only these content-free action labels. */
export type QuestionActionLabel =
  | "model"
  | "document_search"
  | "document_read"
  | "live_data"
  | "trusted_comparison"
  | "other_tool";

export type QuestionActionFrame = {
  type: "action";
  sequence: number;
  phase: "action_started" | "action_finished";
  label: QuestionActionLabel;
  /** Present only on action_started: a short, safe description of the request (e.g. the search query text). */
  request?: string;
  outcome?: "succeeded" | "failed";
  duration_ms?: number;
  /** Present only on action_finished: a short, safe outcome summary (e.g. a hit count). */
  detail?: string;
};

export type QuestionStreamFrame<Run> =
  | QuestionActionFrame
  | { type: "result"; result: Run }
  | { type: "error"; code: "QUESTION_FAILED"; request_id: string };

export type QuestionStreamTerminal<Run> = Exclude<QuestionStreamFrame<Run>, QuestionActionFrame>;

export function observationForGeneration(
  owner: number, currentGeneration: () => number, observe: (action: QuestionActionFrame) => void,
): (action: QuestionActionFrame) => void {
  return (action) => { if (currentGeneration() === owner) observe(action); };
}

export async function readQuestionStream<Run>(
  body: ReadableStream<Uint8Array>, onAction: (action: QuestionActionFrame) => void,
): Promise<QuestionStreamTerminal<Run>> {
  const reader = body.getReader();
  const decoder = new QuestionStreamDecoder<Run>();
  let terminal: QuestionStreamTerminal<Run> | null = null;
  for (;;) {
    const chunk = await reader.read();
    if (chunk.done) break;
    for (const frame of decoder.push(chunk.value)) {
      if (frame.type === "action") onAction(frame);
      else terminal = frame;
    }
  }
  decoder.finish();
  if (terminal === null) throw new Error("Missing terminal question frame");
  return terminal;
}

const actionLabels = new Set<QuestionActionLabel>([
  "model", "document_search", "document_read", "live_data", "trusted_comparison", "other_tool",
]);
const maxLineBytes = 16 * 1024 * 1024;
const maxChunkBytes = 32 * 1024 * 1024;
const maxActionFrames = 4096;
/** Mirrors the server's question.ActionTextMaxRunes: the client re-checks the same bound rather than trusting it. */
const maxActionTextRunes = 180;

// Over-long text is clamped, not refused: a refused frame ends the whole
// stream, and a step label must never cost the user the answer.
function clampActionText(value: string): string {
  const runes = Array.from(value);
  return runes.length <= maxActionTextRunes ? value : runes.slice(0, maxActionTextRunes - 1).join("") + "…";
}

function object(value: unknown): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Invalid question stream frame");
  }
  return value as Record<string, unknown>;
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[]): void {
  if (Object.keys(value).some((key) => !allowed.includes(key))) {
    throw new Error("Unexpected question stream field");
  }
}

/** Incremental, strict NDJSON decoder. It never treats an incomplete stream as an answer. */
export class QuestionStreamDecoder<Run> {
  private readonly decoder = new TextDecoder("utf-8", { fatal: true });
  private readonly seenSequences = new Set<number>();
  private buffer = "";
  private terminal = false;

  push(bytes: Uint8Array): QuestionStreamFrame<Run>[] {
    if (this.terminal) throw new Error("Question stream already finished");
    if (bytes.byteLength > maxChunkBytes) throw new Error("Question stream chunk too large");
    this.buffer += this.decoder.decode(bytes, { stream: true });
    const frames: QuestionStreamFrame<Run>[] = [];
    for (;;) {
      const newline = this.buffer.indexOf("\n");
      if (newline < 0) break;
      const line = this.buffer.slice(0, newline).replace(/\r$/, "");
      this.buffer = this.buffer.slice(newline + 1);
      if (new TextEncoder().encode(line).byteLength > maxLineBytes) {
        throw new Error("Question stream frame too large");
      }
      frames.push(this.parse(line));
    }
    if (new TextEncoder().encode(this.buffer).byteLength > maxLineBytes) {
      throw new Error("Question stream frame too large");
    }
    if (this.terminal && this.buffer.length > 0) {
      throw new Error("Data after terminal question frame");
    }
    return frames;
  }

  finish(): void {
    if (this.decoder.decode().length > 0 || this.buffer.length > 0 || !this.terminal) {
      throw new Error("Incomplete question stream");
    }
  }

  private parse(line: string): QuestionStreamFrame<Run> {
    if (this.terminal) throw new Error("Data after terminal question frame");
    let decoded: unknown;
    try {
      decoded = JSON.parse(line);
    } catch {
      throw new Error("Malformed question stream frame");
    }
    const frame = object(decoded);
    if (frame.type === "action") {
      onlyKeys(frame, ["type", "sequence", "phase", "label", "request", "outcome", "duration_ms", "detail"]);
      if (!Number.isSafeInteger(frame.sequence) || (frame.sequence as number) < 1 ||
          this.seenSequences.has(frame.sequence as number) || this.seenSequences.size >= maxActionFrames ||
          (frame.phase !== "action_started" && frame.phase !== "action_finished") ||
          !actionLabels.has(frame.label as QuestionActionLabel)) {
        throw new Error("Invalid question action frame");
      }
      if (frame.request !== undefined && typeof frame.request !== "string") {
        throw new Error("Invalid question action request text");
      }
      if (frame.detail !== undefined && typeof frame.detail !== "string") {
        throw new Error("Invalid question action detail text");
      }
      if (typeof frame.request === "string") frame.request = clampActionText(frame.request);
      if (typeof frame.detail === "string") frame.detail = clampActionText(frame.detail);
      // Request describes what was asked (known only once a call starts);
      // detail describes what came back (known only once it finishes). Each
      // is valid on exactly one phase, mirroring outcome/duration_ms below.
      if (frame.phase === "action_started" && (frame.outcome !== undefined || frame.duration_ms !== undefined || frame.detail !== undefined)) {
        throw new Error("Invalid started action frame");
      }
      if (frame.phase === "action_finished" &&
          (frame.request !== undefined ||
           (frame.outcome !== "succeeded" && frame.outcome !== "failed") ||
           (frame.duration_ms !== undefined &&
            (!Number.isSafeInteger(frame.duration_ms) || (frame.duration_ms as number) < 0)))) {
        throw new Error("Invalid finished action frame");
      }
      this.seenSequences.add(frame.sequence as number);
      return frame as QuestionActionFrame;
    }
    if (frame.type === "result") {
      onlyKeys(frame, ["type", "result"]);
      const run = object(frame.result);
      if (typeof run.question_run_id !== "string" || run.question_run_id.length === 0 ||
          typeof run.workspace_id !== "string" || run.workspace_id.length === 0 ||
          typeof run.status !== "string" || run.status.length === 0) {
        throw new Error("Invalid question result frame");
      }
      this.terminal = true;
      return { type: "result", result: frame.result as Run };
    }
    if (frame.type === "error") {
      onlyKeys(frame, ["type", "code", "request_id"]);
      if (frame.code !== "QUESTION_FAILED" || typeof frame.request_id !== "string") {
        throw new Error("Invalid question error frame");
      }
      this.terminal = true;
      return { type: "error", code: "QUESTION_FAILED", request_id: frame.request_id };
    }
    throw new Error("Unknown question stream frame");
  }
}
