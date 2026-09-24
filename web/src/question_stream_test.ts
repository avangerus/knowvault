import { observationForGeneration, QuestionStreamDecoder, readQuestionStream } from "./question-stream";

function check(condition: boolean, message: string) {
  if (!condition) throw new Error(message);
}

function refuses(run: () => unknown, message: string) {
  let denied = false;
  try { run(); } catch { denied = true; }
  check(denied, message);
}

const encode = (text: string) => new TextEncoder().encode(text);
const action = (sequence: number, label = "document_search") =>
  JSON.stringify({ type: "action", sequence, phase: "action_started", label }) + "\n";
const result = JSON.stringify({
  type: "result", result: { question_run_id: "qr_1", workspace_id: "ws_1", status: "COMPLETED", answer: "Готово" },
}) + "\n";

const decoder = new QuestionStreamDecoder<{ question_run_id: string; answer: string }>();
const payload = encode(action(2) + action(1, "document_read") + result);
const utf8Break = payload.indexOf(0xd0);
check(decoder.push(payload.slice(0, 8)).length === 0, "partial line stays pending");
const first = decoder.push(payload.slice(8, utf8Break + 1));
check(first.length === 2 && first[0].type === "action" && first[0].sequence === 2 &&
  first[1].type === "action" && first[1].sequence === 1, "out-of-order unique actions remain tagged for UI sorting");
const last = decoder.push(payload.slice(utf8Break + 1));
check(last.length === 1 && last[0].type === "result" && last[0].result.answer === "Готово",
  "split UTF-8 terminal payload survives chunking");
decoder.finish();
refuses(() => decoder.push(encode(action(3))), "action after terminal is refused");

const windowsLines = new QuestionStreamDecoder<unknown>();
check(windowsLines.push(encode(action(1).replace("\n", "\r\n") +
  JSON.stringify({ type: "error", code: "QUESTION_FAILED", request_id: "req_1" }) + "\r\n")).length === 2,
"CRLF and multiple frames in one chunk are supported");
windowsLines.finish();

const duplicateSequence = new QuestionStreamDecoder<unknown>();
refuses(() => duplicateSequence.push(encode(action(1) + action(1))), "duplicate action sequence is refused");
const duplicateTerminal = new QuestionStreamDecoder<unknown>();
refuses(() => duplicateTerminal.push(encode(result + result)), "duplicate terminal is refused");
refuses(() => new QuestionStreamDecoder<unknown>().push(encode("{bad}\n")), "malformed JSON is refused");
refuses(() => new QuestionStreamDecoder<unknown>().push(encode(action(1, "secret_argument"))),
  "unallowlisted action label is refused");
refuses(() => new QuestionStreamDecoder<unknown>().push(encode(JSON.stringify({
  type: "action", sequence: 1, phase: "action_finished", label: "model", outcome: "succeeded", duration_ms: -1,
}) + "\n")), "negative duration is refused");
refuses(() => new QuestionStreamDecoder<unknown>().push(encode(JSON.stringify({
  type: "error", code: "SERVER_EXCEPTION", request_id: "req_1",
}) + "\n")), "unknown terminal code is refused");
refuses(() => new QuestionStreamDecoder<unknown>().push(encode(JSON.stringify({
  type: "action", sequence: 1, phase: "action_started", label: "model", secret: "leak",
}) + "\n")), "extra action fields are refused");

// R1/R2: the started frame's request and the finished frame's detail carry
// the live step content (the search query text, a hit count, and so on).
// They decode as ordinary bounded strings and never on the wrong phase.
const withContent = new QuestionStreamDecoder<unknown>();
const started = withContent.push(encode(JSON.stringify({
  type: "action", sequence: 1, phase: "action_started", label: "document_search", request: "termination clause",
}) + "\n"))[0];
check(started.type === "action" && started.phase === "action_started" && started.request === "termination clause",
  "a started frame's request decodes as visible step content");
const finished = withContent.push(encode(JSON.stringify({
  type: "action", sequence: 2, phase: "action_finished", label: "document_search", outcome: "succeeded", detail: "3 hits",
}) + "\n"))[0];
check(finished.type === "action" && finished.phase === "action_finished" && finished.detail === "3 hits",
  "a finished frame's detail decodes as visible step content");
refuses(() => new QuestionStreamDecoder<unknown>().push(encode(JSON.stringify({
  type: "action", sequence: 1, phase: "action_finished", label: "document_search", outcome: "succeeded", request: "leaked after the fact",
}) + "\n")), "a request on a finished frame is refused");
refuses(() => new QuestionStreamDecoder<unknown>().push(encode(JSON.stringify({
  type: "action", sequence: 1, phase: "action_started", label: "document_search", detail: "leaked before the call ran",
}) + "\n")), "a detail on a started frame is refused");
const longRequest = new QuestionStreamDecoder<unknown>().push(encode(JSON.stringify({
  type: "action", sequence: 1, phase: "action_started", label: "document_search", request: "я".repeat(181),
}) + "\n"))[0];
check(longRequest.type === "action" && Array.from(longRequest.request ?? "").length === 180 && (longRequest.request ?? "").endsWith("…"),
  "a request past the bound is clamped, not refused");
const longDetail = new QuestionStreamDecoder<unknown>().push(encode(JSON.stringify({
  type: "action", sequence: 1, phase: "action_finished", label: "document_search", outcome: "succeeded", detail: "я".repeat(181),
}) + "\n"))[0];
check(longDetail.type === "action" && Array.from(longDetail.detail ?? "").length === 180 && (longDetail.detail ?? "").endsWith("…"),
  "a detail past the bound is clamped, not refused");
const tooManyActions = new QuestionStreamDecoder<unknown>();
tooManyActions.push(encode(Array.from({ length: 4096 }, (_, index) => action(index + 1)).join("")));
refuses(() => tooManyActions.push(encode(action(4097))), "unbounded action history is refused");

const incomplete = new QuestionStreamDecoder<unknown>();
incomplete.push(encode(action(1)));
refuses(() => incomplete.finish(), "missing terminal is refused");
const partialTerminal = new QuestionStreamDecoder<unknown>();
partialTerminal.push(encode(result.slice(0, -1)));
refuses(() => partialTerminal.finish(), "truncated terminal line is refused");
refuses(() => new QuestionStreamDecoder<unknown>().push(Uint8Array.from([0xff, 10])),
  "malformed UTF-8 is refused");

let generation = 1;
const observed: number[] = [];
const scoped = observationForGeneration(1, () => generation, (event) => observed.push(event.sequence));
scoped({ type: "action", sequence: 1, phase: "action_started", label: "model" });
generation = 2;
scoped({ type: "action", sequence: 2, phase: "action_finished", label: "model", outcome: "succeeded" });
check(JSON.stringify(observed) === "[1]", "workspace switch drops late progress frames");

function stream(parts: string[]): ReadableStream<Uint8Array> {
  return new ReadableStream({ start(controller) {
    for (const part of parts) controller.enqueue(encode(part));
    controller.close();
  } });
}

async function verifyReader() {
  const actions: number[] = [];
  const terminal = await readQuestionStream<{ answer: string }>(stream([action(1), result]),
    (event) => actions.push(event.sequence));
  check(terminal.type === "result" && terminal.result.answer === "Готово" && JSON.stringify(actions) === "[1]",
    "response reader preserves action and terminal result");
  let truncated = false;
  try { await readQuestionStream(stream([action(1)]), () => {}); } catch { truncated = true; }
  check(truncated, "truncated network stream never becomes a successful answer");
}

// R3: aborting the underlying HTTP request (Stop, switching conversations,
// leaving the conversation — see apiPostQuestionStream/abortActiveQuestion in
// main.tsx) makes fetch's response body stream error. The reader must
// propagate that as a rejection rather than hang or resolve as if an answer
// had arrived, so the composer can never look like it is still waiting on
// (or worse, silently keep) a request the browser already gave up on.
async function verifyAbortedStreamNeverBecomesAnAnswer() {
  const controller = new AbortController();
  let cancelled = false;
  const aborted = new ReadableStream<Uint8Array>({
    start(streamController) {
      controller.signal.addEventListener("abort", () => {
        streamController.error(new DOMException("The user aborted a request.", "AbortError"));
      });
    },
    cancel() { cancelled = true; },
  });
  const pending = readQuestionStream<{ answer: string }>(aborted, () => {});
  controller.abort();
  let rejected: unknown;
  try { await pending; } catch (error) { rejected = error; }
  check(rejected instanceof Error && rejected.name === "AbortError", "an aborted stream rejects the pending answer instead of hanging");
  check(!cancelled, "readQuestionStream reads through reader.read(), not stream.cancel(), so it observes the abort error directly");
}

Promise.all([verifyReader(), verifyAbortedStreamNeverBecomesAnAnswer()]).then(() => console.log("question stream decoder: ok"));
