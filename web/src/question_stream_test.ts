import { QuestionStreamDecoder } from "./question-stream";

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

console.log("question stream decoder: ok");
