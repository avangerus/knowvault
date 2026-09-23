import { toolCallSummary } from "./tool-call-summary";

function check(condition: boolean, message: string) {
  if (!condition) throw new Error(message);
}

const search = toolCallSummary({ name: "knowvault_search", arguments: { query: "GM data dictionary" }, outcome: "SUCCEEDED", result: { structured: { results: [{}, {}], private_text: "SECRET" } } });
check(search.request === "GM data dictionary" && search.result === "2 matches on this page", "search describes only its returned page");
check(!JSON.stringify(search).includes("SECRET"), "raw result content is not projected");
const live = toolCallSummary({ name: "knowvault_ask_live_data", arguments: { question: "assigned on 10 September" }, outcome: "SUCCEEDED", result: { structured: { row_count: 1, rows: [["3888"]] } } });
check(live.request === "assigned on 10 September" && live.result === "1 row returned", "live result describes rows without exposing values");
const denied = toolCallSummary({ name: "knowvault_read", arguments: { address: "kv1:sample" }, outcome: "REFUSED", result: { structured: { text: "SECRET" } } });
check(denied.result === "No result" && !JSON.stringify(denied).includes("SECRET"), "failed action never projects its result");
console.log("tool call summary: ok");
