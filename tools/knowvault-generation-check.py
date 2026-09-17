"""Synthetic native tool-call and result-consumption check; no company data."""
import argparse
import json
import hashlib
from pathlib import Path
import time
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--endpoint", required=True)
parser.add_argument("--model", required=True)
parser.add_argument("--profile")
args = parser.parse_args()
profile = json.loads(Path(args.profile).read_text(encoding="utf-8")) if args.profile else None
if profile:
    assert profile["model_id"] == args.model
    assert profile["endpoint"].rstrip("/") == args.endpoint.rstrip("/") + "/v1"
    assert profile["thinking_mode"] in ["disabled", "enabled"]
tool = {"type": "function", "function": {"name": "read_record", "description": "Read the synthetic project's recorded limits.",
        "parameters": {"type": "object", "properties": {"project": {"type": "string"}}, "required": ["project"], "additionalProperties": False}}}
messages = [
    {"role": "system", "content": "Use read_record to answer the user's factual question. After receiving its result, return ONLY JSON with keys value, metric, source; copy these three fields exactly from the record. No invented facts."},
    {"role": "user", "content": "\u0421\u043a\u043e\u043b\u044c\u043a\u043e \u0447\u0435\u043b\u043e\u0432\u0435\u043a \u043e\u0434\u043d\u043e\u0432\u0440\u0435\u043c\u0435\u043d\u043d\u043e \u043c\u043e\u0436\u0435\u0442 \u0440\u0430\u0431\u043e\u0442\u0430\u0442\u044c \u0432 \u0441\u0438\u043d\u0442\u0435\u0442\u0438\u0447\u0435\u0441\u043a\u043e\u043c \u043f\u0440\u043e\u0435\u043a\u0442\u0435 Demo?"},
]
timings = []


def discard_hidden_reasoning(content):
    while True:
        start, end = content.find("<think>"), content.find("</think>")
        if start < 0:
            if end >= 0:
                content = content[end + len("</think>"):]
                continue
            return content.strip()
        if end < start:
            return content[:start].strip()
        content = content[:start] + content[end + len("</think>"):]


def complete():
    payload = {"model": args.model, "messages": messages, "tools": [tool], "tool_choice": "auto", "temperature": 0,
               "max_tokens": 512, "chat_template_kwargs": {"enable_thinking": False}}
    if profile:
        payload.update(profile["tool_loop"].get("sampling", {}))
        payload["max_tokens"] = profile["tool_loop"]["max_output_tokens"]
        payload["chat_template_kwargs"]["enable_thinking"] = profile["thinking_mode"] == "enabled"
    started = time.monotonic()
    request = urllib.request.Request(args.endpoint + "/v1/chat/completions", json.dumps(payload).encode(), {"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=120) as response:
        result = json.load(response)
    timings.append(time.monotonic() - started)
    assert result["model"] == args.model
    # Match the product context: hidden reasoning never enters the next turn
    # or the qualification receipt, even when provider reasoning is enabled.
    message = result["choices"][0]["message"]
    visible = {key: value for key, value in message.items() if key in ["role", "content", "tool_calls"]}
    if isinstance(visible.get("content"), str):
        visible["content"] = discard_hidden_reasoning(visible["content"])
    return visible


first = complete()
calls = first.get("tool_calls", [])
assert len(calls) == 1 and calls[0]["function"]["name"] == "read_record"
arguments = json.loads(calls[0]["function"]["arguments"])
assert set(arguments) == {"project"} and arguments["project"].lower() == "demo"
messages.append(first)
record = {"value": 314, "metric": "concurrent_users", "source": "synthetic://limits/17"}
messages.append({"role": "tool", "tool_call_id": calls[0]["id"], "content": json.dumps(record)})
second = complete()
assert not second.get("tool_calls")
answer = json.loads(second["content"])
assert answer == record
print(json.dumps({"model": args.model, "profile_sha256": hashlib.sha256(Path(args.profile).read_bytes()).hexdigest() if profile else None,
                  "sampling": profile["tool_loop"].get("sampling") if profile else None,
                  "thinking_mode": profile["thinking_mode"] if profile else "disabled",
                  "native_tool_call": True, "exact_result_consumed": True, "seconds": timings, "scope": "synthetic transport qualification, not PUIT"}))
