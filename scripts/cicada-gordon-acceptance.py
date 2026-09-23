#!/usr/bin/env python3
"""Read-only Gordon question sequence against an already authenticated session.

Set KV_SESSION_COOKIE in the environment (the complete Cookie header value).
The script never prints or persists that value, raw tool results, or SQL rows.
It creates only the four intended Question Runs and reads them back.
"""

import argparse
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


QUESTIONS = (
    "Сколько заданий было назначено 10 сентября 2026 года?",
    "По описанию показателей GM, что означает METER и сколько заданий было назначено 10 сентября 2026 года?",
    "Сколько объектов вошло в этот расчёт и за какой период?",
    "Можно ли считать это число текущим на сегодня? Покажи дату наблюдения и источник.",
)


def request(base, path, cookie, context, method="GET", payload=None, csrf=None):
    headers = {"Accept": "application/json", "Cookie": cookie}
    body = None
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers.update({
            "Content-Type": "application/json",
            "Idempotency-Key": str(uuid.uuid4()),
            "X-KnowVault-CSRF": csrf,
            "Origin": base,
        })
    req = urllib.request.Request(base + path, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, context=context, timeout=360) as response:
            return json.load(response)
    except urllib.error.HTTPError as exc:
        try:
            error = json.load(exc)
            code = error.get("error", {}).get("code", "UNKNOWN")
        except (ValueError, AttributeError):
            code = "UNKNOWN"
        raise RuntimeError(f"{method} {path}: HTTP {exc.code} {code}") from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="Browser-facing HTTPS origin")
    parser.add_argument("--workspace", default="ws_001")
    parser.add_argument("--ca-file", help="Trusted platform CA PEM")
    parser.add_argument("--model-profile", help="Profile ID from workspace catalogue")
    parser.add_argument("--question", action="append", help="Override defaults; repeat for each turn")
    args = parser.parse_args()
    cookie = os.environ.get("KV_SESSION_COOKIE", "")
    if not cookie:
        parser.error("KV_SESSION_COOKIE is required")
    base = args.base_url.rstrip("/")
    context = ssl.create_default_context(cafile=args.ca_file)
    ws = urllib.parse.quote(args.workspace, safe="")
    prefix = f"/api/v1/workspaces/{ws}"
    questions = tuple(args.question or QUESTIONS)
    conversation_id = None
    summaries = []
    for index, question in enumerate(questions, 1):
        csrf = request(base, "/api/v1/session/csrf", cookie, context)["csrf_token"]
        payload = {"question": question}
        if conversation_id:
            payload["conversation_id"] = conversation_id
        if args.model_profile:
            payload["model_profile_id"] = args.model_profile
        start = time.monotonic()
        run = request(base, prefix + "/questions", cookie, context, "POST", payload, csrf)
        elapsed = round(time.monotonic() - start, 2)
        conversation_id = run.get("conversation_id")
        if not conversation_id:
            raise RuntimeError(f"turn {index}: missing conversation_id")
        run_id = run["question_run_id"]
        reread = request(base, prefix + "/questions/" + urllib.parse.quote(run_id, safe=""), cookie, context)
        if reread.get("question_run_id") != run_id:
            raise RuntimeError(f"turn {index}: saved run identity mismatch")
        result = reread.get("answer_result") or {}
        calls = (reread.get("tool_loop") or {}).get("calls") or []
        summary = {
            "turn": index,
            "question": question,
            "elapsed_s": elapsed,
            "run_id": run_id,
            "conversation_id": conversation_id,
            "status": reread.get("status"),
            "stop_reason": (reread.get("tool_loop") or {}).get("stop_reason"),
            "model": (reread.get("model_profile") or {}).get("label"),
            "tool_names": [call.get("name") for call in calls],
            "tool_durations_ms": [call.get("duration_ms") for call in calls],
            "citation_count": len(reread.get("citations") or []),
            "canonical_addresses": [citation.get("address") for citation in reread.get("citations") or []],
            "result_kind": result.get("kind"),
            "result_value": result.get("value"),
            "rows": (result.get("snapshot") or {}).get("row_count"),
            "observation_window": result.get("observation_window"),
            "receipt_digest": result.get("receipt_digest"),
            "answer": reread.get("answer"),
        }
        summaries.append(summary)
        print(json.dumps(summary, ensure_ascii=False), flush=True)
    saved = request(base, prefix + "/conversations/" + urllib.parse.quote(conversation_id, safe=""), cookie, context)
    if len(saved.get("turns") or []) < len(questions):
        raise RuntimeError("conversation history omitted one or more authorized turns")
    print(json.dumps({"history_turns": len(saved["turns"]), "conversation_id": conversation_id}))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (RuntimeError, KeyError, urllib.error.URLError) as exc:
        print(f"Acceptance probe failed: {exc}", file=sys.stderr)
        sys.exit(1)
