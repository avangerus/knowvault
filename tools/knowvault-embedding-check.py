"""Synthetic semantic/identity qualification; no company corpus is transmitted."""
import argparse
import json
import math
import time
import urllib.request
import random
import string
from concurrent.futures import ThreadPoolExecutor

parser = argparse.ArgumentParser()
parser.add_argument("--endpoint", required=True)
parser.add_argument("--model", required=True)
parser.add_argument("--concurrency-check", action="store_true")
parser.add_argument("--concurrency", type=int, choices=range(1, 9), default=2)
args = parser.parse_args()
documents = [
    "\u0421\u0435\u0440\u0432\u0438\u0441 \u0440\u0430\u0441\u0441\u0447\u0438\u0442\u0430\u043d \u043d\u0430 \u043e\u0434\u043d\u043e\u0432\u0440\u0435\u043c\u0435\u043d\u043d\u0443\u044e \u0440\u0430\u0431\u043e\u0442\u0443 314 \u043f\u043e\u043b\u044c\u0437\u043e\u0432\u0430\u0442\u0435\u043b\u0435\u0439.",
    "\u0422\u0435\u0445\u043d\u0438\u0447\u0435\u0441\u043a\u043e\u0435 \u043e\u0431\u0441\u043b\u0443\u0436\u0438\u0432\u0430\u043d\u0438\u0435 \u043d\u0430\u0447\u0438\u043d\u0430\u0435\u0442\u0441\u044f \u043a\u0430\u0436\u0434\u043e\u0435 \u0432\u043e\u0441\u043a\u0440\u0435\u0441\u0435\u043d\u044c\u0435 \u0432 \u043f\u043e\u043b\u043d\u043e\u0447\u044c.",
    "\u0416\u0443\u0440\u043d\u0430\u043b \u0434\u0435\u0439\u0441\u0442\u0432\u0438\u0439 \u0441\u043e\u0442\u0440\u0443\u0434\u043d\u0438\u043a\u043e\u0432 \u0445\u0440\u0430\u043d\u0438\u0442\u0441\u044f 180 \u0441\u0443\u0442\u043e\u043a, \u0437\u0430\u0442\u0435\u043c \u0430\u0440\u0445\u0438\u0432\u0438\u0440\u0443\u0435\u0442\u0441\u044f.",
    "\u041f\u0430\u0440\u043e\u043b\u044c \u0434\u043e\u043b\u0436\u0435\u043d \u0441\u043e\u0434\u0435\u0440\u0436\u0430\u0442\u044c \u043d\u0435 \u043c\u0435\u043d\u044c\u0448\u0435 \u0434\u0432\u0435\u043d\u0430\u0434\u0446\u0430\u0442\u0438 \u0441\u0438\u043c\u0432\u043e\u043b\u043e\u0432.",
    "\u041f\u0440\u043e\u0441\u043c\u0430\u0442\u0440\u0438\u0432\u0430\u0442\u044c \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u044b \u043e\u0442\u0434\u0435\u043b\u0430 \u043a\u0430\u0434\u0440\u043e\u0432 \u0440\u0430\u0437\u0440\u0435\u0448\u0435\u043d\u043e \u0442\u043e\u043b\u044c\u043a\u043e \u0443\u0447\u0430\u0441\u0442\u043d\u0438\u043a\u0430\u043c \u0433\u0440\u0443\u043f\u043f\u044b HR.",
    "\u0414\u043e\u0441\u0442\u0430\u0432\u043a\u0430 \u043e\u0431\u043e\u0440\u0443\u0434\u043e\u0432\u0430\u043d\u0438\u044f \u043e\u0441\u0443\u0449\u0435\u0441\u0442\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u043f\u043e \u0430\u0434\u0440\u0435\u0441\u0443 \u0441\u043a\u043b\u0430\u0434\u0430 \u043e\u0440\u0433\u0430\u043d\u0438\u0437\u0430\u0446\u0438\u0438.",
    "\u0418\u0441\u0442\u0451\u043a\u0448\u0438\u0439 \u0442\u043e\u043a\u0435\u043d \u0434\u043e\u0441\u0442\u0443\u043f\u0430 \u043e\u0431\u043d\u043e\u0432\u043b\u044f\u0435\u0442\u0441\u044f \u043f\u043e\u0441\u043b\u0435 \u043f\u043e\u0432\u0442\u043e\u0440\u043d\u043e\u0439 \u0430\u0443\u0442\u0435\u043d\u0442\u0438\u0444\u0438\u043a\u0430\u0446\u0438\u0438.",
    "\u0412 \u0440\u0435\u0437\u0435\u0440\u0432\u043d\u0443\u044e \u043a\u043e\u043f\u0438\u044e \u0432\u0445\u043e\u0434\u044f\u0442 \u0438\u0441\u0445\u043e\u0434\u043d\u044b\u0435 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u044b, \u0438\u043d\u0434\u0435\u043a\u0441 \u0438 \u0436\u0443\u0440\u043d\u0430\u043b \u0430\u0443\u0434\u0438\u0442\u0430.",
]
questions = [
    ("\u0441\u043a\u043e\u043a\u0430 \u043d\u0430\u0440\u043e\u0434\u0443 \u043c\u043e\u0436\u0435\u0442 \u0441\u0438\u0434\u0435\u0442\u044c \u0432 \u0441\u0438\u0441\u0442\u0435\u043c\u0435 \u0440\u0430\u0437\u043e\u043c?", 0),
    ("\u043a\u043e\u0433\u0434\u0430 \u0441\u0442\u0430\u0440\u044b\u0435 \u0437\u0430\u043f\u0438\u0441\u0438 \u043e \u0442\u043e\u043c \u043a\u0442\u043e \u0447\u0442\u043e \u0434\u0435\u043b\u0430\u043b \u0443\u0431\u0438\u0440\u0430\u044e\u0442?", 2),
    ("\u0432\u0441\u0435\u043c \u043b\u0438 \u043c\u043e\u0436\u043d\u043e \u0433\u043b\u044f\u043d\u0443\u0442\u044c \u043a\u0430\u0434\u0440\u043e\u0432\u044b\u0435 \u0444\u0430\u0439\u043b\u044b?", 4),
    ("\u0447\u0442\u043e \u043f\u043e\u043f\u0430\u0434\u0451\u0442 \u0432 \u0431\u044d\u043a\u0430\u043f?", 7),
]
timings = []


def embed(text):
    payload = json.dumps({"model": args.model, "input": text, "encoding_format": "float"}).encode()
    started = time.monotonic()
    response = json.load(urllib.request.urlopen(urllib.request.Request(args.endpoint + "/v1/embeddings", payload, {"Content-Type": "application/json"}), timeout=30))
    timings.append(time.monotonic() - started)
    vector = response["data"][0]["embedding"]
    assert response["model"] == args.model and len(vector) == 1024
    assert all(math.isfinite(x) for x in vector)
    norm = math.sqrt(sum(x * x for x in vector))
    assert abs(norm - 1) < 0.0001
    return vector


vectors = [embed(doc) for doc in documents]
rows = []
for question, expected in questions:
    vector = embed(question)
    ranked = sorted(enumerate(sum(a*b for a, b in zip(vector, candidate)) for candidate in vectors), key=lambda item: -item[1])
    rows.append({"question": question, "expected": expected, "top": ranked[:3], "pass": ranked[0][0] == expected})
repeat = embed(documents[0])
max_delta = max(abs(a-b) for a, b in zip(vectors[0], repeat))
capacity = None
if args.concurrency_check:
    # Distinct high-token-density ASCII inputs exercise the byte ceiling without
    # a repeated prefix/cache shortcut. These strings carry no company data.
    rng = random.Random(135)
    long_inputs = ["".join(rng.choices(string.ascii_letters + string.digits + " ", k=8192)) for _ in range(24)]
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        completed = list(pool.map(embed, long_inputs))
    capacity = {"concurrency": args.concurrency, "requests": len(completed), "input_bytes": 8192, "distinct_inputs": True,
                "elapsed_seconds": time.monotonic() - started, "pass": len(completed) == 24}
result = {"model": args.model, "dimension": 1024, "documents": documents, "rows": rows,
          "correct": sum(row["pass"] for row in rows), "total": len(rows), "repeat_max_delta": max_delta,
          "seconds": timings, "capacity": capacity, "scope": "synthetic profile qualification, not PUIT or domain acceptance"}
print(json.dumps(result, ensure_ascii=False, indent=2))
raise SystemExit(0 if result["correct"] == len(rows) and max_delta < 0.00001 else 1)
