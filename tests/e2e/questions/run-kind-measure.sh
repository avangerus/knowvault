#!/usr/bin/env bash
# Card D-15 result 3: one command that measures the separate recognition step
# (ADR-0099 amendment 1) on the real model.
#
#   KNOWVAULT_KIND_MEASURE_API_KEY_FILE  path to the DeepSeek API key file
#                                        (default: $HOME/.deepseek/api_key)
#
# Usage:
#   bash tests/e2e/questions/run-kind-measure.sh -file PATH [-runs 3]
#
# The command reads the key only at run time. It never writes the key into the
# repository, the report or the logs. The phrasings file is JSON: a bare array
# or {"phrasings":[...]}, each entry {"question": "...", "kind": "full"}; the
# kind is one of full, change, hypothetical, plain_overview,
# workspace_overview, sources_overview, greeting, off_topic, vague.
#
# It prints the per-kind correct counts and every case where a `full` question
# was recognised as another kind, and exits non-zero when either the overall
# accuracy is below -min-accuracy (default 0.95) or a single full question was
# recognised as another kind.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export GOENV=off
export GOTOOLCHAIN=go1.26.5
export GOEXPERIMENT=jsonv2
export KNOWVAULT_KIND_MEASURE_API_KEY_FILE="${KNOWVAULT_KIND_MEASURE_API_KEY_FILE:-$HOME/.deepseek/api_key}"

cd "$root"
go run ./tests/e2e/questions/kindmeasure "$@"
