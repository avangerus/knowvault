#!/usr/bin/env bash
# Card E-1a: one command that runs the question set on the synthetic proving
# environment with the real DeepSeek channel and writes the report.
#
#   KNOWVAULT_QUESTION_SET_API_KEY_FILE  path to the DeepSeek API key file
#                                        (default: $HOME/.deepseek/api_key)
#   KNOWVAULT_QUESTION_SET_REPORT_DIR    report output directory
#                                        (default: tests/e2e/questions/baseline)
#   KNOWVAULT_QUESTION_SET_ONLY          optional comma-separated question ids
#   KNOWVAULT_QUESTION_SET_INSTANCE      1..9: run next to another worktree (container
#                                        suffix -N, host ports +10*N)
#
# The test starts and removes both card containers itself (kv-card-e-1a-pg on
# 55488, kv-card-e-1a-src on 55489) and exits non-zero when any question fails.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export GOENV=off
export GOTOOLCHAIN=go1.26.5
export GOEXPERIMENT=jsonv2
export KNOWVAULT_QUESTION_SET_API_KEY_FILE="${KNOWVAULT_QUESTION_SET_API_KEY_FILE:-$HOME/.deepseek/api_key}"
export KNOWVAULT_QUESTION_SET_REPORT_DIR="${KNOWVAULT_QUESTION_SET_REPORT_DIR:-$root/tests/e2e/questions/baseline}"

cd "$root"
go test ./tests/integration/postgres -run '^TestQuestionSetRealModel$' -count=1 -v -timeout 90m
