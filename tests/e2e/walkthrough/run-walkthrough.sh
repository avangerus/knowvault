#!/usr/bin/env bash
# Card U-1: one command that starts the local synthetic stand with the web
# interface, signs in as a test user, walks the card's scenario in a real
# browser, writes the report with screenshots, and removes everything it
# started (the PostgreSQL container together with its volume).
#
#   KNOWVAULT_WALKTHROUGH_REPORT_DIR  report output directory
#                                     (default: tests/e2e/walkthrough/baseline)
#   KNOWVAULT_WALKTHROUGH_INSTANCE    1..9: run next to another walkthrough
#                                     (container suffix -N, host ports +N)
#   KNOWVAULT_PLAYWRIGHT_MODULE       module name/path of the Playwright package
#                                     (default: playwright)
#
# The browser driver needs Node.js with Playwright installed; if Playwright is
# not resolvable from the repository, point KNOWVAULT_PLAYWRIGHT_MODULE at it.
# The product itself never depends on the browser.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
export GOENV=off
export GOTOOLCHAIN=go1.26.5
export GOEXPERIMENT=jsonv2
export KNOWVAULT_WALKTHROUGH=1
export KNOWVAULT_WALKTHROUGH_REPORT_DIR="${KNOWVAULT_WALKTHROUGH_REPORT_DIR:-$root/tests/e2e/walkthrough/baseline}"

cd "$root"
go test ./tests/integration/postgres -run '^TestU1Walkthrough$' -count=1 -v -timeout 20m
