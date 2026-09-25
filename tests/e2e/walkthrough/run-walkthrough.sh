#!/usr/bin/env bash
# Card U-1: one command that starts the local synthetic stand with the web
# interface, signs in as a test user, walks the card's scenario in a real
# browser, writes the report with screenshots, and removes everything it
# started (the PostgreSQL container together with its volume).
#
# Card U-2: the same command, with KNOWVAULT_WALKTHROUGH_TARGET=stand, points
# the robot at another address and signs in with a login read from a
# credentials file. No code change is needed to switch stands.
#
# Card U-3: every step's screenshot is compared with the approved reference
# picture of that step; the report shows the difference per step and a picture
# that highlights it. A local step beyond the threshold fails. The one command
# that replaces the approved references after an intended screen change is
#
#   KNOWVAULT_WALKTHROUGH_UPDATE_REFERENCES=1 \
#     bash tests/e2e/walkthrough/run-walkthrough.sh
#
# and its report names every reference that changed. An ordinary run never
# writes inside the reference directory.
#
#   KNOWVAULT_WALKTHROUGH_TARGET      local (default) | stand
#   KNOWVAULT_WALKTHROUGH_BASE_URL    stand origin; required for target=stand
#   KNOWVAULT_WALKTHROUGH_CREDENTIALS credentials file path; required for
#                                     target=stand, read at run time only
#   KNOWVAULT_WALKTHROUGH_USER        test user, when the file has no username
#   KNOWVAULT_WALKTHROUGH_REPORT_DIR  report output directory; required for
#                                     target=stand so stand data never lands
#                                     in the repository
#                                     (local default: tests/e2e/walkthrough/baseline)
#   KNOWVAULT_WALKTHROUGH_SCENARIO    local | read-only; target=stand defaults
#                                     to read-only
#   KNOWVAULT_WALKTHROUGH_INSTANCE    1..9: run next to another local walkthrough
#                                     (container suffix -N, host ports +N)
#   KNOWVAULT_WALKTHROUGH_REFERENCE_DIR
#                                     approved reference pictures (default:
#                                     tests/e2e/walkthrough/references/<scenario>);
#                                     a stand update needs one outside the repo
#   KNOWVAULT_WALKTHROUGH_UPDATE_REFERENCES
#                                     1 replaces the approved references
#   KNOWVAULT_WALKTHROUGH_DIFFERENCE_THRESHOLD
#                                     share of the screen that may differ
#   KNOWVAULT_PLAYWRIGHT_MODULE       module name/path of the Playwright package
#                                     (default: playwright)
#
# The browser driver needs Node.js with Playwright installed; if Playwright is
# not resolvable from the repository, point KNOWVAULT_PLAYWRIGHT_MODULE at it.
# The product itself never depends on the browser.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
target="${KNOWVAULT_WALKTHROUGH_TARGET:-local}"

if [[ "$target" == "stand" ]]; then
  : "${KNOWVAULT_WALKTHROUGH_BASE_URL:?KNOWVAULT_WALKTHROUGH_BASE_URL is required for target=stand}"
  : "${KNOWVAULT_WALKTHROUGH_CREDENTIALS:?KNOWVAULT_WALKTHROUGH_CREDENTIALS is required for target=stand}"
  : "${KNOWVAULT_WALKTHROUGH_REPORT_DIR:?KNOWVAULT_WALKTHROUGH_REPORT_DIR is required for target=stand (keep it outside the repository)}"
  export KNOWVAULT_WALKTHROUGH_SCENARIO="${KNOWVAULT_WALKTHROUGH_SCENARIO:-read-only}"
  cd "$root"
  exec node tests/e2e/walkthrough/walkthrough.mjs
fi

if [[ "$target" != "local" ]]; then
  echo "KNOWVAULT_WALKTHROUGH_TARGET=$target, want local or stand" >&2
  exit 2
fi

export GOENV=off
export GOTOOLCHAIN=go1.26.5
export GOEXPERIMENT=jsonv2
export KNOWVAULT_WALKTHROUGH=1
export KNOWVAULT_WALKTHROUGH_SCENARIO="${KNOWVAULT_WALKTHROUGH_SCENARIO:-local}"
export KNOWVAULT_WALKTHROUGH_REPORT_DIR="${KNOWVAULT_WALKTHROUGH_REPORT_DIR:-$root/tests/e2e/walkthrough/baseline}"

cd "$root"
go test ./tests/integration/postgres -run '^TestU1Walkthrough$' -count=1 -v -timeout 20m
