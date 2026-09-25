# Screen walkthrough (card U-1)

The question set checks answers through the API. This directory adds the robot
that walks the product's screens before the owner does: one command starts a
local synthetic stand with the web interface, signs in as a test user, walks
the card's scenario in a real headless browser, writes a report with
screenshots, and removes everything it started.

## One command

```text
bash tests/e2e/walkthrough/run-walkthrough.sh
```

The command:

1. starts the card's PostgreSQL container (`kv-card-u-1-pg`, host port 55470)
   and removes it together with its volume when the run finishes;
2. builds the E-1a synthetic workspace (three documents, a workspace
   dictionary and three PostgreSQL source tables bound to the workspace and
   left awaiting confirmation);
3. serves the real `web/dist` application through the real product HTTP
   dispatcher, with the real `workspaceapi` handler, registration and
   confirmation authority and question tool loop over that database;
4. drives the scenario in order in headless Chromium (Playwright): sign in;
   Sources, confirm the tables of the synthetic database source; Settings, save
   a change to the model context; chat, ask «что ты знаешь?» and get an answer;
   open the evidence behind that answer;
5. writes `report.md`, `report.json` and `screenshots/` (default output
   `tests/e2e/walkthrough/baseline/`), and exits non-zero when any step failed.

## What is synthetic

Everything is test data. The identity provider and the model channel are the
only substitutes: the stand's `/auth/login` mints the same session cookie
`httpauth` validates instead of an OIDC redirect, and a deterministic
OpenAI-compatible endpoint plays one grounded tool-loop turn instead of
DeepSeek. No customer data, credential or external service is involved.

## Report

Every step records passed/failed, the desktop screenshot after the step, its
duration, every HTTP response with status >= 500 (with method and request
path) and every browser console error seen while the step was active. A step
is failed when its action threw, any request it caused answered 5xx, or the
browser logged an error during it.

`node --test tests/e2e/walkthrough/report.test.mjs` proves the 5xx rule against
a deliberately broken local endpoint.

## Environment

| Variable | Meaning |
| --- | --- |
| `KNOWVAULT_WALKTHROUGH_REPORT_DIR` | report output directory |
| `KNOWVAULT_WALKTHROUGH_INSTANCE` | `1..9`: run next to another walkthrough |
| `KNOWVAULT_PLAYWRIGHT_MODULE` | module name/path of the Playwright package |
| `KNOWVAULT_WALKTHROUGH_QUESTION` | chat question (default «что ты знаешь?») |

The browser tool is test infrastructure only: nothing under `internal/`,
`cmd/` or `web/` imports or depends on Playwright.
