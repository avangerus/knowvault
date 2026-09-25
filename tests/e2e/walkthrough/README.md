# Screen walkthrough (cards U-1, U-2)

The question set checks answers through the API. This directory adds the robot
that walks the product's screens before the owner does: one command starts a
local synthetic stand with the web interface, signs in as a test user, walks
the card's scenario in a real headless browser, writes a report with
screenshots, and removes everything it started.

The same command, pointed at another address, walks an owner-facing stand in
read-only mode first, so the owner only meets screens and answers that already
work.

## One command

```text
bash tests/e2e/walkthrough/run-walkthrough.sh
```

The local run:

1. starts the card's PostgreSQL container (`kv-card-u-1-pg`, host port 55470)
   and removes it together with its volume when the run finishes;
2. builds the E-1a synthetic workspace (three documents, a workspace
   dictionary and three PostgreSQL source tables bound to the workspace and
   left awaiting confirmation);
3. serves the real `web/dist` application through the real product HTTP
   dispatcher, with the real `workspaceapi` handler, registration and
   confirmation authority and question tool loop over that database;
4. drives the `local` scenario in order in headless Chromium (Playwright): sign
   in; Sources, confirm the tables of the synthetic database source; Settings,
   save a change to the model context; chat, ask «что ты знаешь?» and get an
   answer; collapse and expand the conversation list; open the evidence panel
   with the screen control, close it again, then open the evidence behind that
   answer from its own link;
5. writes `report.md`, `report.json` and `screenshots/` (default output
   `tests/e2e/walkthrough/baseline/`), and exits non-zero when any step failed.

## A stand the robot did not start

```text
KNOWVAULT_WALKTHROUGH_TARGET=stand \
KNOWVAULT_WALKTHROUGH_BASE_URL=<stand origin> \
KNOWVAULT_WALKTHROUGH_CREDENTIALS=<credentials file> \
KNOWVAULT_WALKTHROUGH_USER=<test user> \
KNOWVAULT_WALKTHROUGH_REPORT_DIR=<directory outside the repository> \
bash tests/e2e/walkthrough/run-walkthrough.sh
```

No code changes are needed to move between stands: only the address and the
credentials file change. The `stand` target defaults to the `read-only`
scenario:

1. sign in with the login read from the credentials file (the stand's own
   `/auth/login` either completes the login or redirects to the identity
   provider's form; the robot fills that form when it appears);
2. Sources — opened, read, nothing confirmed;
3. Settings — opened, read, nothing saved;
4. chat — ask «что ты знаешь?», «какие есть источники?» and «что в базе данных
   можем посмотреть?», and wait for each answer;
5. open the evidence of one answer;
6. fail the run if any request other than asking a question or signing in was
   made, so "changes nothing in the workspace" is checked.

The report directory must be outside the repository for the `stand` target:
the report and the screenshots hold stand data and are never committed.

## Credentials

The credentials file is read at run time and kept in memory. Only its path
travels through the environment; the password is never written to the report,
the logs or a screenshot, and every string the report records passes through a
redaction gate. Accepted file shapes:

```text
<one bare value: the password>
```

```text
username = <test user>
password = <password>
```

```json
{"username": "<test user>", "password": "<password>"}
```

The username may also come from `KNOWVAULT_WALKTHROUGH_USER`. The password is
never taken from the command line.

## What is synthetic

Everything is test data. The identity provider and the model channel are the
only substitutes: the stand's `/auth/login` mints the same session cookie
`httpauth` validates instead of an OIDC redirect, and a deterministic
OpenAI-compatible endpoint plays one grounded tool-loop turn instead of
DeepSeek. No customer data, credential or external service is involved.

## Report

Every step records passed/failed, the desktop screenshot after the step, its
duration, the mutating requests it made, every HTTP response with status >= 500
(with method and request path) and every browser console error seen while the
step was active. A step is failed when its action threw, any request it caused
answered 5xx, or the browser logged an error during it. The report also holds
the text of every answer the robot waited for.

`node --test tests/e2e/walkthrough/report.test.mjs` proves the 5xx rule against
a deliberately broken local endpoint. `node --test
tests/e2e/walkthrough/credentials.test.mjs` proves the credentials-file run and
the redaction gate against a dummy stand.

## Environment

| Variable | Meaning |
| --- | --- |
| `KNOWVAULT_WALKTHROUGH_TARGET` | `local` (default) or `stand` |
| `KNOWVAULT_WALKTHROUGH_BASE_URL` | stand origin; required for `stand` |
| `KNOWVAULT_WALKTHROUGH_CREDENTIALS` | credentials file path; required for `stand`, read at run time |
| `KNOWVAULT_WALKTHROUGH_USER` | test user when the file has no username |
| `KNOWVAULT_WALKTHROUGH_SCENARIO` | `local` or `read-only` (`stand` defaults to `read-only`) |
| `KNOWVAULT_WALKTHROUGH_REPORT_DIR` | report output directory; required and outside the repository for `stand` |
| `KNOWVAULT_WALKTHROUGH_INSTANCE` | `1..9`: run next to another local walkthrough |
| `KNOWVAULT_PLAYWRIGHT_MODULE` | module name/path of the Playwright package |
| `KNOWVAULT_WALKTHROUGH_QUESTION` | chat question, `local` scenario (default «что ты знаешь?») |

The browser tool is test infrastructure only: nothing under `internal/`,
`cmd/` or `web/` imports or depends on Playwright.
