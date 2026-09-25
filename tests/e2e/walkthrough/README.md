# Screen walkthrough (cards U-1, U-2, U-3)

The question set checks answers through the API. This directory adds the robot
that walks the product's screens before the owner does: one command starts a
local synthetic stand with the web interface, signs in as a test user, walks
the card's scenario in a real headless browser, writes a report with
screenshots, and removes everything it started.

Since card U-3 the robot also compares every step's screenshot with the
approved reference picture of that step, so a screen that silently changed (a
button moved, a panel vanished, a layout broke) fails the run instead of
waiting for a person to notice the picture.

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
5. compares each step's screenshot with the approved reference picture of that
   step in `tests/e2e/walkthrough/references/local/`, writes
   `report.md`, `report.json`, `screenshots/` and — for a step beyond the
   threshold — `differences/` (default output
   `tests/e2e/walkthrough/baseline/`), and exits non-zero when any step failed.

## Approved references and the difference report

An approved reference is the picture of a step a person accepted as correct.
The local set is committed under `tests/e2e/walkthrough/references/local/`, one
PNG per step, named exactly like that step's screenshot. A local run reads the
set and never writes into it.

The report states, per step, the share of the screen that differs
(`difference_ratio`), the threshold it is measured against, the per-pixel
tolerance, and the reference it used. When the share is above the threshold the
step also gets `differences/<step>.png`: the actual screen faded to dark grey
with every differing pixel painted red, so a person sees what moved. Local runs
enforce the threshold — such a step is failed and the run is failed. The share
is the count of differing pixels over the whole picture, so the number is
"how much of the screen changed" and nothing else.

The threshold is measured, not guessed. Across six consecutive full local runs
of unchanged code (one update run and five enforcing runs) the largest
per-step difference was 0.0194% of the 1440x900 screen, and it was always the
clock text the evidence panel or the conversation list renders; no other step
passed 0.012%. The default threshold is **0.05%**
(`DEFAULT_DIFFERENCE_THRESHOLD = 0.0005`), about two and a half times that noise
floor.
A per-pixel tolerance of 16 (of 255) on every colour channel absorbs
anti-aliasing; the screenshot is taken with the text caret hidden, after the
page stopped fetching and after toasts, webfonts and CSS animations settled, so
a blinking cursor, a short-lived notification or a half-loaded screen cannot
fail a step. A deliberately moved control is far above the threshold: the
walkthrough's own proof moves one button by 60 px and the step reports 0.198%
of the screen.

### Replacing the references after an intended screen change

One explicit command re-approves the screens of the local stand:

```text
KNOWVAULT_WALKTHROUGH_UPDATE_REFERENCES=1 \
  bash tests/e2e/walkthrough/run-walkthrough.sh
```

It walks the same scenario, replaces every reference that no longer matches,
leaves the ones that do, and its report names every reference that changed
(`added` or `replaced`, with the difference measured before replacement) in
`report.json` under `visual.references_updated`, in `report.md` under
"Approved references replaced", and on the command's own output. An ordinary
run never writes inside the reference directory, so a passing run, a failing
run and a deliberate break all leave every reference byte-identical.

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

The stand run compares screens in **report** mode: when a step's screen
differs from the reference it uses, the difference, its ratio and the
difference picture are reported, but the step is not failed — the stand's data
is not a build regression. A stand has no references by default, so an
unconfigured run records "no approved reference" per step; point
`KNOWVAULT_WALKTHROUGH_REFERENCE_DIR` at a directory outside the repository
to compare against a known-good stand screen set. Replacing those references
with `KNOWVAULT_WALKTHROUGH_UPDATE_REFERENCES=1` is refused while the directory
is inside the repository, and still never fails a step.

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
answered 5xx, the browser logged an error during it, or its screen differed
beyond the comparison threshold in `enforce` mode. The report also holds the
text of every answer the robot waited for and, per step, the screen comparison
against the approved reference (see above).

`node --test tests/e2e/walkthrough/report.test.mjs` proves the 5xx rule against
a deliberately broken local endpoint. `node --test
tests/e2e/walkthrough/credentials.test.mjs` proves the credentials-file run and
the redaction gate against a dummy stand. `node --test
tests/e2e/walkthrough/visual.test.mjs` proves the screen comparison: the PNG
codec, the difference rule, two unchanged runs passing with byte-identical
references, a control deliberately moved by the test (never by `web/src/`)
failing exactly its own step with a difference picture, the replace command
naming the replaced reference before the next run passes, and the read-only
mode reporting a difference without failing. Set
`KNOWVAULT_WALKTHROUGH_TEST_ARTIFACTS=<directory>` to keep that run's
screenshots, references and difference pictures instead of a temporary
directory that is removed.

## Environment

| Variable | Meaning |
| --- | --- |
| `KNOWVAULT_WALKTHROUGH_TARGET` | `local` (default) or `stand` |
| `KNOWVAULT_WALKTHROUGH_BASE_URL` | stand origin; required for `stand` |
| `KNOWVAULT_WALKTHROUGH_CREDENTIALS` | credentials file path; required for `stand`, read at run time |
| `KNOWVAULT_WALKTHROUGH_USER` | test user when the file has no username |
| `KNOWVAULT_WALKTHROUGH_SCENARIO` | `local` or `read-only` (`stand` defaults to `read-only`) |
| `KNOWVAULT_WALKTHROUGH_REPORT_DIR` | report output directory; required and outside the repository for `stand` |
| `KNOWVAULT_WALKTHROUGH_REFERENCE_DIR` | approved reference pictures (default `tests/e2e/walkthrough/references/<scenario>`); a stand update needs one outside the repository |
| `KNOWVAULT_WALKTHROUGH_UPDATE_REFERENCES` | `1` replaces the approved references with this run's screenshots and reports which changed |
| `KNOWVAULT_WALKTHROUGH_DIFFERENCE_THRESHOLD` | share of the screen that may differ (default `0.0005`) |
| `KNOWVAULT_WALKTHROUGH_INSTANCE` | `1..9`: run next to another local walkthrough |
| `KNOWVAULT_PLAYWRIGHT_MODULE` | module name/path of the Playwright package |
| `KNOWVAULT_WALKTHROUGH_QUESTION` | chat question, `local` scenario (default «что ты знаешь?») |

The browser tool is test infrastructure only: nothing under `internal/`,
`cmd/` or `web/` imports or depends on Playwright.
