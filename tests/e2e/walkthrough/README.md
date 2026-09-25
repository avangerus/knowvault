# Screen walkthrough (cards U-1, U-2, U-3, U-4)

The question set checks answers through the API. This directory adds the robot
that walks the product's screens before the owner does: one command starts a
local synthetic stand with the web interface, signs in as a test user, walks
the card's scenario in a real headless browser, writes a report with
screenshots, and removes everything it started.

Since card U-3 the robot also compares every step's screenshot with the
approved reference picture of that step, so a screen that silently changed (a
button moved, a panel vanished, a layout broke) fails the run instead of
waiting for a person to notice the picture.

Since card U-4 a vision model also looks at every screenshot and judges it
against the numbered interface rules of `docs/UI-PRINCIPLES.md`, so an
overloaded screen, a duplicated control, a tiny control or cut-off text reaches
the report as a remark instead of reaching the owner.

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

## The vision review of every screen

```text
KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE=<file holding the model's key> \
  bash tests/e2e/walkthrough/run-walkthrough.sh
```

After a step's screenshot is taken it is sent, together with the 15 numbered
rules of `docs/UI-PRINCIPLES.md` read from the repository as a checklist and the
picture's own pixel size, to a vision model (`deepseek-flash` at
`https://api.deepseek.com` by default). The model answers with a list of
remarks; each remark carries the rule number, the place on the screen and what
is wrong. The report lists them per screen, and a screen the model finds
nothing wrong with says **No remarks.** An answer that is not a list of usable
remarks is recorded as a failed review of that screen.

**Remarks inform; they never fail the run.** A step is failed by its action, a
5xx response, a browser console error or (in `enforce` mode) a screen that
differs from its approved reference — never by a remark from the model. A run
whose every screen gets remarks still passes with every step passed.

### The cost of one run

The review is billed by the model provider. The report states what the run's
review cost, computed from the token usage the provider returns and the
published DeepSeek Flash prices, using the cache-hit and cache-miss input
counts separately and the peak/off-peak window of the moment (`$0.30`/`$0.15`
per million input tokens, `$1.20`/`$0.60` per million output tokens). Before
every call the reviewer reserves the most expensive call it could make
(`REVIEW_MAX_INPUT_TOKENS` plus `max_tokens` at peak prices) and stops calling
the model when that reservation would cross the ceiling, so one run's review
costs at most **$0.05** (`REVIEW_COST_LIMIT_USD`; override with
`KNOWVAULT_WALKTHROUGH_REVIEW_MAX_COST_USD`). Screens the ceiling skipped say
so in the report.

### When the review does not happen

The review is optional infrastructure. The run still passes, and the report
says the review did not happen and why, when

- no key file is given (`KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE`), the file is
  missing, or it is empty;
- the model is unreachable (a connection failure is retried once, then
  recorded);
- the model refuses the key or answers with a server error or a body that
  cannot be read;
- the review is switched off with `KNOWVAULT_WALKTHROUGH_REVIEW=0`;
- the target is `stand`: stand screenshots hold owner data, so sending them to
  a model needs the explicit `KNOWVAULT_WALKTHROUGH_REVIEW=1`.

The key is read from its file at run time, kept in memory, and passed to no
other channel. It is never put in the prompt, the report, a log line or a
screenshot, and it is added to the same redaction gate as the credentials
password. `node --test tests/e2e/walkthrough/review.test.mjs` proves that: it
runs a walkthrough with no key file, with a dummy key and with a model address
where nothing listens, and checks on the bytes that no part of the key file's
content reached the report, or any file tracked by git.

### Proving the review sees the picture

The same test proves the review is a real look at the image, not a scripted
answer:

- against a local fake OpenAI-compatible endpoint it shows that the image the
  model receives is **the bytes of that step's own screenshot**, that a full
  run makes exactly one review per step and that the reported cost is above
  zero;
- with the fake model answering no remarks for one screen and remarks for the
  others, it shows the report says **No remarks.** for that screen and the run
  still passes with every step passed;
- two `live` tests call the real model (and are skipped without a key file):
  one reviews the chat screenshot from the commit **before** the duplicated
  «Sources» control was removed, found in the git history of the walkthrough
  baseline and kept byte-identical as
  `review-fixtures/chat-before-sources-dedup.png` (the blob is
  `0b51347c29567a967b02be168c9fa83c91454409`, the version at
  `1b660eef2^`), and requires a rule 2 remark that names the duplication and
  its place; the other renders the dummy stand with its controls shrunk far
  below the readable size (a stylesheet injected inside the test, never in
  `web/src/`) and requires a rule 12 remark with its place.

### A stand the robot did not start

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
text of every answer the robot waited for, per step the screen comparison
against the approved reference, and the interface review: per screen the
remarks with their rule number and place, or **No remarks.**, or — when the
review did not happen — the reason (see above).

`node --test tests/e2e/walkthrough/report.test.mjs` proves the 5xx rule against
a deliberately broken local endpoint. `node --test
tests/e2e/walkthrough/credentials.test.mjs` proves the credentials-file run and
the redaction gate against a dummy stand. `node --test
tests/e2e/walkthrough/visual.test.mjs` proves the screen comparison: the PNG
codec, the difference rule, two unchanged runs passing with byte-identical
references, a control deliberately moved by the test (never by `web/src/`)
failing exactly its own step with a difference picture, the replace command
naming the replaced reference before the next run passes, and the read-only
mode reporting a difference without failing. `node --test
tests/e2e/walkthrough/review.test.mjs` proves the interface review: the rule
checklist, the price arithmetic, the answer parser, the image bytes the model
receives, one review per step with a cost above zero, a screen with no remarks,
a run full of remarks still passing, and the three no-review runs with no key
file, a dummy key and an address where nothing listens. Set
`KNOWVAULT_WALKTHROUGH_TEST_ARTIFACTS=<directory>` to keep that run's
screenshots, references, difference pictures and the deliberately bad
screenshot instead of a temporary directory that is removed.

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
| `KNOWVAULT_WALKTHROUGH_REVIEW_KEY_FILE` | file holding the review model's key, read at run time; without it the interface review is skipped |
| `KNOWVAULT_WALKTHROUGH_REVIEW` | `0` switches the review off; `1` enables it for `stand`, whose screenshots otherwise stay on the stand |
| `KNOWVAULT_WALKTHROUGH_REVIEW_BASE_URL` | OpenAI-compatible model endpoint (default `https://api.deepseek.com`) |
| `KNOWVAULT_WALKTHROUGH_REVIEW_MODEL` | vision model name (default `deepseek-flash`) |
| `KNOWVAULT_WALKTHROUGH_REVIEW_MAX_COST_USD` | review cost ceiling for one run (default `0.05`) |
| `KNOWVAULT_WALKTHROUGH_INSTANCE` | `1..9`: run next to another local walkthrough |
| `KNOWVAULT_PLAYWRIGHT_MODULE` | module name/path of the Playwright package |
| `KNOWVAULT_WALKTHROUGH_QUESTION` | chat question, `local` scenario (default «что ты знаешь?») |

The browser tool is test infrastructure only: nothing under `internal/`,
`cmd/` or `web/` imports or depends on Playwright.
