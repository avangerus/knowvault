# Walkthrough report (card U-1)

A robot walked the real web interface of the local synthetic stand.

- Command: `bash tests/e2e/walkthrough/run-walkthrough.sh`
- Stand: https://127.0.0.1:55471
- Started: 2026-09-25T14:48:57.142Z
- Finished: 2026-09-25T14:48:59.849Z
- Total: 2.707 s
- Result: **PASS** (5 steps, 0 failed)

## Steps

### 1. sign in as the test user — passed (0.20 s)

![sign in as the test user](screenshots/01-sign-in-as-the-test-user.png)

HTTP responses >= 500 (0):

- none

Browser console errors (1):

- Failed to load resource: the server responded with a status of 401 (Unauthorized)

HTTP responses 400-499 (1):

- GET /api/v1/workspaces -> 401 (UNAUTHENTICATED)

### 2. open Sources and confirm the synthetic database tables — passed (1.09 s)

![open Sources and confirm the synthetic database tables](screenshots/02-open-sources-and-confirm-the-synthetic-database-tables.png)

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

### 3. open the model settings and save a change — passed (0.15 s)

![open the model settings and save a change](screenshots/03-open-the-model-settings-and-save-a-change.png)

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

### 4. ask the question in the chat and get an answer — passed (0.97 s)

![ask the question in the chat and get an answer](screenshots/04-ask-the-question-in-the-chat-and-get-an-answer.png)

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

### 5. open the evidence of that answer — passed (0.08 s)

![open the evidence of that answer](screenshots/05-open-the-evidence-of-that-answer.png)

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

