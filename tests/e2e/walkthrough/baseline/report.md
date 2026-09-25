# Walkthrough report

A robot walked the real web interface of the local synthetic stand.

- Command: `bash tests/e2e/walkthrough/run-walkthrough.sh`
- Scenario: local
- Stand: https://127.0.0.1:55476
- Started: 2026-09-25T18:26:45.280Z
- Finished: 2026-09-25T18:26:48.065Z
- Total: 2.785 s
- Result: **PASS** (5 steps, 0 failed)

## Answers (1)

### что ты знаешь?

Вывоз твёрдых коммунальных отходов с места накопления отходов выполняется не позднее 24 часов с момента заполнения контейнера.

## Steps

### 1. sign in as the test user — passed (0.21 s)

![sign in as the test user](screenshots/01-sign-in-as-the-test-user.png)

Mutating requests (0):

- none

HTTP responses >= 500 (0):

- none

Browser console errors (1):

- Failed to load resource: the server responded with a status of 401 (Unauthorized)

HTTP responses 400-499 (1):

- GET /api/v1/workspaces -> 401 (UNAUTHENTICATED)

### 2. open Sources and confirm the synthetic database tables — passed (1.05 s)

![open Sources and confirm the synthetic database tables](screenshots/02-open-sources-and-confirm-the-synthetic-database-tables.png)

Mutating requests (3):

- POST /api/v1/workspaces/ws_registration/managed-source-confirmations:batch
- POST /api/v1/workspaces/ws_registration/managed-source-confirmations:batch
- POST /api/v1/workspaces/ws_registration/managed-source-confirmations:batch

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

### 3. open the model settings and save a change — passed (0.23 s)

![open the model settings and save a change](screenshots/03-open-the-model-settings-and-save-a-change.png)

Mutating requests (1):

- PUT /api/v1/workspaces/ws_registration/model-context

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

### 4. ask the question in the chat and get an answer — passed (0.96 s)

![ask the question in the chat and get an answer](screenshots/04-ask-the-question-in-the-chat-and-get-an-answer.png)

Answer texts (1):

> что ты знаешь?
>
> Вывоз твёрдых коммунальных отходов с места накопления отходов выполняется не позднее 24 часов с момента заполнения контейнера.

Mutating requests (1):

- POST /api/v1/workspaces/ws_registration/questions

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

### 5. open the evidence of that answer — passed (0.12 s)

![open the evidence of that answer](screenshots/05-open-the-evidence-of-that-answer.png)

Mutating requests (0):

- none

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

