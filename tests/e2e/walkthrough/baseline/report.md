# Walkthrough report

A robot walked the real web interface of the local synthetic stand.

- Command: `bash tests/e2e/walkthrough/run-walkthrough.sh`
- Scenario: local
- Stand: https://127.0.0.1:55479
- Started: 2026-09-25T19:36:12.534Z
- Finished: 2026-09-25T19:36:19.700Z
- Total: 7.166 s
- Result: **PASS** (11 steps, 0 failed)

## Answers (1)

### что ты знаешь?

Вывоз твёрдых коммунальных отходов с места накопления отходов выполняется не позднее 24 часов с момента заполнения контейнера.

## Steps

### 1. the interface shows the running server revision — passed (0.13 s)

![the interface shows the running server revision](screenshots/01-the-interface-shows-the-running-server-revision.png)

Mutating requests (0):

- none

HTTP responses >= 500 (0):

- none

Browser console errors (1):

- Failed to load resource: the server responded with a status of 401 (Unauthorized)

HTTP responses 400-499 (1):

- GET /api/v1/workspaces -> 401 (UNAUTHENTICATED)

### 2. sign in as the test user — passed (0.09 s)

![sign in as the test user](screenshots/02-sign-in-as-the-test-user.png)

Mutating requests (0):

- none

HTTP responses >= 500 (0):

- none

Browser console errors (1):

- Failed to load resource: the server responded with a status of 401 (Unauthorized)

HTTP responses 400-499 (1):

- GET /api/v1/workspaces -> 401 (UNAUTHENTICATED)

### 3. open Sources and confirm the synthetic database tables — passed (1.10 s)

![open Sources and confirm the synthetic database tables](screenshots/03-open-sources-and-confirm-the-synthetic-database-tables.png)

Mutating requests (3):

- POST /api/v1/workspaces/ws_registration/managed-source-confirmations:batch
- POST /api/v1/workspaces/ws_registration/managed-source-confirmations:batch
- POST /api/v1/workspaces/ws_registration/managed-source-confirmations:batch

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

### 4. open the model settings and save a change — passed (0.26 s)

![open the model settings and save a change](screenshots/04-open-the-model-settings-and-save-a-change.png)

Mutating requests (1):

- PUT /api/v1/workspaces/ws_registration/model-context

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

### 5. ask the question in the chat and get an answer — passed (4.46 s)

![ask the question in the chat and get an answer](screenshots/05-ask-the-question-in-the-chat-and-get-an-answer.png)

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

### 6. collapse the conversation list — passed (0.05 s)

![collapse the conversation list](screenshots/06-collapse-the-conversation-list.png)

Mutating requests (0):

- none

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

### 7. expand the conversation list again — passed (0.05 s)

![expand the conversation list again](screenshots/07-expand-the-conversation-list-again.png)

Mutating requests (0):

- none

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

### 8. open the evidence panel with the screen control — passed (0.05 s)

![open the evidence panel with the screen control](screenshots/08-open-the-evidence-panel-with-the-screen-control.png)

Mutating requests (0):

- none

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

### 9. close the evidence panel with one action — passed (0.05 s)

![close the evidence panel with one action](screenshots/09-close-the-evidence-panel-with-one-action.png)

Mutating requests (0):

- none

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

### 10. open the evidence of that answer — passed (0.24 s)

![open the evidence of that answer](screenshots/10-open-the-evidence-of-that-answer.png)

Mutating requests (0):

- none

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

### 11. open the source page of that answer — passed (0.21 s)

![open the source page of that answer](screenshots/11-open-the-source-page-of-that-answer.png)

Mutating requests (0):

- none

HTTP responses >= 500 (0):

- none

Browser console errors (0):

- none

