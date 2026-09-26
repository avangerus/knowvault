# Question set (card E-1a)

This directory is the single home of the E-1a question set: real questions asked
of the real model on a synthetic proving environment, judged by fixed rules
before anything reaches the owner.

## One command

```text
KNOWVAULT_QUESTION_SET_API_KEY_FILE=/path/to/deepseek/key \
  bash tests/e2e/questions/run-question-set.sh
```

The command:

1. starts the two card containers (`kv-card-e-1a-pg` on 55488 for the product
   database, `kv-card-e-1a-src` on 55489 for the synthetic source database) and
   removes both when it finishes;
2. builds the synthetic workspace (three documents, a workspace dictionary, and
   the `contract`, `client` and `container_group` PostgreSQL source relations
   with their query credentials and confirmed tables);
3. runs every question three times against DeepSeek `deepseek-flash`;
4. writes `report.md` and `report.json` (default output
   `tests/e2e/questions/baseline/`);
5. exits non-zero when any question fails.

The DeepSeek key is read from its file only at run time. It is never written
into the repository, the report or the logs. Every other value here is
synthetic: the documents, the counts, the contract number and the source
database contain no customer data.

## Recognition of the question kind (card D-15)

ADR-0099 amendment 1 recognises the kind of each question by meaning in a
separate short model call, before the answer. The question set records the
recognised kind for every run and reports it per run (`kind` in `report.json`,
the Kind column and the `Recognised kinds` section in `report.md`), together
with the recognition call's own token cost.

One command measures that recognition step on the real model:

```text
KNOWVAULT_KIND_MEASURE_API_KEY_FILE=/path/to/deepseek/key \
  bash tests/e2e/questions/run-kind-measure.sh \
  -file tests/e2e/questions/kind-phrasings.json
```

The phrasings file is JSON: a bare array or `{"phrasings":[...]}`, each entry
`{"question": "...", "kind": "full"}`. The kind is one of `full`, `change`,
`hypothetical`, `plain_overview`, `workspace_overview`, `sources_overview`,
`greeting`, `off_topic`, `vague`. The command runs every phrasing three times
by default, prints the per-kind correct counts and every case where a `full`
question was recognised as another kind, and exits non-zero when the accuracy
is below 95 % or when a single `full` question was recognised as another kind.
`kind-phrasings.json` is the executor's own small file; acceptance uses its own
unseen file with the same shape.

## The data file

`questions.json` is the one data file: environment (containers, synthetic
documents, dictionary, table columns and seed SQL, known counts `A`/`M` and
contract number `N`), the universal rules, and the questions with their own
checks. The rule engine and the runner read it and contain no second copy of
the questions or expectations.

A question may name the surface the runner must ask it through (`via: "mcp"`,
card D-19) and the question it must match in the same full run
(`compares_to`). The judge's `number_equals_peer` rule is green only when both
answers state the same number and `source_equals_peer` only when both cite the
same governed live source; `mcp_transport_recorded` requires the run to have
arrived through the product's MCP server and the product's own
`question.created` record to carry the MCP transport's request id. Q7 is Q3's
count question asked through MCP, so a full run answers it over the MCP
transport and compares it with the chat's Q3 of the same run index.

Every answer must pass the universal hard rules: non-empty text, no
`profile limits` / `could not be completed`, no short label followed by a colon
at the start of a line, no `Evidence 1`-style marker, no prose claiming a
citation was verified, no internal identifiers, the question's language, no
duplicated tool call, the same tool on the same source at most twice, the
question's step and length limits, and a verification status that is not a
failure.

Hard rules must pass 3 of 3 runs; value and time rules must pass 2 of 3. The
verification status field is the response's `status` with
`tool_loop.stop_reason`; `CITATIONS_UNVERIFIED` is the one tolerated failure.

## H5: the database that cannot be read yet (card E-2)

`questions.json` also describes one synthetic PostgreSQL database, «Заявки»,
whose tables are bound to the workspace but whose confirmation is never minted.
Its own container is `kv-card-e-2-pg` on 55622 with database `knowvault_test`,
and the one command starts and removes it like the two card containers. `H5`
asks a count question about its data; it is green only when the answer is at
most two sentences, names «Заявки», says the database cannot be read yet, says
that confirming its tables is what makes it readable, and the run recorded no
`knowvault_source_sql` call. A bare zero count or a "no records" answer is red.

The two statements are judged by `stems_in_same_sentence`: one sentence must
carry a stem from `texts` and a stem from `with`, in any order and any
grammatical form, so «не читается» and «прочитать пока нельзя», «таблицы не
подтверждены» and «как только таблицы подтвердят» are all accepted. The stems
are data in `questions.json`; the engine only matches them, folded to lower case
with ё written as е. A stem of three letters or fewer is matched as a whole
word, so the negation `не` is not found inside `менее`.

The one command reads the product's own source status immediately before asking
each `H5` run and records it in the report; if the database's tables are
confirmed instead of awaiting confirmation, the harness fails, because the
question would no longer test the "cannot be read yet" answer.

The database is a separate `environment.unconfirmed_database` block, not a
fourth entry in `environment.sources`, and the run binds it only when it reaches
`H5` (`H5` stays the last question): every other question is asked in exactly
the workspace it had before, and the interface walkthrough and every other test
keep the workspace they had.

## Tests

```text
go test ./tests/e2e/questions              # rule engine on canned answers
go test ./tests/integration/postgres -run '^TestQuestionSetSmoke$'
```

The smoke test runs the same runner against a stub OpenAI-compatible endpoint
and the real product database, so CI can exercise the pipeline without a key.

The rule-engine tests pin the owner's real failed answer to «что ты знаешь?»,
the label/evidence/id answer, a renamed label, and a short correct answer.

## Baseline

`baseline/report.md` and `baseline/report.json` are one full run of the current
code. Q1 is expected to fail: it reproduces the owner's failure. The report
records every run's tool calls, steps, seconds, rule verdicts and answer text,
plus the total time and the DeepSeek token use and cost.
