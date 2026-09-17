# Company-month seed

This is a deterministic, fictional source fixture for KnowVault connector and
tool tests. The company is **KV Service Demo** and the materialized month is
2026-08. It contains 24 synthetic employees in four teams, eight customers, ten
contracts, 80 assets, 600 tickets with event histories, 40 invoices, payments,
time entries, 12 releases, 56 small English documents, and a 12-commit local
Git history. All contacts use `example.invalid`; no real people, companies,
credentials, or network operations are involved.

The generator uses only the Python standard library and refuses to write into a
populated output directory. It does not delete anything. The explicit timezone
is `Europe/Moscow` (UTC+03:00), with an August snapshot cutoff of
`2026-09-01T00:00:00+03:00`.

The dataset revision is **`company-month-seed-v2-en`**. It translates the original
fixture into English, including company labels, ticket categories, documents,
generated code and acceptance questions. IDs, counts, dates and numeric business
facts are preserved. The default seed key remains `company-month-v1` so those
facts remain reproducible. Text bytes, file hashes and generated Git commit
hashes differ from the previous revision; named refs such as `v0.3.0` stay the
same. Generate into a new directory; existing connected fixtures are unchanged.

## Generate

From the repository root:

```text
python3 tools/seeds/company-month/generate.py --out .local/release/company-month-seed-v2-en --month 2026-08 --seed company-month-v1
```

`--out` must be a new empty directory. To compare another generation, use two
new temporary directories and the same `--month` and `--seed`.
Use `py -3` instead of `python3` on Windows if that is your Python launcher.

The source roots are deliberately separate:

| Root | Intended connector content |
|---|---|
| `documents/` | English company, support, incident, policy, meeting, contract and finance documents |
| `repo/` | Small Go source repository with deterministic refs `v0.3.0` and `v0.4.0` among 12 commits |
| `relational/` | CSV tables and `bootstrap.sql` for a separate external PostgreSQL source |
| `control/` | Oracle only: manifest, hashes, counts, questions, access matrix; never ingest or mount |

`relational/bootstrap.sql` creates tables and uses psql `\\copy` from the seed
root. It is intended for a separate external PostgreSQL fixture database. It
does not target the KnowVault product database and does not add a product
migration.

## Validate and test

Validation recomputes foreign keys, dates, ticket status transitions and
terminal events, invoice tax/payment arithmetic, Git history, manifest hashes,
and the golden numeric answers from the underlying rows:

```text
python3 tools/seeds/company-month/validate.py --seed-dir .local/release/company-month-seed-v2-en
python3 tools/seeds/company-month/test_seed.py
```

The question oracle has 36 scenarios across M1 documents/Git and M3 SQL:
lookups, typo/ellipsis wording, timelines, code at refs, aggregate SQL,
rule-plus-rows answers, current versus superseded SLA rules, no-data answers,
permission denial for finance, ordinary support access, and intentionally
ambiguous prompts that require clarification. It describes intended test
capabilities; it does not claim that a live connector or stand is connected.

`natural-questions.json` adds 14 ordinary, misspelled, ambiguous or false-premise
prompts tied to that oracle. It stays in the test package, outside source roots.
For example: "how many ppl n teams we got?", "all 600 tickets are closed already,
right?" and "P1 is half an hour right, so 25 minutes is fine?" Answers need semantic source
review; returning a real address alone is insufficient. Permission tests use
the actual caller identity, never a role asserted in the prompt.

## Mounting and access

Use `control/access-matrix.md` while configuring connector identities. A
`support-agent` may see `documents/common`, `documents/support`, and support
tables; it must not see `documents/finance`, contracts, invoices or payments.
A finance identity may see the finance root and all relational tables. Mount
only the selected source roots or an allowlisted subdirectory. Never mount the
seed parent, `control/`, `.git/`, or a recursive path that exposes the oracle.

The generated output is local review material under
`.local/release/company-month-seed-v2-en` and is not connected to a stand by this
package. The oracle stays outside all ingestible roots.
