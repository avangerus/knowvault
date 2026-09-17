# Deterministic Number Verification 1.0

Notation: Cyrillic dictionary entries and examples use standard `\uXXXX` escapes in this English document. Decode them before lexing or comparing UTF-8 byte offsets. The runtime words, dictionary, numeric values and required byte boundaries are unchanged.

Status: `ACCEPTED`. The semantic verifier is not sufficient protection for numbers, dates, and units. Before every terminal commit, each `FACT` additionally undergoes `numeric-validator-v1` without LLM.

## 1. Exact lexer `numeric-validator-v1`

Input — canonical UTF-8 `text-v1`. Offsets below are 0-based half-open UTF-8 byte offsets. The algorithm proceeds from left to right:

1. Any Unicode decimal digit of category `Nd`, except ASCII `0..9`, creates a FAILED literal: mixing numeral scripts version 1.0 does not support.
2. Base character — Unicode `Letter`, `Mark`, ASCII digit, or `_`. Join character — `. , : / - + U+2212`; it is included in the span only between two base characters. Currency/quantity suffix `$ € £ ¥ ₽ ₴ ₸ % ‰ °` may adjoin the span. Leading `+`, `-`, `U+2212`, or currency symbol is included only when a span with an ASCII digit begins immediately after it.
3. Primary span — the maximum sequence of these rules containing at least one ASCII digit. Therefore, `15.07.2026`, `v2.3`, `0xFF`, and `ALPHA-291` are checked as a whole, not just by individual digits.
4. Month token has the highest compound priority. Forms `day-number + separator + month + separator + 4-digit-year` and `month + separator + day-number + (separator or comma+separator) + 4-digit-year` form a single `DATE_TIME` span. Year is optional, but if present adjacent in this form, it cannot be separated. Separator — exactly one rune from `U+0020`, `U+00A0`, `U+202F`; LF is not allowed.
5. Then, exactly one currency token from `currency-code-v1` may be attached to the primary span on either side, or one following token from `unit-v1`. Longest valid match is used; currency/unit token does not create a second overlapping literal. Between token and number, the same single separator rune is allowed, which is preserved byte-exact. More than one whitespace, LF, or other separator does not join literals.
6. Spans do not overlap and are issued in order `claim_start`; identical text in different locations remains different entries. `claim_end > claim_start`, and `text` must be a byte-exact slice claim.

Fixed case-insensitive dictionaries are compared pinned Go 1.26.5 `strings.EqualFold`; exact casing and separator are preserved in literal:

```text
currency-code-v1:
USD EUR RUB GBP CNY JPY KZT UAH

unit-v1:
% ‰
ms s sec sec. min min. h hr day days week weeks month months year years
\u043c\u0441 \u0441 \u0441\u0435\u043a \u0441\u0435\u043a. \u043c\u0438\u043d \u043c\u0438\u043d. \u0447 \u0447. \u0447\u0430\u0441 \u0447\u0430\u0441\u0430 \u0447\u0430\u0441\u043e\u0432 \u0434\u0435\u043d\u044c \u0434\u043d\u044f \u0434\u043d\u0435\u0439 \u043d\u0435\u0434\u0435\u043b\u044f \u043d\u0435\u0434\u0435\u043b\u0438 \u043d\u0435\u0434\u0435\u043b\u044c
\u043c\u0435\u0441\u044f\u0446 \u043c\u0435\u0441\u044f\u0446\u0430 \u043c\u0435\u0441\u044f\u0446\u0435\u0432 \u0433\u043e\u0434 \u0433\u043e\u0434\u0430 \u043b\u0435\u0442
B KB MB GB TB KiB MiB GiB TiB \u0431\u0430\u0439\u0442 \u0431\u0430\u0439\u0442\u0430 \u0431\u0430\u0439\u0442\u043e\u0432 \u041a\u0411 \u041c\u0411 \u0413\u0411 \u0422\u0411
mm cm m km mg g kg t \u043c\u043c \u0441\u043c \u043c \u043a\u043c \u043c\u0433 \u0433 \u043a\u0433 \u0442
°C °F \u0448\u0442 \u0448\u0442. pcs
rub rub. \u0440\u0443\u0431 \u0440\u0443\u0431. \u0440\u0443\u0431\u043b\u044c \u0440\u0443\u0431\u043b\u044f \u0440\u0443\u0431\u043b\u0435\u0439 dollar dollars euro
\u044f\u043d\u0432\u0430\u0440\u044c \u044f\u043d\u0432\u0430\u0440\u044f \u0444\u0435\u0432\u0440\u0430\u043b\u044c \u0444\u0435\u0432\u0440\u0430\u043b\u044f \u043c\u0430\u0440\u0442 \u043c\u0430\u0440\u0442\u0430 \u0430\u043f\u0440\u0435\u043b\u044c \u0430\u043f\u0440\u0435\u043b\u044f \u043c\u0430\u0439 \u043c\u0430\u044f \u0438\u044e\u043d\u044c \u0438\u044e\u043d\u044f
\u0438\u044e\u043b\u044c \u0438\u044e\u043b\u044f \u0430\u0432\u0433\u0443\u0441\u0442 \u0430\u0432\u0433\u0443\u0441\u0442\u0430 \u0441\u0435\u043d\u0442\u044f\u0431\u0440\u044c \u0441\u0435\u043d\u0442\u044f\u0431\u0440\u044f \u043e\u043a\u0442\u044f\u0431\u0440\u044c \u043e\u043a\u0442\u044f\u0431\u0440\u044f \u043d\u043e\u044f\u0431\u0440\u044c \u043d\u043e\u044f\u0431\u0440\u044f
\u0434\u0435\u043a\u0430\u0431\u0440\u044c \u0434\u0435\u043a\u0430\u0431\u0440\u044f jan january feb february mar march apr april may jun june
jul july aug august sep sept september oct october nov november dec december
```

Classification deterministic: currency code/symbol/word → `CURRENCY`; `%/‰` → `PERCENT`; month token or base span with `:`, `/`, `T` or at least two date separators `.`/`-` → `DATE_TIME`; other unit → `VALUE_WITH_UNIT`; otherwise `NUMBER`. This order is used in case of overlap.

Changing the lexer/dictionary creates a new version, rather than silently modifying `numeric-validator-v1`.

## 2. Support Verification

Version 1.0 is intentionally conservative: a literal FACT is considered supported only if its exact canonical byte sequence is present in full within at least one `cited_excerpt` of that specific FACT. Whitespace has already been normalized `text-v1`; no translation is performed between formats, locales, currencies, time zones, and units. The semantic verifier must separately confirm that the found literal belongs to the same entity and meaning, and not merely appears nearby.

For example, evidence `15 \u0438\u044e\u043b\u044f` does not allow claim `16 \u0438\u044e\u043b\u044f`; `$1,000` does not allow `1000 USD`; `0,5` does not allow `50%`. The Generator must preserve the source form or not publish the FACT.

For supported FACT literal `citation_numbers` contains all citations of this FACT, where exact bytes are found, in ascending order. If the list is empty, the literal is moved to `unsupported_literals` with `NOT_IN_CITED_EXCERPT`. If number and recognized unit/currency or parts of compound date split are in different excerpts, compound exact match is absent and reason equals `INCOMPLETE_VALUE_UNIT`. Terminal validator repeats lexer and search itself; an array of saved output is not an authority.

INFERENCE does not search for numbers across a global set of answer citations. For it, the validator constructs allowed evidence only from **immediate** `supporting_claim_ids`. Each supporting claim must be a FACT, have `SUPPORTED` ClaimVerification, and its own `numeric-validator-v1 = PASSED`; its published citations exact-match verification evidence. A literal INFERENCE must entirely exact-match the literal/text of at least one such supporting FACT and be entirely present within a single citation of that FACT. Transitive claims, adjacent citations, and evidence from another FACT are prohibited. In deterministic output, INFERENCE `citation_numbers` contains only the numbers of the suitable citations of these supporting FACTs; this is the provenance of the verification and does not turn INFERENCE into a source Fact in the renderer.

## 3. Computations

Sum, difference, ratio, rounding, currency conversion, unit conversion, and timezone conversion are considered new assertions. In 1.0, the deterministic calculator component is absent, so such a FACT cannot obtain `SUPPORTED` if the final literal is not verbatim present in the cited evidence. The model does not perform arithmetic on behalf of the validator.

Extractive Question Run has a single limited exception for PostgreSQL business-object snapshot: `\u0441\u043a\u043e\u043b\u044c\u043a\u043e`/`\u0438\u0442\u043e\u0433\u043e` can sum only numeric `POSTGRESQL_QUERY_CELL` of one declared column. If the question contains a date (`\u0441\u0435\u0433\u043e\u0434\u043d\u044f`/`\u0432\u0447\u0435\u0440\u0430` or English equivalent), the same immutable row/version must have an Evidence cell with an exact ISO day; rows without it are discarded. Text label (`stream = \u043e\u0442\u0445\u043e\u0434\u043e\u0432`) merely selects row context and is not included in the sum. Multiple numeric columns, different row/version/lineage, or absence of date Evidence yield a standard extractive/`INSUFFICIENT_EVIDENCE` result — aggregation is not guessed. Each numeric cell remains a separate citation; the total does not replace them and is not revealed without the current Evidence policy gate.

## 4. Terminal gate

The terminal validator retrieves exact claim bytes and exact cited excerpts from trusted storage, re-extracts literals using profile `numeric-validator-v1`, and forms a deterministic result:

```text
claim_id
validator_version = numeric-validator-v1
validation_input_hash
material_literals[]
unsupported_literals[]
outcome = PASSED | FAILED
```

The result passes `numeric-validator-output.schema.json`, is stored immutable alongside `ClaimVerification`; the output hash is included in the Answer Manifest. `validation_input_hash` is the exact-match verification input. For FACT/INFERENCE with `FAILED`, terminal commit is forbidden. This generation attempt becomes unselected: the system regenerates a bounded number of times or creates a new exact insufficient plan. Silent removal from the selected plan is forbidden.

`INFERENCE` does not receive a hidden grace: its numbers must already be present in one directly supporting FACT in the same exact form, and this FACT must have `PASSED` deterministic record. A newly calculated number requires a future versioned calculator contract.

## 5. Mandatory golden/negative cases

Golden vectors record one indivisible span and exact UTF-8 byte offsets for compound `15 \u0438\u044e\u043b\u044f 2026` and `July 15, 2026`, as well as offsets/class/order for `−12,5%`, `$1,000`, `1000 USD`, `2026-07-14T10:42`, `v2.3`, `ALPHA-291`, `0xFF`, NBSP/NNBSP and repeated literals. Negative fixture forbids collecting `15 \u0438\u044e\u043b\u044f 2026` from citation A=`15 \u0438\u044e\u043b\u044f 2025` and citation B with a separate `2026`. Separate negative fixtures forbid confirming a numeric INFERENCE from another citation or a number that appears in the direct FACT citation but is absent from the canonical text/PASSED material literals of the FACT itself.

- changed digit, sign, percentage, currency, or unit;
- date/time with a different value;
- number found only in unquoted context;
- number and unit separated across different evidence;
- arithmetic result present only in model text;
- validator result relates to a different claim hash or citation set;
- validator version change without regression suite.
