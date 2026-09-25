# ADR-0099 — The kind of answer is recognised by meaning, not by word lists

**Status:** accepted

**Date:** 2026-09-25

**Owners:** release lead

**Related:** ADR-0097 (workspace source tools), `internal/question/tool_loop.go`,
`internal/question/tool_loop_overview.go`, question set `tests/e2e/questions/`

## Context

A question gets one of two kinds of answer: a short one (an overview of the
workspace or its sources, what the database holds in business words, whether a
document changed, a hypothetical, an off-topic question, a vague request that
needs one clarifying question) or the full tool loop (real reading, counting,
citing).

Five consecutive changes chose the kind with lists of words and stems matched
against the user's question. Every independent acceptance then found ordinary
phrasings the lists missed — a different verb form, a synonym, an English
wording — and those questions fell back to the long answer that retells
documents and lists tables, the exact behaviour the owner rejected. Hidden
reworded runs showed the same (a reworded «did the regulation change?» and a
reworded vague request stayed red while the visible wording was green). Each
fix lengthened the lists; the class of defect did not close.

## Decision

1. The kind of answer is decided by the meaning of the question, not by which
   words it contains. Server code does not branch on words, stems or regular
   expressions over the user's question text to choose the kind of answer.
2. What the server keeps deciding deterministically is what does not depend on
   wording: step and length limits, suppression of an identical repeated tool
   call, stub prevention, citation verification, language of service texts,
   access and SQL safety.
3. Recognition by meaning is proven only by runs of the real model: the
   visible question set, the hidden reworded set, and the acceptor's own new
   phrasings. A unit test over a list of phrasings does not prove it.

## Alternatives considered

| Option | Why it was not selected |
| --- | --- |
| Keep word lists and extend them per finding | Five rounds showed the class does not close; every acceptance finds new misses. |
| A separate embedding classifier | New dependency and model to operate; the answering model already reads the question and the workspace overview. |
| Always the full tool loop | Short questions become long reports again — the owner's original complaint. |

## Consequences

### Positive

- One mechanism for all short kinds; natural phrasings in any wording behave
  alike.
- Fewer returns on answer tasks: acceptance probes no longer find list gaps.

### Negative

- Recognition becomes stochastic; it is measured by runs (3 per question,
  visible and hidden), not by unit tests.
- Existing word-list code has to be removed or bypassed, which touches code
  several accepted tasks rely on; the question set guards against regression.
