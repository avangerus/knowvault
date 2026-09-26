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

## Amendment 1 (2026-09-26)

**recognition is a separate step, not a paragraph of the answering prompt.**

Context. Two cards implemented decision 1 by adding kind paragraphs to the single answering
instruction (`toolLoopInstructions`). Each paragraph needed exclusion clauses in other rules, and
each change moved other questions: D-11 regressed H3, hidden H1, Q12 across three versions; D-13
did not converge after ~15 wording rounds (Q13 SQL-free 5/9, no fully green full run). Word-based
classes (greeting, overview, sources, comparison cue) also remained in server code.

Decision.
4. The kind of a question is recognised by meaning in a dedicated short model call that returns
   only the kind from a closed list; the answering call does not recognise kinds and its
   instruction carries no kind paragraphs or cross-kind exclusions. The default kind on doubt or
   error is the full tool loop.
5. Each kind has its own deterministic route: a server-rendered answer, or a kind-specific
   prompt with only the tools that kind needs. A rule of one kind never appears in another
   kind's prompt. Short kinds are never mounted with SQL or live-data tools.
6. The recognised kind is recorded in the run record and reported per run by the question set.
   Recognition is measured in bulk on real-model runs of phrasings (visible, hidden, acceptor's
   own), three runs each, against a stated threshold; routes and renderers are covered by
   deterministic tests. Decision 3 stands: a unit test over phrasings does not prove recognition.
7. The remaining word-based classes in server code (greeting, workspace overview, sources) move
   to the same recognition step; decision 1 is considered met only when none remain.

Alternatives considered. One growing instruction prompt — rejected on the evidence above:
each kind added made the others less reliable. Kind-specific answer tools in the single call —
keeps the competing rules and mounted SQL tools in one context; may be used inside the full
route later, not as the recognition mechanism.

Consequences. One extra short call per question (≈ +700 input tokens, ≈ +1 s); the answering
prompt shrinks by the kind paragraphs; a new kind is one definition plus one route, with no edit
to other routes; misrecognition becomes a single measurable event instead of a diffuse
regression.
