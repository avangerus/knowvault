# KnowVault release path

The source of product authority is the owner's 12 September 2026 canon, kept
in the private handoff archive. The earlier [ADR-0096](../adr/0096-read-only-conversational-analytics-authority-withdrawn.md)
was never approved by the owner and does not amend that canon.

KnowVault is a read-only enterprise knowledge tool. An authorized employee
asks about company data in the web chat or through an external MCP agent. The
model chooses workspace-scoped KnowVault tools, reads the returned data,
performs simple reasoning, and answers with inspectable source addresses.
KnowVault supplies complete, paginated data, permissions, audit, versions and
source identity; it does not substitute a fixed-operation planner or a closed
business-intent catalogue for the model's interpretation. Structured reads and
reviewed checks can be tools, but are not the default question interface.

The release is accepted only when these user-visible outcomes are true:

1. In the web interface, a user can hold a multi-turn conversation over
   KnowVault data. The model selects and calls the same read-only knowledge
   tools exposed to an external agent by MCP, then answers with source
   addresses.
2. During a turn, the interface shows each real action as it happens: the
   requested tool, its safe arguments, its outcome and the emerging answer.
   A long turn is not a silent wait.
3. A live Cicada demonstration shows a document question; “How many tasks were
   assigned on 10 September 2026?” with the observed value 3,888 and Moscow
   date; and a follow-up that uses the previous answer. A screen recording or
   screenshots of the live interface are the acceptance evidence.
4. That demonstration runs from a commit contained in `origin/main`.
5. The owner's I1–I10 invariants hold in web chat and MCP: evidence or an
   unconfirmed label, answer language, current versions, workspace terms,
   justified numbers, honest no-data and out-of-scope outcomes, resistance to
   injection and destructive requests, workspace isolation, and surface
   parity. Tools only read source data.
6. Product documents describe owner decisions truthfully. Any departure from
   the 12 September canon is proposed to the owner before it is recorded as
   accepted.

The immediate delivery order is to use the existing model-over-tools loop,
restore the real document source, make its actions visible in the browser,
run the three Cicada questions, and merge that exact working revision to
`main`. Work that does not change one of those observed behaviors waits.
