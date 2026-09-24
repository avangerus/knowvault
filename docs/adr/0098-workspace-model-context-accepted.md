# ADR-0098 — Workspace model context: explicit glossary, rules and source notes

**Status:** accepted on 2026-09-24.

**Provenance:** product direction set by the owner on 2026-09-24; architecture
decision taken by the release lead under the owner's explicit delegation
(constitution §9, item 4). Verbatim statements are kept in the private project
record.

**Date:** 2026-09-24

**Related:** ADR-0097, PRODUCT_CONSTITUTION §3, §4, §6.1 and §7.

## Context

Answers over customer data depend on the customer's language. Examples:
abbreviations, synonyms, which table holds which business object, what
«active» means, which time zone defines a business day. Nothing in a database
schema without comments says this, and today the only place for it is an
ordinary document that the model may or may not find.

The constitution forbids hidden long-term model memory and treating earlier
answers as evidence. A place for workspace language must therefore be
explicit, visible, versioned, governed by rights and audited. It must never
become evidence and never change the system rules.

## Decision

1. **WorkspaceModelContext.** Each workspace carries an explicit, versioned
   WorkspaceModelContext:
   - description;
   - answer rules;
   - glossary: term, synonyms, definition, data locations;
   - notes for its sources, tables and columns.

   OWNER and MANAGER may edit it. Members and scoped service principals may
   read it. Every revision is immutable and audited without content.
2. **Delivery to the model.**
   - It is rendered verbatim, JSON-escaped and delimited, after the fixed
     system instructions of the built-in chat. The same rendering is offered
     to MCP clients in `initialize` instructions and through the
     `knowvault_workspace_context` tool.
   - It may shape terminology and presentation only.
3. **Not evidence, not a new capability.**
   - Claims still bind only to tool reads made in the current turn.
   - The tool catalog, read-only transactions and authorization are
     unaffected by its content.
   - Notes may reference only sources enabled in the workspace and columns
     that are not excluded.
4. **Proposals.**
   - The system may derive PROPOSED glossary changes from completed question
     runs with deterministic heuristics: an unknown abbreviation the model
     resolved to a known term, an explicit correction, a repeated unknown
     term.
   - A proposal takes effect only after an explicit, audited decision by
     OWNER or MANAGER.
   - A proposal's text is shown only to managers who can currently read at
     least one of its source runs. It is erased when those conversations are
     purged.
5. **This is visible workspace configuration, not hidden model memory.** The
   UI gains a Settings section for it.

## Alternatives considered

| Option | Why it was not selected |
| --- | --- |
| Keep terminology in ordinary documents only | Retrieval may miss them; no structure for synonyms or data locations; no review queue. |
| Let the model learn silently from conversations | Hidden memory; forbidden by the constitution and impossible to audit. |
| Use a model to generate proposals from chats now | Cost and non-determinism; deferred to the knowledge stage, which will reuse the same review queue. |

## Consequences

- Administrators teach a workspace its language in one place. The chat and
  external agents see the same context.
- Context size is bounded: 16 KiB rendered, with truncation priority
  description, rules, matched terms, other terms, source notes.
- Tests must prove escaping, isolation, rights, audit, parity between the
  chat and MCP, and that a rule such as «ignore citations» changes nothing.
