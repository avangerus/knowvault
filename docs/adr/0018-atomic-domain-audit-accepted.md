# ADR-0018: Atomic domain state and audit append

Status: accepted.

Any security-significant state transition must persist its required audit event
inside the same `database.Write` transaction. A second, best-effort audit call
after a business commit is forbidden: a process crash or transient audit
failure would make the outcome non-reproducible.

`audit.AppendInTransaction` receives the existing tenant-scoped transaction,
derives the audit chain sequence and hash there, and neither commits nor
retries it independently. The owning domain repository is responsible for a
bounded replay of the entire business transaction if PostgreSQL reports a
serialization conflict. Every transport boundary maps the resulting error to a
content-free code and never exposes a database cause.

The first consumer will be the identity repository: claiming an OIDC attempt,
creating an opaque session, consuming the attempt and recording
`identity.login` must become one commit. The same rule applies to session
revocation and future privileged workspace/source mutations.
