# ADR-0036: Production PostgreSQL constructor

Status: accepted.

Production server composition must use `database.OpenProduction`; the existing
`Open` remains limited to local and integration environments until their
database fixtures provide TLS. Migration jobs use a separate role and workflow.

The database URL has already crossed the mounted-secret boundary, but pgx also
implements libpq environment defaults. The database package records whether
any defined `PG*` variable existed during package initialization and repeats
the check against `os.Environ` immediately before parsing. Empty values and
case variants are denied too. Production composition is a single-threaded,
pre-listener startup phase in which process environment is immutable;
in-process hostile code is outside this threat model. Within that assumption,
the init bit prevents removal from laundering a contaminated startup and the
live check rejects additions made before pgx parsing. Exact post-parse checks
still reject any target, fallback, runtime-parameter or TLS dilution.

Before pgx parsing, the URL is required to be one canonical `postgres` URL with
an explicit non-IP lowercase DNS host and port, non-empty user, password and
database, and the exact query `sslmode=verify-full`. Socket targets, service
files, multiple hosts, fallback parameters and arbitrary runtime parameters
are outside the production contract.

After parsing and before a network call, the constructor exact-matches host,
port, database, user and password to the canonical URL. TLS must be present,
must perform certificate and hostname verification for that exact host, and
must not install a custom verification callback. Fallbacks and `RuntimeParams`
must both be empty. Only after this check does the package add the fixed
`application_name`, pool bounds and runtime-role verification hook.

This ADR does not choose the production CA artifact. The server image or
deployment must provide a separately reviewed trust bundle before production
composition is enabled. No third-party dependency is introduced.
