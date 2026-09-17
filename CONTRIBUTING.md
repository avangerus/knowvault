# Contributing to KnowVault

KnowVault connects AI agents to company knowledge with permissions, versioned
sources, and audit. Contributions should make that workflow easier to use and
verify. Start with the [documentation map](docs/README.md) and
[current pilot scope](docs/PILOT-STATUS.md).

## Propose a change

Use a [bug report or feature request](https://github.com/avangerus/knowvault/issues/new/choose)
to describe the user problem, expected behavior, and a small reproducible
example. For a substantial feature or new dependency, agree on the scope with a
maintainer before implementing it. Existing designs are not a commitment to
include every capability in the pilot.

Report vulnerabilities privately using the [security policy](SECURITY.md).
Never include customer documents, access codes, credentials, or production logs
in an issue, pull request, or test fixture. Use synthetic examples.

## Develop and verify

1. Find the existing API, contract, and package responsible for the behavior.
2. Keep the change focused. Preserve workspace boundaries, complete reads,
   immutable source addresses, and audit before data is returned.
3. Add meaningful regression tests for changed behavior. Authorization,
   integrity, and failure handling need negative cases as well as successful ones.
4. Follow [Testing](docs/TESTING.md) for the pinned toolchain and relevant checks.
5. Explain the user-visible result, verification, and remaining limitations in
   the pull request.

The Go toolchain is pinned in [architecture/versions.json](architecture/versions.json).
Use `GOTOOLCHAIN=local` and `GOEXPERIMENT=jsonv2`. A typical Go change uses:

```bash
export GOTOOLCHAIN=local
export GOEXPERIMENT=jsonv2
go run ./scripts/check-architecture.go
go test -mod=readonly -run '^$' ./...
go test -mod=readonly -count=1 ./internal/... ./scripts/... ./tests/contracts/runner ./tests/integration/sandboxdispatch
go vet ./...
```

Database integration tests require an isolated PostgreSQL instance and the
prerequisites in the testing guide. Never point tests at a customer database.
Use the repository's pinned Node/pnpm workflow for web changes; do not replace
the package manager or refresh dependencies incidentally.

## Architecture and documentation

Contracts and accepted decisions live in [architecture/](architecture/) and
[docs/adr/](docs/adr/README.md). An API, persistence, trust-boundary, licensing,
or deployment change may require an ADR and corresponding contract updates.
Use the [ADR template](docs/adr/TEMPLATE.md) and identify the affected invariant.
Ordinary wording corrections do not need a new architectural decision.

The architecture check includes protected-file hashes. A protected change must
be reviewed together with its specific registry updates. Do not refresh the
whole baseline to make an unexplained failure disappear.

Keep public documentation in English. Clearly distinguish implemented behavior,
observed test results, and planned work. A mockup or contract does not establish
that a capability works in a deployed system.

## Pull request checklist

- The problem and final behavior are clear.
- Relevant checks passed, or failures and their scope are recorded explicitly.
- Changed contracts and user documentation are up to date.
- No generated caches, runtime state, credentials, or customer data are included.
- Built web assets, when changed, match the source and build process.
- New dependencies comply with [the dependency license policy](architecture/licenses.yaml).

KnowVault is licensed under [Apache License 2.0](LICENSE). Submitted contributions
are intended to be distributed under that license unless explicitly agreed
otherwise with the maintainers.
