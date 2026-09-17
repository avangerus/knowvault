# Security policy

KnowVault handles company documents, source metadata, service credentials, and
access-controlled evidence. Tenant isolation, authorization, session handling,
parser isolation, integrity, and audit failures are security-sensitive.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/avangerus/knowvault/security/advisories/new)
when it is available for this repository. Do not disclose an unpatched
vulnerability in a public issue or pull request.

If the private reporting form is unavailable, use an existing private channel
with the repository maintainer. If no private channel has been established,
open an issue requesting a private contact **without including vulnerability
details**.

Include:

- The affected commit or release and deployment configuration.
- The expected access boundary and the observed behavior.
- Minimal reproduction steps using synthetic data.
- The likely impact and any mitigations you have verified.
- A safe way to contact you for follow-up.

Remove access codes, passwords, private keys, customer records, and identifying
log content before sharing a report. A small sanitized trace is more useful
than a full production log.

## Release support

KnowVault is in pilot development. There is no published long-term-support
schedule or guaranteed response time. Maintainers assess reports against the
current code and identify affected revisions as part of the fix. Pilot status
does not reduce the importance of a security report.

## Security boundaries

- Workspace permissions are checked when tools return data, including reads of
  a known source address. Possessing a link does not grant access.
- Service access codes are scoped, expire, and can be revoked. They are separate
  from human browser sessions.
- PostgreSQL row-level security provides an additional tenant boundary.
- Search indexes and the browser are not authorization authorities.
- Source and parser inputs are untrusted. Data-return paths must preserve
  authorization, bounded processing, integrity checks, and audit.
- Source credentials and trust material are operator-managed runtime inputs.
  They must not be committed or embedded in distributed images.

These are system requirements, not a claim of independent certification. See
[Trust boundary](docs/TRUST_BOUNDARY.md), [Encryption](docs/ENCRYPTION.md), and
[Deployment](docs/DEPLOYMENT.md) for the detailed contracts. The development
Compose stack is not a production security baseline.

## If a credential is exposed

Revoke or rotate it with the system owner promptly. Preserve minimal sanitized
facts for investigation, and check related build artifacts and attachments.
Coordinate any repository-history cleanup with maintainers; removing a file
from the latest commit does not remove earlier copies.

Fixes should include a regression case proving the old path no longer works.
Maintainers coordinate the affected revisions, remediation guidance, and public
disclosure when a report is ready to be published.
