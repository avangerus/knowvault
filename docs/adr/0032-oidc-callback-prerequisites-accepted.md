# ADR-0032: Pinned OIDC callback prerequisites

Status: accepted.

Before an HTTP callback boundary can be composed, the identity repository must
load the exact pending login and immutable provider revision represented by the
authenticated browser record. `LoadPendingLoginConfiguration` therefore uses
one tenant-scoped read and requires organization, provider, provider revision,
login attempt ID, PENDING/unexpired state and exact state, browser-binding,
nonce and PKCE-verifier digests. It returns the configuration only while the
provider remains ACTIVE and its current revision is the attempt revision.

`CompleteLogin` repeats every proof and provider-revision check in the atomic
claim statement. The statement also requires the provider to remain ACTIVE and
current. Session creation, attempt consumption and the audit event remain one
transaction. A preliminary successful read is never authority for completion;
replay or a configuration change must still fail at the write gate.

An authenticated sealed record can restore an `oidc.Attempt` by re-deriving
all four digests through the deployment identity key. Fresh and restored
attempts have different private provenance: a restored callback attempt can be
used for token exchange but `TransportMaterial` refuses to release it for a
new seal. Callback state comparison is constant time.

`oidctransport.BrowserTransport` is the only reviewed HTTP projection for the
sealed cookie. Issuance fixes `__Host-knowvault_oidc`, Secure, HttpOnly,
SameSite=Lax, Path=/, no Domain and an expiry no later than the 15-minute
record. Reading requires exactly one raw Cookie header, strict
`http.ParseCookie`, no quoted values and exactly one transport cookie; malformed
siblings, duplicates and oversized headers fail closed. Clearing emits the
same host-only profile with deletion expiry and `Max-Age=-1`.

This ADR still does not add `/auth/login`, `/auth/callback` or any
`cmd/server` composition. The following HTTP ADR must additionally require an
exact redirect URI derived from trusted public origin, strict query parsing,
an ephemeral client-secret resolver, a hardened injected OIDC HTTP client,
CSPRNG IDs, generic no-store errors, unconditional transport-cookie clearing
and session-cookie issuance only after successful atomic `CompleteLogin`.
