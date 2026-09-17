# ADR-0031: AEAD-sealed OIDC browser transport

Status: accepted.

The OIDC callback needs the raw nonce and PKCE verifier, while the identity
repository deliberately persists only keyed digests. Version 1.0 therefore
uses one short-lived browser transport cookie named
`__Host-knowvault_oidc`. It is not a session, identity assertion, tenant
selector or durable store.

The cookie value is exactly
`v1.<kid>.<12-byte-nonce-base64url>.<ciphertext-base64url>` and is bounded to
2048 bytes. Its plaintext is a bounded, exact JCS `oidc-transport-v1` record
containing organization, provider and provider revision, login attempt ID,
raw state, nonce, PKCE verifier and browser binding, plus UTC issue and expiry
times. The maximum lifetime and plaintext size are 15 minutes and 1024 bytes.
Unknown or duplicate JSON members, invalid UTF-8, non-canonical JSON or
base64url, invalid OIDC material, future/expired records and oversized input
fail closed.

The envelope `kid` uses only the unpadded base64url segment alphabet and cannot
contain the `.` delimiter. The four raw OIDC values are pairwise distinct.
Production `Record` construction accepts only an opaque `oidc.Attempt` carrying
the private proof set by `NewSecureAttempt`; arbitrary strings and composite
literals cannot cross the exported sealing boundary. This prevents accidental
reuse of state as the PKCE verifier, which would expose the verifier in the
authorization URL.

AES-256-GCM authenticates both the record and canonical JCS AAD. The AAD is
`oidc-cookie-aad-v1` and binds the cookie name, deployment-trusted
organization, canonical public HTTPS origin and active key ID. Provider ID and
revision are inside the authenticated record and must exactly match the
deployment/provider configuration before callback completion.

The active `oidc_transport_aead` immutable KMS resource/version identity and
key-material fingerprint are both required to differ from the identity-digest
and browser-session selections. This prevents two aliases from silently
selecting the same material. The key also has a separate lifecycle from the
OIDC client secret. All server instances for one tenant receive the same active
key selection, so a login can start and finish on different instances. Version
1.0 accepts only one active key; rotation
intentionally invalidates pending login cookies without invalidating durable
external-subject mappings or established browser sessions.

Normal formatting and errors expose neither the key nor raw browser material.
The production codec obtains every GCM nonce from the operating-system CSPRNG.
The codec does not own HTTP parsing or cookie issuance. A later accepted ADR
must add strict single-cookie parsing, the exact Secure/HttpOnly/Path=/no
Domain/SameSite=Lax profile, callback state comparison, digest reconstruction,
atomic login completion and clearing the transport cookie on every callback
outcome before any auth route is composed into `cmd/server`.
