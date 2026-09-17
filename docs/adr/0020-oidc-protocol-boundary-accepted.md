# ADR-0020: Isolated OIDC protocol boundary

Status: accepted.

`internal/platform/oidc` is the only package permitted to import `go-oidc`,
`go-jose` or `oauth2`. It constructs Authorization Code requests with exactly
the `openid` scope, S256 PKCE and a nonce. The package generates 256-bit
state, nonce, PKCE verifier and browser-binding material from the operating
system CSPRNG; only domain-separated keyed HMAC digests are passed to the
identity repository.

OIDC discovery is accepted only for HTTPS issuer and endpoint URLs. ID-token
verification uses the reviewed `go-oidc` verifier with an exact client ID and
the signing-algorithm allowlist from the provider revision. The adapter also
checks the nonce in constant time and returns only a digest of the OIDC
subject and token expiry. Authorization codes, ID/access/refresh tokens and
client secrets remain transient and are never returned or persisted.

The identity repository exposes a revision-bound configuration projection,
including an opaque client-secret reference. The actual secret resolver and
HTTP login/callback routes remain separate future slices. A `BeginLogin`
request must carry the exact provider revision used for discovery, preventing
configuration changes from being mixed with a previously discovered endpoint.
