# ADR-0015: Stage 1 OIDC dependency lock

Status: accepted.

Stage 1 supports only corporate OIDC Authorization Code Flow with PKCE S256.
Implicit flow, hybrid flow, token exchange, password grants, client-credentials
authentication for people, SAML and SCIM are not implementation scope here.

`github.com/coreos/go-oidc/v3` is the sole approved library for discovery,
JWK-backed ID-token verification and issuer/audience validation. The server
uses `golang.org/x/oauth2` only for the authorization-code exchange and PKCE
flow. `github.com/go-jose/go-jose/v4` and
`cloud.google.com/go/compute/metadata` are reviewed transitive dependencies.
Their exact versions, checksums, source commits and permissive licenses are
recorded in the closed version and license inventories before application code
imports them.

No hand-rolled JWT, JWK, signature, discovery or token-verification code is
allowed. OIDC, JOSE and OAuth2 imports are permitted only inside
`internal/platform/oidc`; business modules receive only a verified,
token-free identity assertion. Provider configuration, external identity
mapping, login transaction state, opaque server-side sessions and revocation
are separate persistence work and are not implied by this lock.
