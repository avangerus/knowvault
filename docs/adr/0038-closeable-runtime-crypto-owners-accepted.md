# ADR-0038: Closeable runtime cryptographic owners

Status: accepted.

Production composition owns two long-lived cryptographic rotation domains:
the identity/session HMAC digestors and the OIDC browser-transport AES key.
Both are copy-safe opaque handles over private shared lifecycle state. Copying
a handle cannot copy a mutex, retain an independent key, bypass redacted
formatting or escape a later close.

`HMACDigestor.Close` waits for in-flight digest operations, marks every handle
closed and zeroizes the retained HMAC key. Closed and zero-value handles fail
closed and expose a zero fingerprint. `Codec.Close` similarly waits for active
Seal/Open operations and zeroizes its retained AES-256 key. The codec does not
retain a `cipher.AEAD`: it creates an operation-local AES-GCM instance while
holding the shared read lock and clears addressable plaintext, ciphertext,
nonce and AAD buffers. Go does not expose the implementation's temporary AES
expanded schedule for deterministic erasure; the process retains no reusable
schedule and operating-system process teardown remains the final memory
boundary.

All-zero keys are rejected independently of the mounted-secret provider.
Callers still clear the temporary byte slices returned by `KeyMaterial.Bytes`
immediately after construction. Normal shutdown must first quiesce HTTP, then
close the OIDC HTTP client's idle connections, the database, codec and
digestors, and finally the mounted-secret provider. This ADR provides the
closeable owners but does not yet authorize listener composition.

Static OIDC provider metadata is checked before discovery through
`ValidateProviderConfiguration`, which applies the same content-free admission
rules as the protocol boundary. The HTTP server's fixed graceful-shutdown
profile is 75 seconds so its future runtime owner can drain the maximum
standard verified-answer response window before closing cryptographic state.

No third-party dependency is introduced.
