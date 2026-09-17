# ADR-0041: Purpose-typed mounted key capabilities

Status: accepted.

The mounted-secret boundary exposes three deliberately non-convertible
capability types: `IdentityKey`, `SessionKey` and `OIDCTransportKey`. There is
no generic `KeyMaterial` type. Identity and session capabilities expose only a
reference, version and temporary byte copy; the transport capability exposes
only a reference, key ID and temporary byte copy. This makes swapping identity,
session and browser-transport rotation domains a compile-time composition
error rather than a convention.

Each Provider accessor creates a local owner with its own copied 32-byte key.
Copies of that capability share one lifecycle state. Calling `Clear` on any
copy zeroizes the local key, clears its metadata and makes every copy fail
closed. `Bytes` always returns a new copy, which production composition must
clear immediately after the crypto constructor returns. The Provider retains
its separate source material until `Provider.Close`, allowing a cleared local
capability to have no effect on later legitimate provider access.

Zero-value, cleared and typed-nil capability state returns no metadata or key
bytes. Formatting is redacted for value and pointer forms. Provider close and
local capability clear are independently idempotent and race-safe. Production
composition is the only runtime package allowed to import the mounted-secret
capability boundary.

No third-party dependency is introduced.
