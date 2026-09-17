# ADR-0046: Encrypted artifact and ordered outbox foundation

Status: accepted.

Migration `000005` introduces two data-plane foundations without enabling an
ingestion or OpenSearch worker.

`encrypted_artifact` is the only PostgreSQL envelope store for sensitive,
non-searchable derived payloads. Its AAD owner tuple is a closed 26-branch map
identical to `encrypted-artifact-aad-v1`: organization, owning table and column,
resource type and ID, field and schema version are not caller-selected during
decrypt. The runtime may SELECT and INSERT but cannot UPDATE or DELETE.

Plaintext size is 1 through 8 MiB and AES-256-GCM ciphertext length is exactly
plaintext size plus the 16-byte tag. Nonce is exactly 12 bytes and wrapped DEK
is 1 through 64 KiB. Content purge is privileged and one-way: ciphertext and
wrapped DEK are removed, while hashes, AAD identity and nonce remain. Retaining
nonce and hashes preserves purge provenance without retaining decryptable
content. Nonce uniqueness is enforced across the whole
tenant KEK reference/version and does not trust the supplied wrapped-DEK hash.
Hard delete is permitted only after content
purge while the organization is `DELETING` or `DELETED`.

The outbox is one tenant-local ordered stream. Every event, aggregate and
payload reference is a server-generated typed-prefix canonical ULID; display
labels and source-native identifiers are not valid references. A transactional row-locked head
assigns contiguous sequence numbers; rollback reverts both event and head, so
identity/sequence generators and gaps are forbidden. Event payload is a bounded
closed reference/hash/fence object and cannot contain text, ciphertext, paths,
titles, raw ACL principals or secrets. Semantic event fields are append-only.
Acknowledgement can advance only from sequence N to N+1 and PostgreSQL replaces
caller time with `transaction_timestamp()`.

The shared `knowvault_app` role can enqueue and read events but cannot update or
delete events or mutate the head. Therefore `000005` is not yet a production
delivery engine. No outbox applier may be composed until a dedicated worker
role plus head-only lease/CAS, bounded retry, poison/dead-letter and idempotent
external-effect contract is implemented and accepted. Silent skip is forbidden.

This migration installs the closed encrypted-owner inventory ahead of most
owning relations. It is a storage foundation, not permission to compose an
artifact repository. Each owning relation must add its tenant-bound composite
foreign key (or an accepted deferred exact-owner validator) before application
code may persist or disclose that artifact field. Orphan artifacts are not an
accepted production state.

No new runtime component or dependency is introduced; PostgreSQL remains the
accepted outbox store and all licenses remain unchanged.
