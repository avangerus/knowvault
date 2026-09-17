# ADR-0048: Source discovery and scope DRAFT checkpoint

Status: accepted.

Migration `000007` extends the source control plane with trusted discovery rows,
scope lineage, immutable scope revisions and an initial activation projection.
It is a storage checkpoint only. Every scope and activation remains `DRAFT`,
every `active_revision` remains `NULL`, and no connector job, content event,
workspace binding, ingestion, catalog, retrieval or query path may use it.

A discovered scope belongs to one exact source-connection revision and type.
Its raw provider identity and display metadata remain encrypted artifacts. The
relational row stores only generated internal IDs, an explicit keyed-digest
version, the HMAC identity digest, plaintext integrity hashes and exact artifact
references. Both artifacts must have the accepted owner/type/field/resource ID,
matching plaintext hash and non-purged state when the row is created. A label,
caller-supplied external ID, digest from another key version, connection or
revision never authorizes a scope.

`SourceScopeRevision` binds one exact tuple: organization, source-scope and
revision, connection and immutable connection revision, discovered-scope ID,
identity digest and digest-key version, source type, encrypted canonical scope
configuration and its hash, access mode, freshness settings and limits. The
scope-config artifact must exactly own that revision and match its plaintext
hash. Requested access mode and limits must be a subset of the referenced
connection revision. `SOURCE_ENFORCED` additionally requires the exact verified
capability profile to declare stable object identity, item-level ACL and ACL
refresh support. These checks validate a draft; they do not activate it.

The parent `latest_revision` is management lineage only and is checked by a
deferred exact validator rather than a reverse foreign key. The independent
`active_revision` is constrained to `NULL`. An activation row can only be
created in `DRAFT`; transitions to `SYNCING`, `READY`, `REVOKED` or `FAILED`
remain unavailable until a later checkpoint introduces full scan, signed job
and event, workspace-binding/confirmation and audit gates together.

Rows are tenant-isolated with forced RLS. The shared application role receives
read-only access and cannot call privileged validation helpers. Configuration,
discovery identity and activation records are immutable in this checkpoint;
hard deletion is available only during tenant deletion and must follow the
forward-FK order without circular references.

Artifact purge or digest-key retirement can leave a historically valid DRAFT
chain in storage, but cannot create authority because no active pointer or
query path exists. Every future activation and use gate must re-check current
artifact non-purged state, digest-key validity, discovery lifecycle, connection
trust and the complete exact tuple. This requirement cannot be satisfied by the
insert-time constraint triggers alone.

No new runtime component, dependency or license is introduced by this decision.
