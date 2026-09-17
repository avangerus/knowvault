# Source Contracts 1.0

Status: `ACCEPTED`. This document defines the mandatory semantics for configuring five source types. Connector cannot declare scope `READY` if it is not capable of fulfilling its contract.

## 1. Connection, Scope and Revision

`SourceConnection` stores the type, endpoint, credential reference, trust settings, and capabilities. The credential is visible only to ConnectorAdmin; the workspace never receives it.

`SourceScopeRevision` — immutable limited slice of connection. Common fields:

```text
source_scope_id
revision
connection_id
connection_revision       exact immutable trust/capability/credential profile revision
discovered_scope_id       exact trusted discovery row
source_type              FOLDER | GIT | MAIL | SITE | POSTGRESQL_QUERY
discovered_identity_digest exact identity of that discovery row
access_mode              WORKSPACE_MANAGED | SOURCE_ENFORCED
scope_config
sync_interval_seconds
content_freshness_sla_seconds
acl_freshness_sla_seconds
object_limit
byte_limit
created_by
created_at
```

Changing any field creates a new immutable revision with a separate activation projection `DRAFT`. Parent `latest_revision` shows only management lineage; nullable `active_revision` is a separate authority and is always empty in `000006`. Scope exact-match references immutable `SourceConnectionRevision` and one discovery row by ID, identity digest, and connection/revision; raw external scope identity remains inside the encrypted canonical config. Mutable latest connection and display label are not used as authority. Changing credential/trust/build/capability/agent/limits creates a new connection revision, but switches nothing: old scopes remain bound to the previous revision and become `DEGRADED` upon revoke/expiry of its separate trust projection. Only an explicit audited revalidation/cutover after a full scan can select a new revision.

`scope_config` passes strict tagged schema validation against `source_type`; unknown fields are forbidden. The Connector receives a signed bounded job with exact connection ID+revision, capability profile/build, scope/revision/config hash, limits, and expiry. It may narrow the result due to deny/error, but it cannot expand the scope.

Raw `external_scope_id` is not a field of authority SourceScopeRevision. It is stored only inside the encrypted discovery/config payload, while authorization exact-match uses trusted `discovered_scope_id + discovered_identity_digest + connection_id + connection_revision`. For a Site where there is no native scope ID, the server computes the discovery identity digest from the canonical identity subset (connection ID, seed/sitemap, and allowed prefixes). A mismatch is rejected. General `object_limit` and `byte_limit` are the only aggregate limits; nested caps limit only one object/response and are always `<= byte_limit`.

`WORKSPACE_MANAGED` is an explicit data grant, not a fallback in the absence of ACL. Confirmation belongs not to reusable scope, but to exact workspace binding: organization, workspace and WorkspaceRevision, workspace binding, scope ID/revision, full `scope_config_hash`, actor, policy revision, `workspace-managed-risk-v1` warning and time. It is created only in checkpoint workspace binding. Prior to this, WORKSPACE_MANAGED revision may exist only as `DRAFT` snapshot and is not queryable. For `SOURCE_ENFORCED` confirmation is absent. Foreign, revoked, or belonging to another binding/revision/hash confirmation prohibits activation/query.

Migrations `000006` and `000007` create only safe DRAFT control plane: first connection revisions, then trusted discovery and scope revisions. They do not allow `SYNCING`, `READY`, query, content-bearing connector events, or jobs, and do not populate the active scope pointer. These transitions are opened only by a subsequent accepted checkpoint with full scan, activation, exact workspace binding/confirmation, signed-event, and audit gates.

Any content-bearing event must originate from a single stable read snapshot: object identity, external version, metadata, bytes, and content hash cannot be obtained from different states. The Connector records the available native version/identity before reading and re-verifies after the complete read; a mismatch means retry, and after the limit—quarantine, but not commit SourceVersion.

## 2. Folder and File Storage

Connection is set by the administrator:

```text
root_alias               opaque name of a pre-mounted root
root_identity            volume/share stable ID
platform                 WINDOWS | POSIX | S3_COMPATIBLE
credential_reference
read_only = true
allowed_access_modes
platform                  exact signed enum for FOLDER only
```

The user scope does not pass an absolute filesystem path. It selects only a path relative to `root_alias`:

```text
relative_root
path_matcher_version = scope-glob-v1
recursive
include_globs[]
exclude_globs[]
max_file_bytes
ocr_mode                 OFF | AUTO
follow_symlinks = false
formats[]                allowlist from Product Constitution
```

Rules:

- separator is reduced to `/`, strings are NFC; absolute path, empty segment, `.`, `..`, NUL and control characters are forbidden;
- each open is performed relative to an already opened root handle and after resolution, containment is rechecked; Windows reparse points/junctions and POSIX symlinks are not followed;
- for WINDOWS, additionally forbidden are `:`/NTFS alternate data streams, trailing dot/space, NT namespace/device prefixes and case-insensitive device names `CON`, `PRN`, `AUX`, `NUL`, `COM1..9`, `LPT1..9` with any extension;
- extension does not determine the parser: media type is verified by signature/structure, mismatch goes to quarantine;
- ZIP/archives, executable payload, password-protected content and embedded object extraction are forbidden in 1.0;
- Office macros, formulas, external links, OLE and active HTML are never executed; XLSX formula may be indexed as text together with the saved cached value, but is not computed;
- parser/OCR operate with CPU, memory, byte, page and time limits; expansion-ratio limit protects against decompression bomb;
- source binary exists only in ephemeral processing area, is not included in backup and is deleted after extraction or error;
- if native file ID/version are absent, version is determined by content hash, and rename/move is not considered proven identity without connector capability;
- local/SMB read holds open handle, verifies file identity, size and available native change/version token before and after reading; S3 uses exact `versionId` or conditional `If-Match` GET. ETag by itself is not considered content hash. Torn read does not create SourceVersion;
- `SOURCE_ENFORCED` is allowed only with stable user/group mapping and current item ACL. Otherwise scope must be explicit `WORKSPACE_MANAGED` grant.

## 3. Git

Connection sets the HTTPS provider/remote, immutable repository identity, credential reference, and TLS trust. SSH and protocol/file remotes are prohibited in 1.0; TLS verification is mandatory, and private PKI is specified only via an admin-managed CA reference. Scope:

```text
repository_id
branch_name
path_matcher_version = scope-glob-v1
include_paths[]
exclude_paths[]
max_blob_bytes
text_media_types[]
submodules = false
lfs_content = false
```

`branch_name` is selected only from the trusted discovered branch list and compiled by the server into the exact `refs/heads/<name>`. HEAD, tag, raw SHA, revision expression (`~`, `^`, `..`), refspec, wildcard, control, leading `-`, and an arbitrary ref from the request are prohibited. Each scan first resolves the branch to an exact commit SHA and processes a single tree of that commit. Logical SourceObject is `(connection, repository, branch, path)`, SourceVersion records the commit SHA and blob ID/hash. Citation always includes repository, commit SHA, path, and line range; subsequent branch movement does not change the old citation.

In 1.0, commit history, issues, pull requests, review comments, actions, submodules, and fetching Git LFS content are prohibited. The Connector does not run hooks, credential helpers, smudge/clean filters, build scripts, or a file from the repository. The Credential has only read scope. The Path undergoes the same traversal/NFC rules as the folder. Deleting the Path in a new commit closes only that object/version after reconciliation.

KnowVault implementation uses only the standard Go HTTPS transport and GitHub/GitLab API providers; system `git`, shell, hooks, runtime download, and unknown transitive libraries are prohibited. Before activation, the capability/version lock must be fixed with the exact provider API contract, build/artifact hash, and contract-suite hash, and the endpoint/credential/trust must undergo live qualification.

## 4. Email

Connection type:

```text
MICROSOFT_GRAPH | GMAIL_API | IMAP
```

Connection stores the provider tenant/host, immutable mailbox discovery context, read-only credential reference, and custom CA reference if necessary. Scope:

```text
mailbox_id
folder_or_label_ids[]
from_date
include_attachments
max_message_bytes
max_attachment_bytes
body_preference           PLAIN_THEN_SANITIZED_HTML
```

The SourceObject unit is a specific message with a provider-stable immutable ID; attachment is a separate object linked to message/MIME part. Microsoft Graph is always requested with `Prefer: IdType="ImmutableId"`, while changeKey/provider version is fixed separately; mutable default Graph ID is forbidden. Gmail uses a stable message ID. IMAP uses a tuple of mailbox/folder identity + UIDVALIDITY + UID. Thread is used only for context expansion, but citation points to the exact message or attachment.

Rules:

- OAuth/IMAP rights are read-only; send, draft, move, delete, flag, and subscription mutations are absent from the interface;
- IMAP reads through `BODY.PEEK` and does not set `\\Seen`; UID is used only together with UIDVALIDITY and mailbox/folder identity;
- remote images, styles, forms, scripts, and URLs from the HTML body are not loaded; HTML is converted to canonical text in a sandbox;
- MIME limits, nesting depth, attachment media sniffing, and file parser rules are mandatory;
- BCC/headers are indexed only if actually returned by the provider and allowed by the policy; the connector reconstructs nothing;
- the provider delta cursor is supplemented with reconciliation because move/delete/label semantics differ;
- `SOURCE_ENFORCED` is allowed only if the connector checks the specific internal user's access to the mailbox/item. Service-account access by itself implies `WORKSPACE_MANAGED`.

## 5. Website

Connection is created by an administrator:

```text
origin_allowlist[]
port_allowlist[]
network_zone             PUBLIC | ADMIN_APPROVED_PRIVATE
private_cidr_allowlist[]
credential_reference
custom_ca_reference
```

Scope:

```text
seed_urls[] | sitemap_url
allowed_url_prefixes[]
path_matcher_version = scope-glob-v1
include_patterns[]
exclude_patterns[]
max_depth
max_response_bytes
requests_per_second
max_redirects             0..5
query_policy             PRESERVE | DROP_TRACKING
respect_robots_txt = true
render_mode = HTML_ONLY
```

1.0 performs only `GET`/`HEAD` standard HTML. JavaScript/browser runtime, form submit, WebSocket, file upload, CAPTCHA bypass, and arbitrary authenticated browser session are not in scope.

SSRF gate is applied to seed, sitemap, each found link, and each redirect hop:

- only `http`/`https` are allowed; userinfo and fragment are forbidden;
- hostname/port must be present in the connection allowlist and scope prefix;
- DNS is re-resolved before connect, all IPs are checked; mixed allowed/denied answer results in deny;
- loopback, link-local, multicast, cloud metadata, and private ranges are forbidden for `PUBLIC`;
- a private address is accessible only via Connector Agent and an exact `ADMIN_APPROVED_PRIVATE` host/CIDR allowlist;
- redirect, DNS rebinding, and IPv4-in-IPv6 do not bypass the check;
- `allowed_url_prefixes` are compared only after canonical URL parsing: exact origin and either exact path or path-segment boundary; raw string `HasPrefix`, encoded separator bypass, and mixing query with path are forbidden;
- TLS verification cannot be disabled; private PKI is connected only via an admin-managed CA reference;
- cookies/auth header are not sent to another origin;
- redirect count is limited to `max_redirects`; content-type/time/rate/depth/page limits are checked before parsing;
- `max_response_bytes` applies to the decoded body, while the compressed stream has a separate compressed-byte and expansion-ratio limit;
- sitemap/XML parser forbids DTD, external entities, parameter entities, XInclude, and any network/file resolvers; XXE cannot bypass the SSRF gate.

Canonical URL and DOM/text anchor are defined in `CANONICALIZATION.md`. ETag/Last-Modified accelerate sync, but identity/version are confirmed by canonical URL and content hash. Links from retrieved evidence are never loaded by the model or Question Run.

## 6. Capability and access gate

Before checking `access_mode` server for **each** scope exact-match, it loads trusted `SourceConnectionRevision` and `ConnectorCapabilityProfile`:

```text
connection_id + connection_revision
connector_build_id
connector_version
connector_artifact_hash
capability_profile_id + capability_profile_hash
connector_agent_id + execution_target
connector_contract_suite_hash
verified_at
trust_record_id
trust_profile_hash
trust_projection.status = VERIFIED
allowed_access_modes
```

Build ID/type/version/artifact hash and capability-profile hash must match the connection revision, while the contract-suite hash must match the suite result of exactly that build. The Trust record exact-match links the same connection revision, execution target, and trust-profile hash; a record for a different target does not apply. `execution_target=CONNECTOR_AGENT` requires non-null exact `connector_agent_id`, and `CENTRAL_WORKER` requires `connector_agent_id = null`. For FOLDER `platform` (`WINDOWS | POSIX | S3_COMPATIBLE`), inclusion in signed `trust_profile_hash` is also required; an unknown or modified value means deny. Revocation/expiry affects only a separate monotonic trust projection; effective health of a dependent scope is computed as `DEGRADED`, but this is not a state and does not UPDATE immutable SourceScopeRevision or activation projection. This common trust gate is performed identically for `WORKSPACE_MANAGED` and `SOURCE_ENFORCED`.

Only after the general gate server compares the requested behavior with verified capabilities. Examples of fail-closed:

| Request | No capability | Result |
|---|---|---|
| SOURCE_ENFORCED | stable identity + ACL refresh | scope rejected |
| incremental sync | cursor/webhook | only full reconciliation with honest freshness SLA is allowed |
| native version link | historical version/deeplink | version snapshot/local locator is used, or scope rejected if exact citation is impossible |
| deletion events | delete signal | mandatory periodic reconciliation |
| local extraction | compatible signed agent profile | content is processed centrally or scope rejected policy |

Capability — not a self-declared boolean from request. It is bound to the exact connector build/version/artifact, passes the contract suite, and is stored in the trusted connection record. A foreign profile of the same connector type, a matching version string without artifact hash, or an incomplete record lacking suite hash/verified-at does not permit `READY`.

`access_mode` additionally intersects with trusted `connection.allowed_access_modes`. `SOURCE_ENFORCED` requires verified stable-identity + item-ACL + ACL-refresh capabilities exact connector build; a single numerical ACL SLA in scope is insufficient.

## 7. `scope-glob-v1`

Folder/Git/Site path patterns are executed by a single Go package server/connector and contract validator, compiled with exact Go 1.26.5. Any other glob engine is forbidden.

- input path NFC, separator `/`, relative; empty/`.`/`..` segment and backslash are forbidden;
- literal match, `*` = zero/more characters within a single segment, `?` = one Unicode code point within a segment;
- `**` is allowed only as a whole segment and means zero/more path segments;
- escape, `!` negation, braces, character classes, extglob, regex, `***` and trailing whitespace are forbidden;
- an empty include list means the entire selected root/prefix; any matching exclude has priority and cannot be returned by include;
- Git/S3/POSIX match is case-sensitive. WINDOWS match uses Unicode simple fold semantics pinned Go `strings.EqualFold`, but open still resolves relative to the root handle and returns the actual canonical case;
- maximum 128 include + 128 exclude, 4096 UTF-8 bytes per pattern, 256 segments; exceeding this results in a scope validation error;
- one call has a shared budget of 4 194 304 steps for include and exclude; exhausting the budget means fail closed, and a zero-value matcher is always invalid;
- Site matcher is applied only to the canonical URL path; origin/prefix/query undergo separate structural rules.

`path_matcher_version` is included in `scope_config_hash` as a regular field. Server and Connector Agent pass the same golden vectors; version mismatch blocks the signed job.

## 8. General source poka-yoke

1. Scope config cannot be changed in place.
2. A revision that fails validation does not become `READY`.
3. Connector job cannot expand root/repository/mailbox/origin.
4. SOURCE_ENFORCED is impossible without an enforceable ACL.
5. Unknown identity/ACL means deny.
6. Redirect, symlink, move, or overlapping scope do not change tenant/workspace boundary.
7. Active content is never executed.
8. A parser error for one object degrades sync health and remains visible.
9. Temporary unavailability is not considered proven deletion.
10. Deletion first closes queryability, then clears the index.
11. The original binary does not become a permanent artifact.
12. Any new connector dependency passes exact version, SBOM, and default-deny license gate.

## 9. PostgreSQL business-object projections

`POSTGRESQL_QUERY` is a first-class source type. Its full normative boundary is the accepted ADR-0078; this section includes ADRs by reference and intentionally does not create a second abbreviated contract. V1 allows only `WORKSPACE_MANAGED` structured projections over DBA-managed views exactly as per ADR-0078. SQL authoring/input, `SOURCE_ENFORCED`, write-back, base-table root, incremental/CDC mode, and `/execute-sql` surface are prohibited.

Each line crossing the source-agnostic observation boundary is also represented as a minimal business-object envelope: `entity_id`, `entity_version`, `last_updated_at`, canonical `payload`, `payload_format` (`JSON`, `TEXT` or `MARKDOWN`) and immutable source/projection provenance. In the current PG adapter `payload_format=JSON`, the payload is a canonical typed-row JSON; `VERSION_HINT` provides the source `last_updated_at`, and in its absence, observation-time freshness is explicitly recorded, but no date is invented. All fields are verified against SourceObject/SourceVersion and the organization prior to publication; user or model SQL cannot substitute the envelope.

Registering source type in the normative baseline does not make the capability established: prior to the atomic delivery package and all gates ADR-0078, its schema, migration, connector, job, and runtime composition remain inert/absent, and the scope cannot become `READY`.
