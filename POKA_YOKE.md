# KnowVault safety invariants

These rules require technical enforcement or a safe failure. They define product and deployment constraints; listing a rule or a component here does not establish that every optional capability has been activated or qualified. Current support is described in [Pilot status](docs/PILOT-STATUS.md).

Machine checks: [guardrails](architecture/guardrails.yaml). Dependency policy: [licenses](architecture/licenses.yaml). Component responsibilities: [Architecture](ARCHITECTURE.md).

## 1. Protection Hierarchy

Each critical invariant is protected by at least two independent layers:

```text
compile/static boundary
        ↓
application policy gate
        ↓
database constraint / RLS
        ↓
post-authorization
        ↓
acceptance or security test
```

UI-only validation, prompts and code review do not replace runtime enforcement.

`allowed_binaries` is a closed command inventory. Runtime activation also requires the declared image, capability profile, configuration and readiness checks. The optional native parser/dispatcher deployment is documented in [Native ingestion](docs/NATIVE-INGEST.md).

## 2. Architectural drift

| ID | Invariant | Enforcement |
|---|---|---|
| ARC-001 | Executable application logic only in TypeScript and Go; SQL, CSS, and HTML are allowed as declarative formats | CI uses a default-deny allowlist of extensions and checks new runtime images |
| ARC-002 | OpenSearch is accessible only to the `internal/search` module | architecture import test |
| ARC-003 | Model endpoints are accessible only to `internal/modelgateway` | architecture import test + network policy |
| ARC-004 | Connector credentials are accessible only to the source/connector adapter | package boundary + secret-provider interface |
| ARC-005 | A new runtime component requires an ADR and a license record | release manifest diff gate |
| ARC-006 | No microservice per module | only server, worker, and connector binaries are allowed |
| ARC-007 | OpenAPI is the source of the HTTP contract | generated clients/types; CI prohibits drift |
| ARC-008 | The local hash/checker is not a trust root | protected remote branch + CODEOWNERS + required CI + signed provenance |
| ARC-009 | Canonicalization is not built with another Go/experiment profile | exact Go 1.26.5 + `GOTOOLCHAIN=local` + `GOEXPERIMENT=jsonv2` build check |
| ARC-010 | `/auth` alias or unknown auth route cannot reach the SPA | exact no-RawPath auth routes + reserved namespace + fixed no-store 404 tests |
| ARC-011 | `/api` route cannot be masked by an HTML fallback | the entire `/api` namespace is sent only to the API boundary; the root dispatcher does not clean or redirect the path |
| ARC-012 | Production startup configuration cannot be extended by hidden env, default, or normalization; the UI root cannot be directed to an arbitrary filesystem subtree | opaque redacted four-field `composition.Config` + one-shot exact `KNOWVAULT_*` allowlist + case-insensitive duplicate/unknown rejection; `webui` does not accept caller-supplied root |
| ARC-014 | The production listener cannot be opened before a complete local build and preflight; a partially built runtime cannot be left alive | the only transactional `composition.NewProduction` + immediate reverse rollback + one-shot `Runtime.Run` as the sole owner of `ListenAndServe` |
| ARC-015 | Cleanup cannot outrun HTTP drain, execute twice, or stop after the first error | shared lifecycle `READY→RUNNING→CLOSING→CLOSED` + cancel/wait + reverse cleanup after Runner return + concurrent/race tests |
| ARC-016 | Handler and entry point cannot obtain or bypass runtime capabilities | opaque Runtime without resource accessors + handlers do not receive Runtime/Close + AST boundary for imports, listeners, mounts, and constructors |
| ARC-017 | The production image cannot obtain an arbitrary local UI bundle or an incomplete Go source tree | tracked+hash-protected `web/dist` is rebuilt from source+exact lock in pinned CI and checked via diff; the Go builder copies the full `internal`; clean-checkout Docker build gate |
| ARC-018 | The runtime image cannot contain a shell, system CA, or customer material and does not run as root | final `scratch` + numeric `65532:65532` + image scan + shipped-trust guard |
| ARC-019 | Secret/trust projection cannot weaken a verified filesystem boundary | fixed image mountpoints + direct regular root:65532/0440/nlink=1 files + O_NOFOLLOW/fstat + read-only volume acceptance test |

## 3. Product Boundary

| ID | Invariant | Enforcement |
|---|---|---|
| PROD-001 | No conversation memory | no conversation/thread tables and API; schema test |
| PROD-002 | A new idempotency key creates a new Question Run; matching text does not deduplicate | canonical request hash + idempotency table |
| PROD-008 | Repeating a key with the same body returns the original run, but with a different body returns 409 | unique key + stored request hash |
| PROD-003 | No write actions | connector interface contains only read methods; egress policy |
| PROD-004 | No cross-workspace search | workspace ID is required, scope is built by the server |
| PROD-005 | No arbitrary internet search | worker egress allowlist; models without network access |
| PROD-006 | No separate "Answers" section | UI route test; recent runs are on the Search surface |
| PROD-007 | Audit is not a content store | audit schema forbids source/prompt body fields |

## 4. Tenant and identity

| ID | Invariant | Enforcement |
|---|---|---|
| TEN-001 | Every tenant-owned row has `organization_id NOT NULL` | migration linter + database constraints |
| TEN-002 | Requests without organization context are forbidden | PostgreSQL RLS default deny |
| TEN-003 | The client does not select the organization filter | organization is output only from a verified session/token |
| TEN-004 | Cache between access contexts is forbidden | no answer/retrieval cache in 1.0 |
| TEN-005 | Deprovision immediately blocks the session | monotonic `session_revision` + DB-trigger revoke + integration test |
| IDN-001 | Unknown external identity mapping means deny | policy decision enum has no fallback allow |
| IDN-002 | OrgAdmin does not receive data access automatically | separate management/data permissions |
| IDN-003 | One OIDC callback does not create two sessions | immutable login state machine + `UNIQUE(organization_id, login_attempt_id)` |
| IDN-004 | OIDC secrets and personal claims do not become application data | schema contains only keyed digests; token/code/`sub`/email columns are forbidden by integration test |
| IDN-005 | A session issued via a disabled or modified OIDC provider does not pass authenticated read | issue-time provider ID/revision + current provider exact-match in pure identity validator |
| IDN-006 | Pre-auth OIDC flow does not receive arbitrary user DB context and cannot issue a session without existing mapping | fixed `svc_oidc` tenant-scoped context + repository-only boundary + digest-only external identity lookup |
| IDN-007 | Discovery and login attempt cannot mix different OIDC provider revisions | provider configuration returns current revision; BeginLogin requires exact current revision in one tenant transaction |
| IDN-008 | Raw state, nonce, PKCE verifier, browser binding, authorization code, client secret, and OIDC subject do not become persisted output | CSPRNG transient material + domain-separated HMAC digests + exchange returns only subject digest |
| IDN-009 | HTTP client cannot select tenant via header, path, query, body, or cookie | `TenantResolver` receives only server-controlled `context.Context` and returns tenant-bound organization/origin/digestor as one security context |
| IDN-010 | Raw browser session token does not enter application context, error chain, or repository contract | canonical 256-bit `__Host-knowvault_session` is read exactly once, immediately HMAC-ed as `session_token`; only a re-verified session is returned outward |
| IDN-011 | Cookie-authenticated unsafe request does not pass without tenant-bound same-origin CSRF proof | exact canonical HTTPS Origin + one `X-KnowVault-CSRF` + constant-time comparison with domain-separated HMAC `csrf` |
| IDN-012 | HTTP/OIDC tenant, provider, and public origin are not selected by client request | immutable single-tenant `tenantsecurity.Context` from startup configuration/KMS; static resolver does not receive `http.Request`; ingress headers are not authority |
| IDN-013 | Browser-session key rotation does not break durable OIDC subject mapping | constructor requires different attested KMS resource refs and does not accept one digestor instance; purpose wrappers forbid identity-purpose on session selection and vice versa; HTTP auth receives only session projection |
| IDN-014 | Raw session token is not saved and does not become a loggable object | opaque redacted `SessionMaterial`; only `session_token` digest is available outward; cookie issuer owns private raw value |
| IDN-015 | Session cookie cannot be issued with weakened browser attributes or a duration longer than server session | single issuer fixes `__Host-`, Secure, HttpOnly, Path=/, no Domain, SameSite=Lax, Expires/Max-Age ≤ 24h; invalid material/TTL fail before Set-Cookie |
| IDN-016 | Raw nonce/PKCE/state/binding are not saved in DB but can be restored only by the same tenant deployment to complete callback | short-lived AES-256-GCM `__Host-knowvault_oidc`; repository stores only digests |
| IDN-017 | OIDC transport cannot be replayed to another tenant, origin, or key ID | canonical `oidc-cookie-aad-v1` binds cookie name, trusted organization, canonical HTTPS origin, and active kid |
| IDN-018 | Identity, session, and OIDC transport do not use one rotation domain even via different aliases | `tenantsecurity.Context` compares immutable KMS resource/version refs and key-material fingerprints; codec accepts exactly one separate 32-byte key |
| IDN-019 | Damaged, non-canonical, too large, future, expired, or created by old transport key login material does not reach callback exchange | strict bounded JCS/base64url envelope, AES-GCM authentication, 15-minute TTL, and one-active-key fail-closed Open |
| IDN-020 | State cannot be accidentally reused as PKCE verifier or substituted with a predictable composite literal | opaque `oidc.Attempt` with private CSPRNG proof; transport accepts only this object and requires pairwise-distinct raw values; `kid` does not allow delimiter `.` |
| IDN-021 | Callback does not mix pending attempt with another or new provider configuration | one tenant-scoped `LoadPendingLoginConfiguration` exact-match provider revision + four digests + PENDING/unexpired + ACTIVE current provider |
| IDN-022 | Successful preliminary read does not allow completing replay or stale provider login | atomic `CompleteLogin` repeats revision/four-digest/provider-current gate in claim statement and commits session, consume, and audit together |
| IDN-023 | Restored callback Attempt cannot be reused as fresh login | private fresh/restored provenance; `TransportMaterial` allowed only fresh CSPRNG attempt; restored material is HMAC-ed again with identity key |
| IDN-024 | OIDC transport cookie cannot be read by a permissive parser or issued with a weakened profile | single `BrowserTransport`: exact one header/cookie, `http.ParseCookie`, quoted/malformed/duplicate deny; fixed __Host/Secure/HttpOnly/Lax/Path/no-Domain/TTL and exact deletion |
| IDN-025 | After durable `BeginLogin` cookie issuance, it cannot fall and leave a hidden orphan attempt | `Prepare` performs clock/crypto/validation/serialization before commit; opaque one-shot `WriteOnce` after commit has no error/clock/codec path |
| IDN-026 | A prepared OIDC cookie cannot be issued again via copy or reuse | private shared `atomic.Bool` capability; maximum one `Set-Cookie` for any number of copies |
| IDN-027 | OIDC discovery, JWKS, and token exchange cannot be routed through a weakened or different HTTP client | one injected `HardenedHTTPClient`; production accepts only cloned standard transport, HTTPS-only, no redirects, fixed timeout, unsafe TLS configuration deny |
| IDN-028 | Callback removes transient transport even on malformed request, replay, or internal failure | exact callback route invokes `Clear` before ID generation, parsing, and any `WriteHeader` |
| IDN-029 | Session cookie cannot be issued before atomic consume login attempt + session + audit | linear handler sequencing: verified exchange → fresh session material → `CompleteLogin` → session issuer |
| IDN-030 | Browser auth endpoint does not become a tenant/provider/redirect selector | exactly two exact GET route; empty login query/body; strict callback code+state; trusted server context and exact callback redirect |
| IDN-031 | OIDC client secret from another organization, provider revision, or reference cannot be used in callback | typed `ClientSecretRequest` exact-match organization + provider + revision + reference; generic string lookup absent |
| IDN-032 | Raw startup keys, DB URL, and OIDC client secret cannot be obtained from env or arbitrary path | fixed Linux mount root + fixed manifest name; no environment fallback; DB reference never becomes filename |
| IDN-033 | Symlink/TOCTOU/hardlink cannot substitute a verified mounted secret | pinned root fd + `openat(O_NOFOLLOW)` + same-fd `fstat` + root UID 0 + file UID 0/nlink=1/0400-or-0440 |
| IDN-034 | One server process does not load another tenant/provider's OIDC secrets | versioned manifest top-level scope + `LoadMountedForTenant` exact expected organization/provider + all client tuples same scope |
| IDN-035 | Three rotation domains do not use one reference or key material | strict 32-byte base64url + nonzero keys + pairwise reference and SHA-256 fingerprint separation |
| IDN-036 | DB DSN does not open a secret boundary bypass via libpq file/service/fallback parameters | canonical single-host URL + exact `sslmode=verify-full` query; arbitrary query keys and multi-host rejected before pgx |
| IDN-037 | libpq environment or permissive pgx parse cannot change production DB target and TLS | init contamination bit + live pre-parse deny any defined `PG*`; post-parse exact core fields, DNS host, verify-full TLS, no fallback and empty runtime params until fixed `application_name` |
| IDN-038 | Startup preflight does not reveal OIDC client secret, and provider copy/close does not preserve a bypass lifecycle | copy-safe opaque shared-state handle + exact `ValidateClientBinding` without secret copying + idempotent `Close` with zeroize and fail-closed accessors |
| IDN-039 | Copying runtime crypto owner does not preserve an independent key and does not bypass Close | HMAC/AEAD copy-safe shared state + in-flight RW lock + idempotent zeroize + value/pointer redaction + closed/zero fail-closed tests |
| IDN-040 | Production TLS cannot implicitly trust system CA, proxy from environment, or confuse DB and OIDC root sets | two customer-mounted fixed-name PEM + non-convertible `DatabaseRoots`/`OIDCRoots` with private DER and fresh reparse + no-system-root/no-proxy tests + restart-only rotation |
| IDN-041 | Symlink, hardlink, TOCTOU, owner, or mode cannot substitute mounted trust roots | fixed Linux root + `open/openat(O_NOFOLLOW)` + same-fd `fstat` + root:65532 `0750` + files root:65532 `0440`/nlink=1 + non-Linux fail closed |
| IDN-042 | Leaf, malformed PEM, duplicate CA, unknown critical extension, or oversized bundle does not become a trust anchor | strict CERTIFICATE-only parser + x509 CA/CertSign gate + exact duplicate hash deny + ≤256 certificates/≤1 MiB |
| IDN-043 | Production runtime cannot call or save a permissive DB/OIDC/trust test constructor | AST reference-boundary prohibits direct call, function alias, and dot-import for `database.Open`, `oidc.NewHardenedHTTPClient`, and raw-PEM roots constructors outside test code; composition uses only mounted typed production path |
| IDN-044 | OIDC discovery, JWKS, or token response cannot trigger unbounded memory read | single streaming body wrapper ≤4 MiB + declared-length precheck + max+1 overflow probe + close-on-deny/exact-limit tests |
| IDN-045 | Identity, session, and OIDC transport key cannot be confused during composition or saved as a local copy after cleanup | three non-convertible capability types + purpose-valid metadata API + shared local `Clear`/zeroize + immediate temporary bytes clearing |
| IDN-046 | Listener does not start with another OIDC revision, redirect, or client-secret binding | one current provider read + exact tenant/provider/revision/callback projection + pure OIDC validation + no-copy mounted binding preflight |
| ARC-013 | Production is not declared ready without image-owned UI, and UI assets cannot exit root via symlink | fixed `/web/dist` + pinned `os.OpenRoot`/`Root.FS` confinement + root/index admission checks + closeable request-drained `ProductionHandler` before listener |

## 5. Workspace and permissions

| ID | Invariant | Enforcement |
|---|---|---|
| ACL-001 | SOURCE_ENFORCED workspace does not expand source ACL | policy intersection + post-auth by specific scope membership |
| ACL-002 | Expired ACL in SOURCE_ENFORCED means deny | indexed evidence is excluded from context |
| ACL-003 | WORKSPACE_MANAGED is a separate explicit grant and requires risk confirmation | source scope state machine + audit event; UI does not call it source ACL |
| ACL-004 | Changing membership invalidates access context | membership revision in session/policy decision |
| ACL-005 | Viewer does not run Question Run | application policy + API acceptance test |
| ACL-006 | Auditor does not read content automatically | metadata-only endpoint + separate permission |
| ACL-007 | Saved answer cannot be opened without current access to all essential citations; historical scope snapshot is not a grant | current WorkspaceRevision read gate; on deny, partial rendering is not executed |
| ACL-008 | Stale source ACL does not allow evidence even with PARTIAL corpus | ACL freshness gate inside grant path |
| ACL-009 | Stale identity mapping/group expansion does not allow workspace or source evidence | immutable principal-set snapshot + provider revision/expiry |
| ACL-010 | Retrieval grant must exactly match current WorkspaceRevision, membership, binding, PolicyDecision, and access mode; fields saved in grant are not authority | terminal read transaction against live projections + minimal deterministic grant path + exact digest comparison |
| ACL-011 | Even a zero retrieval result requires a fresh PrincipalSetSnapshot | pre-retrieval principal freshness gate + zero-context negative fixture |
| WSP-001 | WorkspaceRevision configuration is unambiguous and independent of input members/bindings order or Unicode text representation | pure `workspace.Normalize` + NFC `text-v1` + JCS SHA-256 hash |
| WSP-002 | In revision, exactly one OWNER, matching owner workspace | validation in pure snapshot + deferred PostgreSQL owner constraint on persisted state |
| WSP-003 | Future source binding cannot appear outside configuration hash | `source_bindings` is included in canonical workspace-configuration-v1, even when Stage 1 list is empty |
| WSP-004 | Workspace creates only an active Organization Owner or Admin | server-resolved organization/principal/roles + default-deny policy + PostgreSQL integration test |
| WSP-005 | Damaged or non-matching current WorkspaceRevision does not become readable | repository recomputes canonical configuration hash before returning Snapshot |
| WSP-006 | Creating Workspace cannot commit without owner membership, immutable revision, and audit event | one authorized database transaction + deferred owner constraint + `AppendInTransaction` |
| WSP-007 | Only the current Owner/Manager of an ACTIVE workspace can change metadata, archive the Workspace, or add a participant | locked current snapshot + `workspace.manage` default-deny policy + PostgreSQL integration test |
| WSP-008 | Adding a participant does not change past WorkspaceRevision | pure `NextWithMember` creates revision+1; persistence inserts new membership with `valid_from_revision` |
| WSP-009 | Archiving does not delete Workspace, revision, or audit history | `NextArchived` + lifecycle UPDATE + append-only audit event; runtime DELETE privilege is absent |
| WSP-010 | Role change does not overwrite the active membership row | old row is closed by `valid_to_revision`; replacement starts on a new immutable revision |
| WSP-011 | Current owner cannot be removed or demoted by a standard command | pure snapshot functions reject OWNER target + deferred sole-owner database constraint |
| WSP-012 | Ownership transfer is available only to the current OWNER and cannot leave zero or two owners | owner-only command + locked snapshot + atomic closure of two intervals + two replacement membership + PostgreSQL acceptance test |
| WSP-013 | Command from an outdated screen cannot overwrite new workspace configuration | mandatory exact configuration hash + comparison after row lock + `WORKSPACE_REVISION_CONFLICT` and FAILED audit without domain mutation |
| WSP-014 | Repeating a mutating command with the same actor-scoped Idempotency-Key does not create a second mutation/revision/audit | SHA-256 key hash + typed JCS request hash + unique PostgreSQL receipt reservation in one business transaction |
| WSP-015 | Idempotency receipt does not become historical access right | exact replay reads immutable revision snapshot, then re-passes current identity/workspace metadata policy; loss of membership gives NOT_FOUND |
| WSP-016 | Runtime workspace mutation cannot commit without a fresh terminal SUCCESS receipt, exact revision snapshot, and associated audit | actor-scoped immutable command intent + same-transaction deferred PostgreSQL gates on workspace/revision/snapshot/member + exact audit/effect validator |
| WSP-017 | Old SUCCESS receipt or another's audit cannot be used for new workspace mutation | `transaction_timestamp()` freshness + unique revision/audit receipt bindings + actor/action/resource/outcome/error verification |
| WSP-018 | HTTP mutation cannot bypass authentication, CSRF, idempotency, or optimistic concurrency | exact handler pipeline: route → server request ID → session → CSRF → canonical headers/body → repository; unsafe requests without proof do not reach service |
| WSP-019 | Client cannot create an ambiguous workspace HTTP request | exact escaped-path routing without aliases/query, one canonical security header, strict JSONv2 object up to 32 KiB, unknown/duplicate/invalid UTF-8 fail closed |
| WSP-020 | Presence of handler code does not include business routes until browser auth composition is complete | `workspaceapi` does not import `cmd/server`; inclusion requires a separate ADR, production tenant resolver, exact session issuer, and completed OIDC callback |

## 6. Sources and ingestion

| ID | Invariant | Enforcement |
|---|---|---|
| SRC-001 | Connector works only within a saved scope | signed scope manifest checked locally and centrally |
| SRC-002 | Connector read-only | interface, least-privilege credentials, contract tests |
| SRC-003 | No shell/exec in Connector Agent | binary/API surface scan + network test |
| SRC-004 | Scope config is immutable and event is bound to exact revision/job | immutable source_scope_revision + signed connector job |
| SRC-005 | Connector event cannot be forged or replayed | mTLS identity + signed envelope + atomic nonce consumption |
| SRC-006 | Disappearance of an object from one overlapping scope is not considered global deletion | mandatory delete_semantics + revision-aware membership transition + overlap test |
| SRC-007 | Folder path does not exit admin root via traversal/symlink/reparse | root-handle resolution + containment check + symlink disabled |
| SRC-008 | Git content does not execute hooks/filters/submodules/build code | connector interface + sandbox + exact dependency lock |
| SRC-009 | Mail ingestion does not change mailbox state | read-only OAuth scopes + IMAP BODY.PEEK + mutation-free contract |
| SRC-010 | Site crawl does not become SSRF or browser agent | per-hop DNS/IP/origin gate + GET/HEAD-only HTML runtime + bounded crawl |
| SRC-011 | Parser does not trust extension and does not execute active content | media sniff + sandbox + archive/macro/formula/external-link deny |
| SRC-012 | Metadata/version and bytes always belong to one stable read | before/after identity/version check + conditional object read + torn-read quarantine |
| SRC-013 | Server and Connector compute include/exclude boundary identically | scope-glob-v1 shared package + matcher version in signed scope + golden vectors |
| SRC-014 | Scope activation and any connector event, regardless of access mode, are allowed only for exact approved build with passed capability/contract suite | common pre-access-mode trust gates + immutable build/profile/artifact/suite hashes |
| SRC-015 | New source revision does not gain authority via latest/current pointer | separate `latest_revision`/nullable `active_revision`; 000006 creates only DRAFT and contains no READY/job/query mutator |
| SRC-016 | Relational source snapshot of each WorkspaceRevision exactly equals canonical `source_bindings` and itself does not create authority | exact workspace/scope tuple FK + deferred bidirectional set equality + immutable rows |
| SRC-017 | Source binding command cannot bypass single receipt, change second binding, or obtain data authority | one primary `workspace_command_receipt` + exact one-binding transition + full carry of remaining rows + OWNER/MANAGER RLS + exact terminal audit + prohibition of confirmation/activation/grant/job/query |
| ING-001 | ACL allowed before indexing | ingestion state machine forbids transition to INDEX_STAGED |
| ING-002 | Duplicate event does not create duplicate | unique external version key + idempotency key |
| ING-003 | New object not visible until full processing | OpenSearch `visibility=STAGED` |
| ING-004 | Reduction of rights first closes queryability | PostgreSQL deny before asynchronous purge |
| ING-005 | Deletion first closes queryability | tombstone transaction before index cleanup |
| ING-006 | Original binary not permanently saved | ephemeral volume, TTL, backup exclusion, storage scan |
| ING-007 | Error of one file does not complete scope successfully without caveat | per-object error + degraded sync status |
| ING-008 | Reconciliation mandatory even with webhook | scheduler invariant and freshness SLO test |

## 7. Versions and evidence

| ID | Invariant | Enforcement |
|---|---|---|
| VER-001 | EvidenceFragment references an immutable SourceVersion and a specific immutable SourceExtraction of that version | composite non-null foreign key |
| VER-002 | Version is unique within source connection/object | composite unique constraint |
| VER-003 | Old versions do not participate in new retrieval | ACTIVE visibility + DB post-check |
| VER-004 | Overlapping scope revisions do not duplicate SourceObject, version, evidence, or vector | revision-aware M:N source_object_scope + composite uniqueness |
| VER-005 | Deleting one scope membership does not delete the object as long as another active membership exists | membership state machine + overlap tests |
| VER-006 | An old broad revision does not authorize a new narrowed revision | exact revision in workspace snapshot, index nested filter and post-auth |
| VER-007 | Re-extraction of an unchanged SourceVersion does not replace fragments in place; a new retrieval uses only the active Extraction | immutable Extraction + staged set + atomic active pointer + historical citation fixture |
| VER-008 | QuestionRun purge does not delete shared Extraction; source-derived purge fencing does not allow late worker/index resurrection and does not disable newer current version | explicit version retention aggregate + lease/CAS fence + ordered outbox fence + purge race tests |
| EVD-001 | Citation requires a format-specific anchor | JSON schema by object type |
| EVD-002 | Text and anchor are protected by content hash | structural validator |
| EVD-003 | Search chunk is not a citation object | separate IDs and tables/types |
| EVD-004 | Citation ID cannot be guessed | context-pack membership validator |
| EVD-005 | Each citation resolves to its own source/version/evidence chain; the answer is not limited to a single source | keyed chain resolver + multi-source manifest fixtures |
| EVD-006 | All promised file formats have an unambiguous parser-kind→anchor mapping | trusted extraction kind map + JSON/XML/EML positive fixtures |
| PAR-001 | Each format has a terminal exact-anchor resolver without file-level fallback | parser ownership matrix + quarantine |
| PAR-002 | Parser/OCR does not execute active/external content and respects resource limits | sandbox/profile/XXE/OCR binding tests |
| PAR-003 | Resolver is selected by immutable `canonical_format`, not mutable MIME | format in Extraction profile hash + media signature gate |

## 8. Search

| ID | Invariant | Enforcement |
|---|---|---|
| SRCH-001 | Tenant/workspace filters builds the server | typed `AuthorizedSearchScope`; no raw filter in API |
| SRCH-002 | OpenSearch prefilter is not final authorization | mandatory post-authorization batch |
| SRCH-003 | Removed/revoked evidence, non-current SourceVersion, or non-active Extraction is not passed to the model | DB lifecycle/version/extraction check after retrieval |
| SRCH-004 | Truncation of retrieval degrades corpus status | token/candidate budget event in manifest |
| SRCH-005 | Source binding error degrades corpus status | snapshot status reducer has no silent success |
| SRCH-006 | Workspace does not create a copy of embeddings | index documents do not contain `workspace_id` as ownership key |
| SRCH-007 | Each final context evidence has a persisted current/active grant path | retrieval-authorization snapshot + terminal post-auth transaction |
| SRCH-008 | Stale SOURCE_ENFORCED ACL does not allow evidence even with PARTIAL corpus | grant-path construction fail closed; coverage status is not authorization |
| SRCH-009 | Manifest/metadata does not reveal the number of denied retrieval hits | only post-authorized candidate count is exported; raw counts restricted and aggregated |
| SRCH-010 | Query and corpus vectors belong to the same exact embedding profile | profile hash index field + staged re-embedding + atomic alias |
| SRCH-011 | Retrieval config cannot be changed under the same version string | immutable profile hash covers code/analyzer/models/RRF/limits/budgets/tie-breakers |

## 9. Models and Response

| ID | Invariant | Enforcement |
|---|---|---|
| MOD-001 | Model does not receive tools | Model Gateway contract does not contain tool schema |
| MOD-002 | Model does not receive credentials | typed evidence DTO + secret scanner test |
| MOD-003 | Retrieved instructions remain data | fixed prompt envelope + injection corpus tests |
| MOD-004 | `GENERATIVE`: model answer is strictly schema-valid; `EXTRACTIVE` does not accept model answer | mode-scoped JSON schema validation; bounded retries; fail closed |
| MOD-005 | Model does not add URLs | renderer builds links only from Citation records |
| MOD-006 | Model text cannot embed Markdown/HTML/RTL structure | single-paragraph validator + server AST Text node + injection fixtures |
| MOD-007 | `GENERATIVE`: Manifest does not invent model call | actual model runs exact-match persisted gateway attempts; each manifest has selected EMBEDDING run, precheck denial manifest does not create |
| MOD-008 | `GENERATIVE`: Selected model runs are linked to exact question/candidate/context, while generator output is linked to final plan | purpose-specific input hashes + reverse plan projection |
| MOD-009 | `GENERATIVE`: Model profile hash covers weights/runtime/tokenizer/chat template/prompt/schema/decoding | immutable canonical model profile + AIBOM |
| MOD-010 | UNKNOWN does not transfer model-controlled fact or instruction | typed reason + server-owned fixed text + reverse plan projection |
| MOD-011 | Reranker receives full saved set of authorized candidates, while manifest distinguishes candidate and final context counts | immutable authorized-candidate-set-v1 + exact reranker input hash + candidate-count/context-count fixtures |
| MOD-012 | `GENERATIVE`: Plan model runs are created by server before execution; it includes all attempts and links snapshot exactly to model IDs, profile hashes, inputs and outputs | append-only model-execution-plan-v1 + ordered attempt intervals + exact corpus-snapshot projection |
| CIT-001 | Every actual phrase is linked to a citation | claim/span coverage validator |
| CIT-002 | `GENERATIVE`: One or more citations semantically support the phrase; verbatim text match of claim is not a substitute for verifier | persisted verifier result + benchmark threshold + paraphrase/joint-evidence fixtures |
| CIT-003 | Numbers/dates/units match | deterministic validators before completion |
| CIT-004 | Unsupported claim is not published | bounded regeneration/new exact insufficient plan; selected plan is not edited silently |
| CIT-005 | Citation fixes trusted Extraction provenance and cannot substitute parser/OCR profile | extraction snapshot exact-match + manifest validator |
| CIT-006 | `GENERATIVE`: Claim cannot be changed or re-bound after verifier, and verifier output cannot be substituted | immutable ClaimVerification + strict verifier-output schema + exact text/evidence/support/input/output hashes + selected verifier run |
| CIT-007 | Model cannot place unverified fact in title or other renderer prose | section title const null + fixed server prefixes + schema negative test |
| CIT-008 | Compound dates, numbers and units in Russian and English are checked as a single semantic span, not as independent matched tokens | numeric-lexer-v1 compound spans + locale-aware deterministic validator + split-citation negatives |
| CIT-009 | Numeric inference can rely only on directly supporting SUPPORTED FACT claims with PASSED numeric validation and only on their citations | direct supporting-fact graph + per-claim citation closure; global answer citations forbidden |
| EXA-001 | `EXTRACTIVE`: answer mode and verification method are signed in manifest and cannot diverge | manifest schema v2.0 + signed mode/method binding |
| EXA-002 | `EXTRACTIVE`: claim is a deterministic projection of authorized snapshot | server-owned extractive claim plan + authorized context hash |
| EXA-003 | `EXTRACTIVE`: claim text is byte-equal to one sentence citation without newline and within 2000 UTF-8 bytes | byte-exact validator + one-citation cardinality |
| EXA-004 | `EXTRACTIVE`: generator/verifier profiles, runs and verification records are forbidden | conditional manifest schema + mode-scoped terminal validator |
| QRY-001 | Previous Question Run is not included in prompt | context builder accepts only question + current evidence |
| QRY-002 | Partial corpus is visible above answer | status persisted separately from answer prose |
| QRY-003 | Corpus snapshot exactly covers all enabled bindings WorkspaceRevision; source cannot be hidden by skipping line | composite uniqueness + exact set/hash comparison + manifest negative tests |
| QRY-006 | Health/watermarks/sync/ACL freshness manifest is not self-declared and COMPLETE is computed by trusted SLA at startup moment | source-health snapshot exact-match + deterministic SLA reducer |
| QRY-004 | Manifest exactly reflects size of transmitted model authorized context pack | `context_count == len(context_pack)` + hash/count negative test |
| QRY-005 | Empty or irrelevant context/no verified facts/has UNKNOWN cannot look like `COMPLETED`, and facts-only run cannot be arbitrarily named insufficient | bidirectional terminal status coupling + signed insufficient-evidence fixtures |
| QRY-007 | Retrieval telemetry/truncation/errors are not self-declared | persisted canonical retrieval-authorization snapshot exact-match |
| QRY-008 | Manifest cannot be bound to foreign or non-existent QuestionRun | exact-match locked QuestionRun aggregate + composite FK |
| QRY-009 | All provenance lies within one trusted QuestionRun interval and pipeline order | temporal validator + terminal transaction |

## 10. Immutability and Audit

| ID | Invariant | Enforcement |
|---|---|---|
| IMM-001 | Completed Question Run cannot be changed | database trigger rejects UPDATE of protected columns |
| IMM-002 | Citation/manifest of a completed run are immutable | database trigger + append-only repository API |
| IMM-003 | Rerun creates a new ID | no update command in application API |
| IMM-004 | Retention purge deletes content only via a privileged procedure and leaves tombstone/hash; `PURGING` and `PURGED` block content read, while PURGED requires absence of bytes | explicit QuestionRun retention aggregate + separate DB role + purge completion validator + independent read gate + audit |
| FRESH-001 | Version change is reflected separately from answer text | computed citation state resolver |
| FRESH-002 | DELETED or ACCESS_REVOKED citation blocks issuance of answer body/excerpt | read-time disclosure gate + acceptance test |
| FRESH-003 | Changing active Extraction does not overwrite the answer and does not appear fully current | `EXTRACTION_SUPERSEDED` resolver + rerun action |
| FRESH-004 | Purging/Purged Extraction is not disclosed as a normal superseded item | `EXTRACTION_PURGED` + body/excerpt disclosure deny |
| AUD-001 | Audit is append-only | database role has INSERT/SELECT only; UPDATE/DELETE trigger deny |
| AUD-002 | Audit is tamper-evident even against privileged DB rewrite | per-organization hash chain + signed checkpoint + external append-only sink receipt |
| AUD-003 | Audit does not contain source content or secrets | typed metadata allowlist + redaction tests |
| AUD-004 | Checkpoint verifier re-canonizes the full body of each AuditEvent and verifies the entire hash chain, rather than trusting stored event_hash | strict audit-event-v1 schema + JCS body rehash + sequence/previous-hash verification |
| AUD-005 | Critical state change and mandatory audit event commit either together or not at all | domain repository uses `audit.AppendInTransaction` within the same `database.Write`; integration rollback test |
| SIG-001 | Rotation key does not break historical verification; revoked key fails closed | purpose-scoped ACTIVE/RETIRED/REVOKED records + one-active constraint + KMS signer |

## 11. Jobs, failures, and recovery

| ID | Invariant | Enforcement |
|---|---|---|
| JOB-001 | Job cannot be lost upon worker failure | DB lease + deadline reclamation |
| JOB-002 | Job cannot be acknowledged before committing the result | result + outbox in one transaction |
| JOB-003 | Retry is limited and observable | max attempts + dead letter + alert |
| JOB-004 | Two workers cannot execute the same lease simultaneously | row lock + lease token compare-and-set |
| JOB-005 | Outbox sequence does not receive gaps upon rollback and Web/API runtime cannot acknowledge external delivery | tenant-local transactional head + immutable ordered events + absence of UPDATE/DELETE grant; applier closed before worker lease/CAS gate |
| OPS-001 | Index can be rebuilt from source/canonical derivatives | rebuild acceptance test |
| OPS-002 | Backup does not contain ephemeral binaries or secrets | restore inspection test |

## 12. Licenses and supply chain

| ID | Invariant | Enforcement |
|---|---|---|
| LIC-001 | Unknown license blocks build | default-deny license policy |
| LIC-002 | AGPL, SSPL, BSL, non-commercial and source-available are prohibited | SBOM/license gate |
| LIC-003 | Model has ID, revision, hash and license | AIBOM required for release |
| LIC-004 | Container image is pinned by digest | deployment manifest linter |
| LIC-005 | Runtime does not download code/model from the internet | offline test + egress deny |
| LIC-006 | Transitive dependencies are accounted for | SBOM for each image and UI bundle |
| LIC-007 | Third-party notices are generated automatically | release artifact gate |
| LIC-008 | Version/license lock — closed registry `ACTIVE/DEFERRED`; every actual Go/Node dependency, lock/importer, OCI/Docker stage and CI/local Action must exact-match `ACTIVE`; `replace/go.work`, remote installers and ambiguous license YAML are prohibited | strict inventory + actual manifest/import/runtime reconciliation + full-length integrity + exact license evidence/status + mutation self-tests |
| LIC-009 | CA bundles for PostgreSQL and OIDC are not a supplied component of KnowVault | customer-supplied runtime mount + repository/image basename deny + SBOM external-artifact classification |
| CI-001 | Mandatory check is considered present only as an executable CI command, not as a comment, echo or similar string | indentation-aware run-block parser + exact command contract + comment/echo mutation self-tests |
| CAN-001 | Text offsets use canonical UTF-8 byte range `[start,end)` | shared canonicalization package + Unicode fixtures |
| CAN-002 | JSON, answer, event and manifest hashes use a single canonical form | RFC 8785/JCS + golden vectors |
| CAN-003 | Both signatures cover hash, key ID and time; replay nonce is required only for connector event | two-step envelopes + tamper/replay fixtures |

## 13. Release gate

Release is prohibited if:

1. at least one critical rule lacks an automated test;
2. security/tenant/ACL acceptance suite fails;
3. citation support precision is below the accepted threshold;
4. SBOM or AIBOM is incomplete;
5. there is an unpinned image/model;
6. there is a high/critical finding without an accepted risk ADR;
7. schema, OpenAPI, and generated code are inconsistent;
8. UI, API, and retrieval yield different policy decisions;
9. delete/revoke propagation does not meet SLO;
10. a regulatory file has been changed without an accepted ADR.
