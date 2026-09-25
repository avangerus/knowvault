# KnowVault MCP tools

The source page uses `#evidence/<workspace_id>/<fragment_id>?address=<encoded-kv1>`
in the KnowVault UI. `source_page_url` returned by the evidence GET and
`knowvault_read` is a human-readable link built from the configured deployment
origin; it never grants access. The page shows saved text, authorized source
path, version, extraction and observation time. An exact quote highlight also
requires a verified quote span. Original binary files are not included.

A canonical-address read can open the retained source version and the exact
extraction that owns the addressed fragment, even after a new version or
extraction has been published. It checks current workspace membership,
WORKSPACE_MANAGED scope binding/confirmation and revocation, object availability,
version/extraction retention and artifact availability. Purged or inaccessible
data returns a content-free denial, with no fallback to current data. The
guarantee is stability while retained and currently authorized, not permanent
availability or enforcement of unimplemented item-level source ACLs.

`is_current_version` compares the saved version with the object's current
pointer; false does not promise an accessible replacement. Bare fragment-ID
reads, `knowvault_evidence_get`, default search and default inventory remain
current-only. In whole-object mode, `source_page_url` opens the anchor fragment;
the paged text still contains only its own exact extraction. The evidence GET
accepts optional `address`; duplicate/empty parameters are invalid, while a
malformed/mismatched address and an unavailable exact fragment return the same
404. The persisted chat `deep_link` API URL remains compatible; the source panel
can copy a separate UI link with the immutable address and verified quote span.

The workspace-scoped MCP adapter is served over streamable HTTP at
`POST /api/v1/mcp` and speaks JSON-RPC 2.0 (`initialize`, `tools/list`,
`tools/call`). Every `tools/call` is authenticated with the same session or
service-principal identity as the REST API, and every tool delegates to the same
workspace-scoped service the matching REST route composes: authorization, tenant
isolation and the audit journal stay in that service, never in the transport.

Search text carries one exact `canonical_address` per hit together with its
`fragment_id`, source path, excerpt and ranking/version metadata. The legacy
structured `address` object remains in `structuredContent`; it is not duplicated
in search text when the canonical string is available. Read accepts either the
returned fragment identifier or the copied canonical address. Pagination and
the full structured result remain available to external clients.

`knowvault_evidence_get` returns the fragment text and its anchor/provenance.
When the viewer provides an authorized source identity, both REST and MCP also
return `source_path`; the chat displays this path next to the canonical address.
It is decrypted through the evidence viewer, never inferred from search text.
For structured evidence, `structuredContent` additionally includes the same
optional matched `rowset` as the REST evidence route with its default scope.
It contains columns, selected rows, the selection label and snapshot metadata.
Both transports recheck access before returning it and omit the optional rowset
when it is unavailable. The MCP arguments remain `workspace_id` and
`fragment_id`; this tool does not add a full-snapshot scope argument.

A V1-C SERVICE agent access-code principal sees and may call every knowledge
tool of its workspace — `knowvault_question`, `knowvault_evidence_get`,
`knowvault_read` (and the compatible `knowvault_evidence_read`),
`knowvault_list_objects` (and the compatible `knowvault_workspace_list`),
`knowvault_sources` (and the compatible `knowvault_sources_list`),
`knowvault_refresh`, `knowvault_search`,
`knowvault_grep`, `knowvault_related` and `knowvault_governed_query_ask` —
exactly as a human session does. The read-only SQL ask was added for the owner's
documents-and-SQL MCP pilot on 15.09.2026; it still requires explicit workspace
opt-in and the dedicated external database role. The administrative tools
stay closed to it: conversation management, the confirmation/authority tools,
`knowvault_verify_connection_trust`, `knowvault_source_enable`,
`knowvault_source_sync` and the
metric-definition reads (owner decision 12.09.2026, design item 4(5)). Every
other tool below is shown to and callable by a non-SERVICE (human/operator)
principal.

When an administrator mounts at least one governed SQL preset, SERVICE and human
principals additionally see `knowvault_queries_list` and
`knowvault_query_run`. Both disappear from `tools/list` when no preset is
mounted. They accept no SQL and are described below.
The tool set is KnowVault's own: no wiki-rag tool name (`wiki_search`,
`wiki_get_page`, `wiki_list_pages`, `wiki_find_related`, `code_search`,
`code_get_file`) is advertised in `tools/list` or dispatched by `tools/call`
(owner decision 12.09.2026 / KV-A02b-r2, KV-A02b-r3). A session configured for
wiki-rag is reconfigured by changing the endpoint and the tool names to the
product's canonical names documented below. Every search tool is advertised
only when the deployment mounts the evidence search capability; a service
without the capability fails closed with `-32000` and no content. Likewise
`knowvault_grep` is advertised only when the mounted evidence service supports
the exact-regex capability, directly or through its object inventory and
whole-object reads (the production `*evidence.Viewer` does), and
`knowvault_related` is advertised only when the mounted evidence service
implements the relation capability; the production composition mounts it (the
relation source is wired into the workspace MCP handler), so the tool is
advertised and served in the deployed product rather than failing closed as an
unwired capability.

## Canonical tools

Every canonical tool. Tools marked *R3a-1* are specified in full below; the
remaining tools are the accepted pre-R3a-1 surfaces and keep exactly their
existing parameters and result shapes.

| canonical tool | summary |
| --- | --- |
| `knowvault_question` | Ask a question over the workspace corpus; evidence-backed citations. |
| `knowvault_conversations_list` | List current-access conversation metadata. |
| `knowvault_conversation_get` | Read one current-access conversation. |
| `knowvault_conversation_archive` | Archive one conversation irreversibly. |
| `knowvault_evidence_get` | Open one evidence fragment by citation id. |
| `knowvault_read` *R3a-1* | Read one evidence fragment, or with a cursor the whole object, in full page by page (former name `knowvault_evidence_read` still accepted). |
| `knowvault_confirmation_grant_issue` | Issue a workspace-managed confirmation grant. |
| `knowvault_confirmation_grant_revoke` | Revoke a workspace-managed confirmation grant. |
| `knowvault_managed_source_confirm` | Confirm a workspace-managed source. |
| `knowvault_managed_confirmation_revoke` | Revoke a managed-source confirmation. |
| `knowvault_verify_connection_trust` | Verify a source connection's trust. |
| `knowvault_source_enable` | Bind or re-enable a source scope. |
| `knowvault_source_sync` | Request a full refresh for a source scope. |
| `knowvault_governed_query_ask` | Governed read-only SQL ask over an exposed schema. |
| `knowvault_queries_list` | List versioned, reviewed live-query presets without SQL text. |
| `knowvault_query_run` | Run one reviewed preset by id and return a live execution receipt. |
| `knowvault_metric_definitions_list` | List issued metric-definition versions. |
| `knowvault_metric_definition_get` | Read one exact metric-definition version. |
| `knowvault_sources` *R3a-1* | Source inventory, schedule and confirmation context (former name `knowvault_sources_list` still accepted). |
| `knowvault_refresh` *R3a-1* | Refresh the workspace sources that allow it, paginated, with a closed skip reason per source left alone. |
| `knowvault_list_objects` *R3a-1* | Paginated document/evidence object inventory (former name `knowvault_workspace_list` still accepted). |
| `knowvault_search` *R3a-1* | Lexical and semantic search over workspace data with addressed evidence. |
| `knowvault_grep` *R3a-1* | Exact-regex grep over the canonical text of workspace objects. |
| `knowvault_related` *R3a-1* | Canonical cross-source relations of one addressed object. |

## `knowvault_governed_query_ask`

Accepts only `workspace_id`, `connection_id` and `question`. The requested
connection must match the mounted capability; an unknown connection cannot
fall back to another database. Authorization and the workspace's live-query
opt-in are checked on every call. SQL composition is performed by the configured
model; database grants and a bounded read-only transaction enforce execution.
An exposed schema describes the model's input; it does not replace DB grants.

The text content block contains the same JSON result as `structuredContent`,
including exact SQL, SQL hash, attempt ID, columns and every returned row.
`result_format=postgres-text-table-v1` means non-null cells are PostgreSQL text
values (including exact decimals), while SQL NULL is JSON null. Empty text is
`""`. Values are never shortened; exceeding the row/byte cap refuses the whole
result instead of returning an apparently complete partial table.

Provenance includes `connection_id`, `database_identity`,
`exposed_schema_revision`, `execution_started_at`, `execution_completed_at`
and `result_digest`. The UTC interval is the server's query execution window,
**not** the source record's modification time. The digest is SHA-256 of canonical
JSON containing `format`, `columns`, `row_count` and `rows`; it covers values,
nulls and row order. It excludes time and SQL, whose hash is separate.

This is a live result, not a retained document version. The attempt and audit
record do not store the returned rows, and the attempt ID is not a `kv1:` source
page address. Use ingested SQL snapshots and their existing read addresses when
a retained citation is required. A later live query can return newer data.
SERVICE attempts are attributed to the service actor, not a human.

## `knowvault_queries_list` and `knowvault_query_run`

These optional tools implement the narrower, deterministic preset path. List
requires `workspace_id` and may optionally pin `connection_id`; omitting it
selects the single administrator-mounted preset connection, while an explicit
`connection_id` that does not match that mount fails closed. Run requires all
three fields `workspace_id`, `connection_id` and `preset_id`. Both schemas are
closed: SQL, parameters and unknown fields are invalid.

The catalogue contains a preset id, version, name, description, exact phrases,
source attempt id, reviewed SQL hash, exposed-schema revision and preset hash;
it never contains SQL or credentials. Run reloads the source attempt from the
server, verifies the attempt id, SQL hash and exposed-schema revision against
the current workspace, then uses the same dedicated read-only transaction,
timeout, EXPLAIN cost, row and byte limits as governed ask.

The run result has `data_state=LIVE_OBSERVATION`, exact PostgreSQL text cells,
execution times and content-free receipt hashes. It is not retained Evidence
and has no `kv1:` address. See [Governed SQL presets](GOVERNED-SQL-PRESETS.md).

## `knowvault_read`

Reads one evidence fragment (citation object) **in full** as an explicit
sequence of pages over its canonical normalized text, through the same
authorized `Evidence` viewer, admission-before-data journal and
`citation.opened` outcome as `knowvault_evidence_get` and the REST
`GET /api/v1/workspaces/{id}/evidence/{fragment_id}` route. R3a-1 Outcome 1.
With the optional `cursor` it reads a whole source version instead (see the
whole-object page mode below).

`knowvault_read` is the canonical name (design item 4: by address, paged). The
former name `knowvault_evidence_read` is an accepted **compatibility alias**:
`tools/list` advertises only the canonical name, but a `tools/call` naming the
former name dispatches to the byte-identical read core with the identical
parameters, projection, pagination and error codes. New sessions should use the
canonical name.

Every page is an explicit byte window of the fragment text. The response always
reports `offset`, `length`, the effective `limit`, `total_length`, `has_more`
and, while more remains, `next_offset`. A limit is never silent truncation: a
fragment longer than the default page is returned page by page, and continuing
from `next_offset` until `has_more` is `false` yields the complete saved fragment.
Pages are snapshotted to UTF-8 rune boundaries. The `content[].text` channel
carries the page text itself followed by exactly one trailing metadata line with
the same address, window and hashes the `structuredContent` channel carries, so a
text-channel-only client can read the page, locate its span and continue the
pagination without parsing `structuredContent` and without a base64 copy.
Concatenating the `content[].text` page bytes of every page byte for byte
reproduces the stored canonical text. The exact page bytes are additionally
available as base64 in `structuredContent.text_base64` only when the caller
passes the additive `include_text_base64` boolean argument (default `false`);
that member is absent on a default read, and when it is present its decoded
payloads concatenate to the same stored canonical text. `text_hash` is the
whole-fragment `evidence_fragment.text_hash`, the ADR-0077 **organization-keyed**
HMAC-SHA-256 of the original span rendered as
`hmac-sha256:k<version>:<64 lowercase hex>`; it is never a bare `sha256:` of
plaintext, because a bare content hash would let an outsider confirm a guess
about content offline. `page_hash` is by contrast the **unkeyed** canonical
`sha256:` of the exact page bytes, so a client can verify each page before
trusting the reassembly. The keyed family covers `evidence_fragment.text_hash`
and every canonical-address span digest; the whole-object `whole_hash` and the
per-page `page_hash` are unkeyed SHA-256 of bytes the caller already holds (see
the whole-object page mode below).

`offset` and `limit` are UTF-8 byte offsets, both optional; `limit` defaults to
4096 bytes and is capped at 65536 bytes (the capped value is echoed as `limit`).
A negative offset/limit and an offset past the end of the text are rejected with
`-32602`.

The `address` object identifies the retrievable thing:

- `source`: `source_object_id`, `connection_id`;
- `version`: `source_version_id`, `external_version_key`, `content_hash`, `observed_at`;
- `object`: `extraction_id`, `ordinal`, `fragment_id`;
- `span`: `offset` (0), `length` = `total_length` = length of the canonical
  fragment text, `text_hash` of that span and the canonical `anchor` (base64).

Search hits, object inventory and read pages additionally carry `source_path`
when the authorized source identity is available. For a file this is the path
relative to its connected root or repository. It is decrypted through the same
workspace readability gate as the content; it is not copied from the search
index. Text responses quote it to preserve spaces and escape line breaks.
Legacy objects without an identity artifact omit it or return an empty value.
The path is source metadata, not an instruction or a substitute for an address.

`canonical_address` is the string round-trippable `internal/address` value of
the object (R3a-1 Outcome 1 / KV-A01). Its fixed compact form is
`kv1:<object>:<version>:<span>:<hash16>`, where `<object>` is the
source-qualified reference `<source_object_id>~<fragment_id>`, `<span>` is
`text.<char_start>-<char_end>` (half-open Unicode code point offsets; code uses
`code.<file>@<first>-<last>` and tables `table.<snapshot>@<first>-<last>`), and
`<hash16>` is the first 16 lowercase hex characters of the organization-keyed
HMAC-SHA-256 of exactly the addressed bytes — the same keyed digest family as
the org-keyed `text_hash` (ADR-0077), never a bare SHA-256 of plaintext. It
parses back through `address.Parse` to the same source (`source_object_id`),
object (`fragment_id`), version (`source_version_id`) and whole-text span, so a
client can verify the canonical address against the bytes it reassembled. A
value in the former URL address form is refused by `address.Parse` with a
malformed-address error. The `address` object above is preserved unchanged
beside it.

A caller-supplied `expected_span_hash` that does not equal the stored
whole-fragment `text_hash` is refused with the typed, content-free JSON-RPC
error `-32005` (`evidence span hash mismatch`) and no page text and no address
metadata — this is the tampered-index control. A caller-supplied `address` is
parsed with `address.Parse`: a malformed address, or one naming a different
source/object/version than the authorized fragment, is refused with the typed,
content-free `-32602` (`invalid evidence read arguments`) before any page text
or address is returned, and an address whose span hash does not verify against
the fragment's canonical text is refused with `-32005`. A denied, missing,
cross-tenant or cross-workspace fragment — including one named only by an
`address` — is the viewer's single `ErrNotFound`, mapped to the existing
content-free `-32004` (`evidence not found`) with no text, no address and no
workspace echo.

### Parameters

| field | type | required | notes |
| --- | --- | --- | --- |
| `workspace_id` | string | yes | The workspace that owns the fragment. |
| `fragment_id` | string | one of | The immutable fragment/citation id. Required unless `address` is supplied. |
| `address` | string | one of | Canonical compact `internal/address` value (`kv1:<object>:<version>:<span>:<hash16>`, where `<object>` is `<source_object_id>~<fragment_id>`). Parsed with `address.Parse`; when `fragment_id` is absent it selects the object, and when both are present they must name the same object. Its keyed span digest must verify against the fragment's canonical text. |
| `offset` | integer ≥ 0 | no | UTF-8 byte offset of the page start. Defaults to 0. |
| `limit` | integer ≥ 1 | no | Page size in bytes. Defaults to 4096, capped at 65536. |
| `expected_span_hash` | string | no | The caller's expected whole-fragment `text_hash`; a mismatch is refused with `-32005`. |
| `cursor` | string | no | Whole-object page cursor (R3a-1 KV-A02a). Its presence — even as `""`, which requests the first page — switches the read to the whole source version. Pass the `next_cursor` of the previous page to continue; a cursor this server did not produce, or one past the end of the original, is refused with `-32602`. Mutually exclusive with a non-zero `offset`. |
| `include_text_base64` | boolean | no | Default `false`. When `true`, `structuredContent.text_base64` additionally carries the base64 of the exact page bytes; the `content[].text` channel is identical either way and never carries the base64 copy. |

The server-side decoder accepts the optional `address`, `cursor` and
`include_text_base64` members in addition to the properties advertised in
`tools/list`. It is otherwise closed
(`additionalProperties: false`): a missing `workspace_id`, neither
`fragment_id` nor `address`, a negative or wrong-typed `offset`/`limit` or any
unknown member is rejected with `-32602` before the evidence viewer is touched.

### Request

```json
{
  "jsonrpc": "2.0",
  "id": "ev1",
  "method": "tools/call",
  "params": {
    "name": "knowvault_read",
    "arguments": {
      "workspace_id": "ws_alpha",
      "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "offset": 0,
      "limit": 4096
    }
  }
}
```

### Response (example)

```json
{
  "jsonrpc": "2.0",
  "id": "ev1",
  "result": {
    "content": [{ "type": "text", "text": "Hello, Know\nknowvault_read offset=0 length=11 next_offset=null has_more=false limit=4096 total_length=11 text_hash=hmac-sha256:k1:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b page_hash=sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0 canonical_address=kv1:object_01H9ABCDEFGHJKMNPQRSTVWXYZ~fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ:version_01H9ABCDEFGHJKMNPQRSTVWXYZ:text.0-11:6b1c0f2e9a4d4c1b address={\"object\":{\"extraction_id\":\"extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"fragment_id\":\"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"ordinal\":3},\"source\":{\"connection_id\":\"connection_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"source_object_id\":\"object_01H9ABCDEFGHJKMNPQRSTVWXYZ\"},\"span\":{\"anchor\":\"eyJsb2NhdG9yIjoiZmlsZTovL3ZvbC0xL3Byb2plY3RzL2FscGhhL2RvYy5tZCIsIm9mZnNldCI6MTIwfQ==\",\"length\":11,\"offset\":0,\"text_hash\":\"hmac-sha256:k1:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b\",\"total_length\":11},\"version\":{\"content_hash\":\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\",\"external_version_key\":\"hash:sha256:abababababababababababababababababababababababababababababababab\",\"observed_at\":\"2026-08-13T10:00:00Z\",\"source_version_id\":\"version_01H9ABCDEFGHJKMNPQRSTVWXYZ\"}}" }],
    "structuredContent": {
      "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "text": "Hello, Know",
      "offset": 0,
      "length": 11,
      "next_offset": null,
      "has_more": false,
      "limit": 4096,
      "total_length": 11,
      "text_hash": "hmac-sha256:k1:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b",
      "page_hash": "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
      "address": {
        "source": {
          "source_object_id": "object_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "connection_id": "connection_01H9ABCDEFGHJKMNPQRSTVWXYZ"
        },
        "version": {
          "source_version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "external_version_key": "hash:sha256:abababababababababababababababababababababababababababababababab",
          "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
          "observed_at": "2026-08-13T10:00:00Z"
        },
        "object": {
          "extraction_id": "extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "ordinal": 3,
          "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"
        },
        "span": {
          "offset": 0,
          "length": 11,
          "total_length": 11,
          "text_hash": "hmac-sha256:k1:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b",
          "anchor": "eyJsb2NhdG9yIjoiZmlsZTovL3ZvbC0xL3Byb2plY3RzL2FscGhhL2RvYy5tZCIsIm9mZnNldCI6MTIwfQ=="
        }
      },
      "canonical_address": "kv1:object_01H9ABCDEFGHJKMNPQRSTVWXYZ~fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ:version_01H9ABCDEFGHJKMNPQRSTVWXYZ:text.0-11:6b1c0f2e9a4d4c1b"
    },
    "isError": false
  }
}
```

When a direct fragment read is complete in the response itself (`offset` is 0
and `has_more` is `false`), the server may add an optional `neighbors` object
to `structuredContent`. It contains at most the immediate predecessor and
successor in the same active extraction:

```json
"neighbors": {
  "previous": { "fragment_id": "fragment_previous", "ordinal": 2, "canonical_address": "kv1:..." },
  "next": { "fragment_id": "fragment_next", "ordinal": 4, "canonical_address": "kv1:..." }
}
```

Each entry carries only the fragment id, ordinal and exact full-fragment
`canonical_address`; it never carries neighboring text. A missing boundary is
`null`; an adjacent fragment that fails its authorization or structural check
also leaves only that `previous` or `next` entry as `null`, while the other
side remains independently available. The same compact `neighbors=...` JSON is
appended to the MCP trailing metadata line so clients that consume only
`content[].text` can discover the addresses. Read a returned address separately
when the adjacent fragment is needed. Neighbor metadata is omitted from partial
fragment pages and from whole-object cursor pages. If the optional capability
is unsupported or returns an error, the whole `neighbors` member (and its MCP
trailing metadata) is omitted while the successful primary read remains.

To read one fragment in full, call again with `offset` = `next_offset` and repeat
until `has_more` is `false`; the concatenation of the `content[].text` page bytes
(the page text before each page's trailing metadata line) equals that fragment's
canonical text whose hash is `text_hash`. Each page's single trailing metadata
line also carries `canonical_address`, the exact kv1 string of
`structuredContent.canonical_address`, so a model that reads only
`content[].text` can pass that string straight back to `knowvault_read`. A
client that passed
`include_text_base64: true` may instead concatenate the decoded
`structuredContent.text_base64` payloads of every page, which are the same bytes.

### Whole-object page mode (R3a-1 KV-A02a)

Supplying the optional `cursor` member switches the same tool from reading one
fragment to reading the whole source version named by the `address` (or
`fragment_id`): the authorized, ordinal-ordered assembly of the version's
fragments that `evidence.Viewer.ReadObject` produces under the same
admission-before-data audit path as `knowvault_evidence_get`. This is how any
capable model reads a document larger than one response in full instead of
receiving a silently truncated answer.

`text_representation` states exactly which bytes are available:

- `CANONICAL_TEXT_V1_LAYOUT_V2`: a new TEXT-stream extraction (including HTML
  visible text) retains encrypted layout metadata. The reader verifies fragment
  offsets, exact LF gaps, anchors, total length and the canonical input hash.
- `CANONICAL_STRUCTURAL_TEXT_V1`: a new native Office/text-PDF extraction
  retains the parser's complete canonical object text, including one LF between
  consecutive structural units. Encrypted layout binds unit order/count, byte
  ranges, original structural anchors, total length and the complete text hash.
- `LEGACY_FRAGMENT_CONCAT_V1`: unchanged ordered fragment concatenation. This
  preserves historical addresses and hashes but cannot prove preservation of
  the input's boundary/final newlines. Older text extractions and structured
  Office/PDF extractions and email assemblies use this representation.

All modes return the complete available assembly with pagination. None is
an original binary-file download. Re-extraction creates new immutable fragment
IDs and addresses; old retained addresses continue to identify the old bytes.

- The first page is requested with `"cursor": ""`; continue with the
  `next_cursor` of the previous page until `has_more` is `false`, at which point
  `complete` is `true` and `next_cursor` is `null`.
- Every page reports `offset`, `length`, the effective `limit`, `total_bytes`
  (the size of the whole assembly, not the page), `has_more` and `whole_hash`.
- `whole_hash` is `address.WholeHash` — the shared canonical **unkeyed**
  `sha256:` of the returned assembly, present on every page, so a
  client can verify the concatenated page bytes — and
  `canonical_address` is the round-trippable `internal/address` value of the
  whole object: the same source/object/version over a span `[0, rune count)`
  whose `hash16` is the org-keyed ADR-0077 digest prefix of exactly that whole
  assembly. The two are deliberately different digest families: `whole_hash` is
  a bare SHA-256 that anyone holding the bytes can recompute, while the address
  digest is keyed and is not derivable from plaintext offline.
  Concatenating the `content[].text` page bytes (or, when the caller passed
  `include_text_base64: true`, the decoded `structuredContent.text_base64`
  payloads) of every page reproduces that assembly byte for byte and hashes
  to `whole_hash`.
- `fragment_count`, `ordinal_start` and `ordinal_end` describe the assembled
  ordinal span. `address` remains the anchor fragment's map, exactly as in the
  single-fragment mode.
- The KV-A01c address semantics are unchanged: the address must name the same
  source/object/version as the authorized anchor fragment (or a named
  code-source `ref` that resolves to that immutable version, see the named-ref
  section below), and its span hash
  must verify against the anchor fragment's canonical text (or against the
  reassembled whole text, so the `canonical_address` this mode emits can be
  passed back). A tampered address is refused with `-32005` and no page content.
- A cursor this server did not produce (`not-a-cursor`, `v1:abc`, `v1:-4`) and
  a cursor past the end of the original (`v1:999999`) are refused with the typed,
  content-free `-32602` without serving a page.
- Whole-object mode requires the deployment to mount the whole-object read
  capability; a service that only serves single fragments fails closed with
  `-32000` and no content. A denied or cross-workspace read is the single
  content-free `-32004`.

Example request (first page):

```json
{
  "jsonrpc": "2.0",
  "id": "ev2",
  "method": "tools/call",
  "params": {
    "name": "knowvault_read",
    "arguments": {
      "workspace_id": "ws_alpha",
      "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "address": "kv1:object_01H9ABCDEFGHJKMNPQRSTVWXYZ~fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ:version_01H9ABCDEFGHJKMNPQRSTVWXYZ:text.0-11:6b1c0f2e9a4d4c1b",
      "cursor": "",
      "limit": 4096
    }
  }
}
```

Example response (first of three pages):

```json
{
  "jsonrpc": "2.0",
  "id": "ev2",
  "result": {
    "content": [{ "type": "text", "text": "First page of the whole document\nknowvault_read offset=0 length=31 next_cursor=v1:31 has_more=true complete=false limit=4096 total_bytes=12288 whole_hash=sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809 page_hash=sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0 canonical_address=kv1:object_01H9ABCDEFGHJKMNPQRSTVWXYZ~fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ:version_01H9ABCDEFGHJKMNPQRSTVWXYZ:text.0-12288:4e6d8c2b3a5f7e9d address={\"object\":{\"extraction_id\":\"extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"fragment_id\":\"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"ordinal\":1},\"source\":{\"connection_id\":\"connection_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"source_object_id\":\"object_01H9ABCDEFGHJKMNPQRSTVWXYZ\"},\"span\":{\"anchor\":\"eyJsb2NhdG9yIjoiZmlsZTovL3ZvbC0xL3Byb2plY3RzL2FscGhhL2RvYy5tZCIsIm9mZnNldCI6MTIwfQ==\",\"length\":15,\"offset\":0,\"text_hash\":\"hmac-sha256:k1:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b\",\"total_length\":15},\"version\":{\"content_hash\":\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\",\"external_version_key\":\"hash:sha256:abababababababababababababababababababababababababababababababab\",\"observed_at\":\"2026-08-13T10:00:00Z\",\"source_version_id\":\"version_01H9ABCDEFGHJKMNPQRSTVWXYZ\"}}" }],
    "structuredContent": {
      "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "text": "First page of the whole document",
      "offset": 0,
      "length": 31,
      "next_cursor": "v1:31",
      "has_more": true,
      "complete": false,
      "limit": 4096,
      "total_bytes": 12288,
      "whole_hash": "sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
      "page_hash": "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
      "address": {
        "source": {
          "source_object_id": "object_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "connection_id": "connection_01H9ABCDEFGHJKMNPQRSTVWXYZ"
        },
        "version": {
          "source_version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "external_version_key": "hash:sha256:abababababababababababababababababababababababababababababababab",
          "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
          "observed_at": "2026-08-13T10:00:00Z"
        },
        "object": {
          "extraction_id": "extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "ordinal": 1,
          "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"
        },
        "span": {
          "offset": 0,
          "length": 15,
          "total_length": 15,
          "text_hash": "hmac-sha256:k1:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b",
          "anchor": "eyJsb2NhdG9yIjoiZmlsZTovL3ZvbC0xL3Byb2plY3RzL2FscGhhL2RvYy5tZCIsIm9mZnNldCI6MTIwfQ=="
        }
      },
      "canonical_address": "kv1:object_01H9ABCDEFGHJKMNPQRSTVWXYZ~fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ:version_01H9ABCDEFGHJKMNPQRSTVWXYZ:text.0-12288:4e6d8c2b3a5f7e9d",
      "fragment_count": 3,
      "ordinal_start": 1,
      "ordinal_end": 3
    },
    "isError": false
  }
}
```

Continue with `"cursor": "v1:31"` (and the same address or `fragment_id`) until
`has_more` is `false`; the concatenation of every page's `content[].text` bytes
equals the assembly whose `whole_hash` is reported on every page. A client
that passed `include_text_base64: true` may instead concatenate the decoded
`structuredContent.text_base64` payloads of every page, which are the same bytes.

### Named-ref code-source reads (R3a-1 KV-A04b)

An `address` whose version is a named code-source `ref` (rather than an
immutable `source_version_id`) is resolved from the workspace object inventory
metadata **before any fragment content is read**, then read through the same
authorized `Evidence.Read`/`EvidenceWholeObject` path as any other address. The
version is matched against the registered git code-source object's
`external_version_key` identity (`object_type` `GIT_FILE`), exactly the identity
`knowvault_grep` scoped on: the whole key, the key with `native:` stripped, or
any of its `;`-separated `key:value` tokens (for example the `commit:` token).
Only a `GIT_FILE` object can resolve a ref, so a ref never widens a read onto a
document object.

- The `canonical_address` a ref-scoped `knowvault_grep` hit returns carries the
  ref as its `<version>`; passing it back to `knowvault_read` resolves it to the
  immutable source version the ref named and serves that code source.
- The read parameters are unchanged: `workspace_id` plus the `address` (or
  `fragment_id`), an optional `offset`/`limit` for a byte window, or `cursor`
  for whole-object page mode. Because a ref-scoped grep address spans the whole
  reassembled object, read it in whole-object page mode: request the first page
  with `"cursor": ""` and continue with `next_cursor` until `has_more` is
  `false`, reassembling every page's `content[].text` bytes (or the decoded
  `structuredContent.text_base64` when the caller passed
  `include_text_base64: true`) and checking `whole_hash`.
- An unknown or foreign ref resolves to nothing in the inventory and is refused
  with the existing typed, content-free `-32602`/`400 REQUEST_INVALID` and no
  page text and no address; a denied, unknown or cross-workspace read is still
  the single content-free `-32004`/`404 NOT_FOUND`, and no content is read to
  decide. A tampered address or a mismatching `expected_span_hash` remains
  `-32005`/`409 EVIDENCE_SPAN_HASH_MISMATCH`. The MCP tool schema, the
  advertised names and every route are unchanged.

Example request (first page of a ref-scoped grep address):

```json
{
  "jsonrpc": "2.0",
  "id": "ev3",
  "method": "tools/call",
  "params": {
    "name": "knowvault_read",
    "arguments": {
      "workspace_id": "ws_alpha",
      "address": "kv1:object_01H9ABCDEFGHJKMNPQRSTVWXYZ~fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ:9f2c4a1b7d3e5f6081a2b3c4d5e6f708192a3b4:text.0-42:6b1c0f2e9a4d4c1b",
      "cursor": "",
      "limit": 4096
    }
  }
}
```

Example response (the ref resolved to `version_01H9ABCDEFGHJKMNPQRSTVWXYZ`;
the whole object fits one page here):

```json
{
  "jsonrpc": "2.0",
  "id": "ev3",
  "result": {
    "content": [{ "type": "text", "text": "package main\n\nfunc main() {}\n\nknowvault_read offset=0 length=28 next_cursor=null has_more=false complete=true limit=4096 total_bytes=28 whole_hash=sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809 page_hash=sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0 canonical_address=kv1:object_01H9ABCDEFGHJKMNPQRSTVWXYZ~fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ:version_01H9ABCDEFGHJKMNPQRSTVWXYZ:text.0-28:6b1c0f2e9a4d4c1b address={\"object\":{\"extraction_id\":\"extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"fragment_id\":\"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"ordinal\":1},\"source\":{\"connection_id\":\"connection_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"source_object_id\":\"object_01H9ABCDEFGHJKMNPQRSTVWXYZ\"},\"span\":{\"anchor\":\"eyJsb2NhdG9yIjoiZmlsZTovL3ZvbC0xL3Byb2plY3RzL2FscGhhL2RvYy5tZCIsIm9mZnNldCI6MTIwfQ==\",\"length\":28,\"offset\":0,\"text_hash\":\"hmac-sha256:k1:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b\",\"total_length\":28},\"version\":{\"content_hash\":\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\",\"external_version_key\":\"native:commit:9f2c4a1b7d3e5f6081a2b3c4d5e6f708192a3b4\",\"observed_at\":\"2026-08-13T10:00:00Z\",\"source_version_id\":\"version_01H9ABCDEFGHJKMNPQRSTVWXYZ\"}}" }],
    "structuredContent": {
      "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "text": "package main\n\nfunc main() {}\n",
      "offset": 0,
      "length": 28,
      "next_cursor": null,
      "has_more": false,
      "complete": true,
      "limit": 4096,
      "total_bytes": 28,
      "whole_hash": "sha256:1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809",
      "page_hash": "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
      "address": {
        "source": { "source_object_id": "object_01H9ABCDEFGHJKMNPQRSTVWXYZ", "connection_id": "connection_01H9ABCDEFGHJKMNPQRSTVWXYZ" },
        "version": { "source_version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ", "external_version_key": "native:commit:9f2c4a1b7d3e5f6081a2b3c4d5e6f708192a3b4", "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "observed_at": "2026-08-13T10:00:00Z" },
        "object": { "extraction_id": "extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ", "ordinal": 1, "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ" },
        "span": { "offset": 0, "length": 28, "total_length": 28, "text_hash": "hmac-sha256:k1:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b", "anchor": "eyJsb2NhdG9yIjoiZmlsZTovL3ZvbC0xL3Byb2plY3RzL2FscGhhL2RvYy5tZCIsIm9mZnNldCI6MTIwfQ==" }
      },
      "canonical_address": "kv1:object_01H9ABCDEFGHJKMNPQRSTVWXYZ~fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ:version_01H9ABCDEFGHJKMNPQRSTVWXYZ:text.0-28:6b1c0f2e9a4d4c1b",
      "fragment_count": 1,
      "ordinal_start": 1,
      "ordinal_end": 1
    },
    "isError": false
  }
}
```

The same read is served over REST with `GET`/`POST
/api/v1/workspaces/{workspace_id}/tools/read?address=<kv1 address>&cursor=v1:0`
and the identical response projection.

### REST parity

`knowvault_read` is also served over REST at

```
GET  /api/v1/workspaces/{workspace_id}/tools/read?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&offset=0&limit=4096
POST /api/v1/workspaces/{workspace_id}/tools/read?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&offset=0&limit=4096
```

with the same authorized implementation, the same projection and the same
pagination as the MCP tool, so a REST client and an MCP client observe identical
pages and reassemble identical bytes. The route dispatches through the identical
`Evidence.Read` viewer and the identical `EvidenceWholeObject` +
`address.Read` whole-object path `knowvault_read` composes, so
admission-before-data, the R1 audit journal and the content-free denial stay
exactly the existing ones. The MCP `arguments` map onto the query string:
`fragment_id` or the canonical `address` (at least one, and if both are supplied
they must name the same object), the optional `offset`, `limit`,
`expected_span_hash` and `cursor`.

`offset` and `limit` are unsigned decimal integers: `limit` absent or `0` means
the default 4096-byte page, a requested limit is capped at 65536 and the
effective value is echoed as `limit`; an `offset` past the end of the text is
`400 REQUEST_INVALID`. The presence of `cursor` (the stable `v1:<offset>` form
returned as `next_cursor`) switches the read to whole-object page mode exactly as
the MCP cursor member does; the first whole-object page is requested as
`cursor=v1:0`, and a non-zero `offset` combined with `cursor`, a malformed
cursor or a cursor past the end of the original is `400 REQUEST_INVALID`. The
whole-object response carries `offset`, `length`, `next_cursor`, `has_more`,
`complete`, the effective `limit`, `total_bytes`, `whole_hash`, `page_hash`,
`address`, `canonical_address`, `fragment_count`, `ordinal_start` and
`ordinal_end`; the fragment response carries `fragment_id`, `text`,
`text_base64`, `offset`, `length`, `next_offset`, `has_more`, the effective
`limit`, `total_length`, `text_hash`, `page_hash`, `address` and
`canonical_address`.

A tampered `address` (its keyed span digest does not verify) or an
`expected_span_hash` that does not equal the stored whole-fragment `text_hash` is
the typed, content-free `409 EVIDENCE_SPAN_HASH_MISMATCH` mapped from the MCP
`-32005`, with no page bytes and no address metadata. A missing selector, an
unparsable or object-mismatching `address`, a negative, overflowing or
non-decimal `offset`/`limit`, an unknown or past-end `cursor`, unknown query
keys, duplicates, an empty value and a malformed encoding are all `400
REQUEST_INVALID` before any fragment is read. The POST form is the same operation
for clients that invoke knowledge tools with a POST request: parameters travel in
the query string, the request body is not a parameter channel, and a non-empty
body is refused as `400 REQUEST_INVALID` rather than being silently ignored; the
CSRF gate of every other unsafe method applies. An unknown workspace or a
non-member caller gets the same content-free denial as the MCP tool, here `404
NOT_FOUND` with no text and no workspace-id echo; a service mounted without the
whole-object capability fails closed as `503 SERVICE_UNAVAILABLE`. The route is
declared as an `endpointKind` with an `openAPIRoutes` entry and an
`api/openapi.yaml` path item describing both methods, so the OpenAPI drift gate
covers it. The MCP `tools/list` advertisement and every other REST/MCP route are
unchanged.

## `knowvault_sources`

Read-only inventory of every source bound to the current revision of one
workspace, with its full sync status, schedule fields and the ADR-0087 §1-§2
confirmation context. It composes the same `SourceService.ListSources` and
`SourceService.ConfirmationContext` reads as the REST
`GET /api/v1/workspaces/{id}/sources` route and returns the identical
projection. R3a-1 Outcome 2. It is advertised and dispatched under the
canonical name `knowvault_sources`: that is the name a client sees in
`tools/list` and should send in `tools/call`. The former advertised name
`knowvault_sources_list` stays dispatchable to the byte-identical
source-inventory core for clients that pinned it, but it is never advertised;
any other spelling is refused as an unknown tool with `-32602` and no content.

The production workspace repository admits each metadata read before reading
source projections and rechecks current authorization in the read transaction.
`ListSources` and `ConfirmationContext` each persist
`source.metadata.read.admitted` followed by `source.metadata.read.completed`
or `source.metadata.read.failed`. One successful tool call therefore writes
four events, with the caller's request ID, `HUMAN` or `SERVICE` actor and
`WORKSPACE` resource. The only metadata is one closed `reason_codes` value:
`SOURCE_STATUS_LIST` or `SOURCE_CONFIRMATION_CONTEXT`. The source inventory,
connection names, grants and text are absent from audit metadata.
`knowvault_source_schema`'s two reads use `SOURCE_SCHEMA_LIST` and
`SOURCE_SCHEMA` in that same closed field.

Denials persist admitted/failed with outcome `DENIED` and
`SOURCE_METADATA_READ_DENIED`; an unknown or foreign-organization workspace
uses a null audit `workspace_id` to avoid an invalid foreign key. A known
workspace keeps its ID, including denied calls, for its authorized journal.
Read failures use outcome `FAILED` and `SOURCE_METADATA_READ_FAILED`.
Failure to write admission or completion returns no metadata. After request
cancellation, terminal failure persistence uses an independent timeout of
five seconds. These events audit source metadata, not access to the audit
journal itself. MCP, REST and the product chat tool loop use this same boundary.

### Parameters

| field | type | required | notes |
| --- | --- | --- | --- |
| `workspace_id` | string | yes | The workspace whose current source bindings are read. No other member is accepted (`additionalProperties: false`). |

The schema is closed: a missing or empty `workspace_id`, a wrong-typed member or
any unknown member is rejected with JSON-RPC error `-32602` before either
service read is touched.

### Request

```json
{
  "jsonrpc": "2.0",
  "id": "src1",
  "method": "tools/call",
  "params": {
    "name": "knowvault_sources",
    "arguments": { "workspace_id": "ws_alpha" }
  }
}
```

### Response (example)

```json
{
  "jsonrpc": "2.0",
  "id": "src1",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "knowvault_sources: 1 source(s)\n[1] workspace_source_id=wsrc_01H9ABCDEFGHJKMNPQRSTVWXYZ source_scope_id=scope_01H9ABCDEFGHJKMNPQRSTVWXYZ enabled=true activation_status=READY sync_status=SYNCED freshness_state=FRESH sync_interval_seconds=1800 last_successful_sync_at=2026-09-12T10:02:00Z confirmation_state=ACTIVE\n"
      }
    ],
    "structuredContent": {
      "sources": [
        {
          "workspace_source_id": "wsrc_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "source_scope_id": "scope_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "source_scope_revision": 2,
          "access_mode": "WORKSPACE_MANAGED",
          "enabled": true,
          "scope_config_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "connection_id": "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "connection_name": "Engineering docs",
          "activation_status": "READY",
          "trust_verified": true,
          "sync_status": "SYNCED",
          "sync_error_code": "NONE",
          "sync_started_at": "2026-09-12T10:00:00Z",
          "sync_completed_at": "2026-09-12T10:02:00Z",
          "objects_seen": 10,
          "objects_ingested": 9,
          "versions_created": 9,
          "evidence_published": 9,
          "quarantined": 1,
          "job_id": "job_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "job_status": "QUEUED",
          "job_attempt_count": 0,
          "job_max_attempts": 3,
          "job_available_at": "2026-09-12T10:00:00Z",
          "job_lease_expires_at": "2026-09-12T10:02:00Z",
          "job_last_error_code": "NONE",
          "content_freshness_sla_seconds": 3600,
          "last_successful_sync_at": "2026-09-12T10:02:00Z",
          "freshness_state": "FRESH",
          "sync_interval_seconds": 1800,
          "confirmed": true,
          "confirmation_state": "ACTIVE",
          "can_verify_connection_trust": true
        }
      ],
      "confirmation_context": {
        "expected_policy_revision": "policy-acc-0001",
        "warning_contract": {
          "warning_version": "workspace-managed-risk-v1",
          "warning_contract_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "viewer_principal_id": "principal_alpha",
        "can_issue_confirmation_grant": true,
        "can_verify_connection_trust": true,
        "self_grant": {
          "grant_id": "grant_01",
          "grant_revision": 1,
          "grant_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "valid_until": "2026-09-06T15:00:00Z"
        }
      }
    },
    "isError": false
  }
}
```

The `content[0].text` channel carries the same inventory in a compact,
model-readable form: a leading line with the source count, then one line per
source with its `workspace_source_id`, `source_scope_id`, `enabled`,
`activation_status`, `sync_status`, `freshness_state`, `sync_interval_seconds`,
`last_successful_sync_at` and `confirmation_state`, so a client that reads only
the text channel never loses a source the `structuredContent` channel carried.
An absent optional status member is rendered as the literal `null`.

### Denial

An unknown workspace, or one the caller is not a member of, produces the
content-free denial the REST route produces (`404 NOT_FOUND` there), mapped to
JSON-RPC error `-32004` with message `source scope not found`. The response
contains no source content and never echoes the requested workspace id.

### REST parity

`knowvault_sources` is also served over REST at

```
GET  /api/v1/workspaces/{workspace_id}/tools/sources
POST /api/v1/workspaces/{workspace_id}/tools/sources
```

with the same authorized implementation and the byte-identical
`{sources, confirmation_context}` projection, so a REST client and an MCP client
observe identical source inventory and schedule state. The route composes
exactly the same injected `SourceService.ListSources` and
`SourceService.ConfirmationContext` reads and renders them through the same
projection function the MCP tool and the existing
`GET /api/v1/workspaces/{id}/sources` route use; it introduces no second read,
authorization decision or audit path; the repository's source metadata
admission and terminal outcome cover both transports. There are no
parameters: the route accepts no query key, so unknown keys, duplicates, empty
values and a bare `?` are `400 REQUEST_INVALID` before either service read. The
POST form is the same operation for clients that invoke knowledge tools with a
POST request: the request body is not a parameter channel, a non-empty body is
refused as `400 REQUEST_INVALID` rather than being silently ignored, and the
CSRF gate of every other unsafe method applies. An unknown workspace or a
non-member caller gets the same content-free denial as the MCP tool, here `404
NOT_FOUND` with no source content and no workspace-id echo; an unauthenticated
request is `401`, and a service mounted without the source capability fails
closed as `503 SERVICE_UNAVAILABLE` (the REST twin of the MCP `-32000`). The
route is declared as an `endpointKind` with an `openAPIRoutes` entry and an
`api/openapi.yaml` path item describing both methods, so the OpenAPI drift gate
covers it. The MCP canonical name is `knowvault_sources` (the former name
`knowvault_sources_list` stays accepted for dispatch only); the MCP
`tools/list` advertisement and every other REST/MCP route are unchanged, and no
wiki-rag alias is advertised or dispatched.

Example response (identical to the MCP `structuredContent` above):

```json
{
  "sources": [
    {
      "workspace_source_id": "wsrc_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "source_scope_id": "scope_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "source_scope_revision": 2,
      "access_mode": "WORKSPACE_MANAGED",
      "enabled": true,
      "scope_config_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "connection_id": "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "connection_name": "Engineering docs",
      "activation_status": "READY",
      "trust_verified": true,
      "sync_status": "SYNCED",
      "sync_error_code": "NONE",
      "sync_started_at": "2026-09-12T10:00:00Z",
      "sync_completed_at": "2026-09-12T10:02:00Z",
      "objects_seen": 10,
      "objects_ingested": 9,
      "versions_created": 9,
      "evidence_published": 9,
      "quarantined": 1,
      "job_id": "job_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "job_status": "QUEUED",
      "job_attempt_count": 0,
      "job_max_attempts": 3,
      "job_available_at": "2026-09-12T10:00:00Z",
      "job_lease_expires_at": "2026-09-12T10:02:00Z",
      "job_last_error_code": "NONE",
      "content_freshness_sla_seconds": 3600,
      "last_successful_sync_at": "2026-09-12T10:02:00Z",
      "freshness_state": "FRESH",
      "sync_interval_seconds": 1800,
      "confirmed": true,
      "confirmation_state": "ACTIVE",
      "can_verify_connection_trust": true
    }
  ],
  "confirmation_context": {
    "expected_policy_revision": "policy-acc-0001",
    "warning_contract": {
      "warning_version": "workspace-managed-risk-v1",
      "warning_contract_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    },
    "viewer_principal_id": "principal_alpha",
    "can_issue_confirmation_grant": true,
    "can_verify_connection_trust": true,
    "self_grant": {
      "grant_id": "grant_01",
      "grant_revision": 1,
      "grant_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "valid_until": "2026-09-06T15:00:00Z"
    }
  }
}
```

## `knowvault_source_schema`

Read-only schema of one PostgreSQL source enabled in the caller's workspace
(ADR-0097, S3 card 1): its tables, columns, native types, primary keys and
`pg_class` row estimates, plus the workspace model context notes for the
source, its tables and its columns. It answers from data an earlier
registration already stored -- the immutable, exclusion-narrowed
`postgresql_query_projection` rows and their `postgresql_query_relation_catalog`
companion -- so it opens no source database, composes no SQL and runs no
statement. A column the administrator excluded at registration was never
written into the projection and is therefore never returned.

Without `source_id` the tool lists the workspace's enabled PostgreSQL sources:
id (the source connection id `knowvault_sources` returns), display name and the
number of registered tables. With `source_id` it returns one page of tables,
optionally narrowed to one `schema.name`. `limit` is at most 50 and an omitted
limit is 50; `has_more`/`next_offset` page the table list explicitly, with no
silent truncation. A note authored in the workspace model context wins; the
discovery-time relation/column comment is the fallback, and `context_version`
reports the model context version the notes were read from (0 when no reader is
mounted).

Every call is authorized exactly like `knowvault_sources`: the two repository
reads go through the same admission-before-data `source.metadata.read.*`
boundary, so an unknown, foreign, disabled or non-member source is the single
content-free `NOT_FOUND` (`-32004` over MCP) with no schema content and no
source-id echo. A composition mounted without the capability fails closed with
`-32000`.

### Parameters

| field | type | required | notes |
| --- | --- | --- | --- |
| `workspace_id` | string | yes | The workspace whose enabled PostgreSQL sources are read. |
| `source_id` | string | no | The source connection id. Omit it to list the workspace's PostgreSQL sources. |
| `table` | string | no | Optional `schema.name` selector. |
| `offset` | integer | no | Zero-based table offset. |
| `limit` | integer | no | Page size, 1..50; defaults to 50. |

The schema is closed: an unknown member, a limit over 50, a negative offset or a
malformed `table` selector is rejected with JSON-RPC error `-32602` before the
provider is touched.

### Request

```json
{
  "jsonrpc": "2.0",
  "id": "schema1",
  "method": "tools/call",
  "params": {
    "name": "knowvault_source_schema",
    "arguments": { "workspace_id": "ws_alpha", "source_id": "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ" }
  }
}
```

### Response (example)

```json
{
  "source_id": "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ",
  "database_identity": "pgdb:4d2a0f6c8b1e5a9d3c7f2b6e0a4d8c1f5b9e3a7d2c6f0b4e8a1d5c9f3b7e2a6d",
  "context_version": 3,
  "source_note": "Primary operational database.",
  "tables": [
    {
      "schema": "public",
      "name": "contract",
      "kind": "TABLE",
      "row_estimate": 17030,
      "note": "Договоры",
      "columns": [
        { "name": "id", "type": "uuid", "nullable": false, "primary_key": true, "note": "surrogate key" },
        { "name": "amount", "type": "numeric", "nullable": true, "primary_key": false, "note": "Сумма договора" }
      ]
    }
  ],
  "next_offset": 0,
  "has_more": false
}
```

Without `source_id`:

```json
{ "sources": [ { "id": "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ", "name": "Ops database", "table_count": 3 } ] }
```

## `knowvault_source_sql`

Run one read-only statement the agent writes against one PostgreSQL source
enabled in the caller's workspace (ADR-0097, S3 card 2). The agent reads the
source's tables and columns with `knowvault_source_schema` first and then sends
exactly one `SELECT` or `WITH` statement. This is the only workspace knowledge
tool that accepts SQL text, and the only SQL it can run is one statement against
one source: the statement executes with the source's own query credential (a
role distinct from the ingestion role) inside a read-only transaction, under the
shared governed-execution statement timeout, `EXPLAIN` cost cap and row/byte
cap. Every relation PostgreSQL's planner touches must belong to the source's
registered tables, so `pg_catalog`, `information_schema`, another schema and a
function scan are refused before execution. A column the administrator excluded
is refused by the query role's own column grants.

A deterministic pre-`EXPLAIN` gate additionally refuses, with
`SQL_REJECTED_STATIC`, any statement that could change a session setting
(`set_config`, or any `SET` form, including quoted, schema-qualified or
Unicode-escaped spellings) and any use of the cross-session, server-file and
large-object function families (`pg_stat_get_*`/`pg_stat_activity`-style
functions, `pg_cancel_backend`, `pg_terminate_backend`, `pg_backend_pid`,
advisory locks, `pg_sleep*`, the `*_to_xml`/`*_to_json` query-executing family,
`lo_*`, `pg_read_*`, `pg_ls_*`). Function names are matched case-folded with
quotes and schema qualifiers stripped.

The query role itself must still be least privilege, and the proof now also
requires a bounded `work_mem` (at most 64 MB) and `temp_file_limit` (pinned,
neither unlimited nor above 1 GB), no readable large object, no executable
function in an untrusted procedural language, and no executable `SECURITY
DEFINER` function that is not owned by the bootstrap superuser, in every schema
including `pg_catalog`. The proof runs inside the statement's own read-only
transaction on every execution, so a stored proof can never authorize a later
statement after the role, the credential or the projection changes.

The result is the whole text table with its row count, SQL hash, result digest
and database identity. Each attempt is audited with the source id, SQL hash and
result digest; a failed audit returns no rows. At most three successful
statements are allowed per chat run — a statement that reached execution
consumes the budget even when its result is too large to retain or its
post-processing fails — and parallel query workers are disabled.

An unknown, foreign, disabled or non-member source is the single content-free
`NOT_FOUND` (`-32004` over MCP), exactly like `knowvault_source_schema`. A
connection without a query credential is a successful tool result with
`{"error":"SOURCE_SQL_NOT_CONFIGURED"}`, and a composition mounted without the
capability fails closed with `-32000`.

### Parameters

| field | type | required | notes |
| --- | --- | --- | --- |
| `workspace_id` | string | yes | The workspace whose enabled source is queried. |
| `source_id` | string | yes | The source connection id `knowvault_sources` or `knowvault_source_schema` returns. |
| `sql` | string | yes | Exactly one `SELECT`/`WITH` statement, at most 8192 bytes. |
| `purpose` | string | no | Short note on what the statement answers, at most 200 characters. |

### Request

```json
{
  "jsonrpc": "2.0",
  "id": "sql1",
  "method": "tools/call",
  "params": {
    "name": "knowvault_source_sql",
    "arguments": {
      "workspace_id": "ws_alpha",
      "source_id": "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "sql": "SELECT count(*) FROM public.contract WHERE status = 'active'",
      "purpose": "how many contracts are active"
    }
  }
}
```

### Response (example)

```json
{
  "format": "postgres-text-table-v1",
  "columns": ["count"],
  "rows": [["3"]],
  "row_count": 1,
  "attempt_id": "gqat_01H9ABCDEFGHJKMNPQRSTVWXYZ",
  "sql_hash": "sha256:4d2a0f6c8b1e5a9d3c7f2b6e0a4d8c1f5b9e3a7d2c6f0b4e8a1d5c9f3b7e2a6d",
  "result_digest": "sha256:8b1e5a9d3c7f2b6e0a4d8c1f5b9e3a7d2c6f0b4e8a1d5c9f3b7e2a6d4d2a0f6c",
  "database_identity": "pgdb:4d2a0f6c8b1e5a9d3c7f2b6e0a4d8c1f5b9e3a7d2c6f0b4e8a1d5c9f3b7e2a6d",
  "execution_started_at": "2026-09-24T10:00:00Z",
  "execution_completed_at": "2026-09-24T10:00:01Z",
  "complete": true
}
```

### Closed refusals

A refused statement is a successful tool result (MCP `isError: true`) whose JSON
body carries one closed `error` code, so an agent can react to it:
`SQL_REJECTED_STATIC`, `RELATION_NOT_IN_SOURCE`, `COST_LIMIT`, `ROW_LIMIT`,
`TIMEOUT`, `DATABASE_REJECTED` or `SOURCE_SQL_NOT_CONFIGURED`.

## `knowvault_refresh`

Refresh the sources of one workspace that allow it, through the same authorized
`SourceService.ListSources` read and `SourceService.Sync` command the REST
`GET /api/v1/workspaces/{id}/sources` and `POST /api/v1/sources/{scope}:sync`
routes compose (R3a-1 Outcome 2 / design item 4(4)). It resolves the workspace's
bound sources, skips every source that does not currently allow a refresh and
reports the closed content-free reason, and submits a refresh job for the rest.
A skipped source is not a failure: the response carries it so the caller learns
which sources were left alone and why.

`knowvault_refresh` is deliberately distinct from the administrative
`knowvault_source_sync` (ADR-0087 §3): that tool is a bare per-scope OWNER
command, while `knowvault_refresh` is workspace-scoped and is offered to a V1-C
SERVICE agent access-code principal exactly as the other knowledge tools are.

The resolved source list is paginated with an explicit window: `offset`, the
effective `limit`, `has_more` and, while more remains, `next_offset`. A limit is
never silent truncation — continuing from `next_offset` until `has_more` is
`false` and concatenating the pages observes every source of the workspace. The
default page is 100 sources and a requested limit is capped at 1000; the
effective value is always echoed as `limit`.

Where a refresh is narrowed to one `source_scope_id` that is not bound to the
workspace, the call gets the same content-free not-found a denied workspace
produces. The one exception is a workspace whose source inventory is empty: it
cannot disambiguate the explicitly named scope, so that named scope is submitted
once to the authorized `Sync`, which re-authorizes it and re-checks readiness,
trust and confirmation instead of inventing a membership answer from an empty
inventory.

### Parameters

| field | type | required | notes |
| --- | --- | --- | --- |
| `workspace_id` | string | yes | The workspace whose refreshable sources are refreshed. |
| `source_scope_id` | string | no | Narrow the call to exactly one bound scope. At most 128 characters; must be non-empty when present. |
| `offset` | integer ≥ 0 | no | Zero-based source offset of the page. Defaults to 0. |
| `limit` | integer ≥ 0 | no | Page size in sources. Defaults to 100 when omitted or `0`, capped at 1000. The advertised `inputSchema` sets `minimum: 1`; as on the REST twin a `limit` of `0` is not an error but means the default page. |

The schema is closed (`additionalProperties: false`): a missing or empty
`workspace_id`, a negative or wrong-typed `offset`/`limit`, a `source_scope_id`
longer than 128 characters or any unknown member is rejected with JSON-RPC error
`-32602` before the source service is touched.

### Skip reasons

A bound source that does not allow a refresh is reported in `skipped` with one
closed, content-free `reason`:

| reason | meaning |
| --- | --- |
| `DISABLED` | The source scope binding is not enabled. |
| `NOT_READY` | The activation status is not `READY`. |
| `TRUST_UNVERIFIED` | The connection trust has not been verified. |
| `NOT_CONFIRMED` | The workspace-managed confirmation is not live. |

### Text channel

`content[0].text` carries the same page the `structuredContent` member carries,
in a form a model can read directly without parsing JSON: a leading count line,
then exactly one single-line entry per refreshed source (`source_scope_id` and
`job_id`) and per skipped source (`source_scope_id` and `reason`), then a
trailing cursor line with `offset`, the effective `limit`, `has_more` and
`next_offset` (the literal `null` on the final page). Multi-line values are
flattened so one source is always exactly one line, and the page is not
duplicated as a JSON copy. A client that reads only `content` therefore sees
every refreshed job, every skip reason and the page position, and can continue
from `next_offset` exactly as a client reading `structuredContent` can.

### Request

```json
{
  "jsonrpc": "2.0",
  "id": "rf1",
  "method": "tools/call",
  "params": {
    "name": "knowvault_refresh",
    "arguments": { "workspace_id": "ws_alpha", "limit": 100 }
  }
}
```

### Response (example)

```json
{
  "jsonrpc": "2.0",
  "id": "rf1",
  "result": {
    "content": [{ "type": "text", "text": "knowvault_refresh: 1 source(s) refreshed, 1 skipped\n[1] source_scope_id=scope_01H9ABCDEFGHJKMNPQRSTVWXYZ job_id=job_01H9ABCDEFGHJKMNPQRSTVWXYZ\n[2] source_scope_id=scope_01H9ABCDEFGHJKMNPQRSTVWXY0 reason=TRUST_UNVERIFIED\noffset=0 limit=100 has_more=false next_offset=null\n" }],
    "structuredContent": {
      "refreshed": [
        {
          "source_scope_id": "scope_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "job_id": "job_01H9ABCDEFGHJKMNPQRSTVWXYZ"
        }
      ],
      "skipped": [
        {
          "source_scope_id": "scope_01H9ABCDEFGHJKMNPQRSTVWXY0",
          "reason": "TRUST_UNVERIFIED"
        }
      ],
      "offset": 0,
      "limit": 100,
      "has_more": false,
      "next_offset": null
    },
    "isError": false
  }
}
```

### Denial and audit

An unknown workspace, or one the caller is not a member of, produces the
content-free denial the REST route produces (`404 NOT_FOUND` there), mapped to
JSON-RPC error `-32004` with message `source scope not found`; the response
carries no source row, no skip reason and never echoes the requested workspace
id. An unauthenticated caller is the shared `401`, and a composition mounted
without the source capability fails closed with `-32000` and no content. As with
every knowledge tool in this document, a V1-C SERVICE principal sees and may
call this tool exactly as a human session does; only the administrative tools
stay closed to it. The call is admitted through the existing audit journal
before any source is read and its outcome (including the denial class) is
journalled afterwards.

When the authorized `Sync` refuses a submission as conflicting with an update
already in flight, the MCP transport maps it to JSON-RPC error `-32009` with
message `source sync conflict`, the twin of the REST `409 SOURCE_CONFLICT`.

### REST parity

`knowvault_refresh` is also served over REST at

```
GET  /api/v1/workspaces/{workspace_id}/tools/refresh
POST /api/v1/workspaces/{workspace_id}/tools/refresh
```

with the same authorized implementation, the byte-identical
`{refreshed, skipped, offset, limit, has_more, next_offset}` projection and the
same pagination, so a REST client and an MCP client observe identical refresh
results. The route composes exactly the same injected `SourceService.ListSources`
read and `SourceService.Sync` command the MCP tool and the existing source routes
use; it introduces no second read, authorization decision or audit path, so
admission-before-data and the R1 audit outcome (including denials with a class)
stay the existing ones. The MCP `arguments` map onto the query string:
`source_scope_id`, `offset` and `limit` (an absent query is the first page). The
POST form is the same operation for clients that invoke knowledge tools with a
POST request: parameters travel in the query string, the request body is not a
parameter channel (a non-empty body is refused as `400 REQUEST_INVALID` rather
than being silently ignored), and the CSRF gate of every other unsafe method
applies. Unknown query keys, duplicates, an empty value, a bare `?` and a
malformed encoding are `400 REQUEST_INVALID` before the source service is
touched. A `limit` of `0` or an omitted `limit` means the default page of 100; a
requested limit is capped at 1000 and the effective value is echoed as `limit`.

Example response (identical to the MCP `structuredContent` above):

```json
{
  "refreshed": [
    {
      "source_scope_id": "scope_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "job_id": "job_01H9ABCDEFGHJKMNPQRSTVWXYZ"
    }
  ],
  "skipped": [
    {
      "source_scope_id": "scope_01H9ABCDEFGHJKMNPQRSTVWXY0",
      "reason": "TRUST_UNVERIFIED"
    }
  ],
  "offset": 0,
  "limit": 100,
  "has_more": false,
  "next_offset": null
}
```

An unknown workspace or a non-member caller gets the same content-free denial as
the MCP tool, here `404 NOT_FOUND` with no source content and no workspace-id
echo; a conflict is `409 SOURCE_CONFLICT`; a composition mounted without the
source capability is `503 SERVICE_UNAVAILABLE` (the REST twin of the MCP
`-32000`). The route is declared as an `endpointKind` with an `openAPIRoutes`
entry and an `api/openapi.yaml` path item describing both methods, so the
OpenAPI drift gate covers it. The MCP canonical name is `knowvault_refresh`; the
`tools/list` advertisement and every other REST/MCP route are unchanged, and no
wiki-rag alias is advertised or dispatched.

## `knowvault_list_objects`

Read-only inventory of the document/evidence objects of one workspace with
their current source version, content hash, external version key, moment
(`observed_at`), object type and immutable address (source, version, object and
the exact ordinal span of the version's fragments). It resolves through the same
authorized Evidence viewer, admission-before-data journal and content-free
denial as `knowvault_read` and the REST evidence read. R3a-1 Outcome 2
(KV-A02).

`knowvault_list_objects` is the canonical name. The former name
`knowvault_workspace_list` is an accepted **compatibility alias**: `tools/list`
advertises only the canonical name, but a `tools/call` naming the former name
dispatches to the identical implementation with the identical parameters,
projection and pagination. New sessions should use the canonical name.

Current versions are returned by default; `all_versions: true` returns every
version of every workspace-bound object. The result is paginated with an
explicit window: `offset`, the effective `limit`, `has_more` and, while more
remains, `next_offset`. A limit is never silent truncation — continuing from
`next_offset` until `has_more` is `false` and concatenating the `objects` arrays
reproduces the complete inventory. The default page is 100 objects and a
requested limit is capped at 1000; the effective value is always echoed as
`limit`.

The inventory contains exactly one row per `(source_object_id,
source_version_id)`. When the same object is reachable through several enabled
`workspace_revision_source` scopes the duplicate rows are collapsed, so paging
over the stable `(source_object_id, source_version_id)` order can neither
duplicate nor omit a row (KV-A02). A version is listed only when it satisfies the
same fail-closed visibility gates the evidence read applies: the enabled binding
is `WORKSPACE_MANAGED`, it has a live unrevoked
`workspace_managed_grant_confirmation` on the exact scope tuple, the scope
membership is `ACTIVE`, and the `source_version_retention` is `ACTIVE` and
`queryable`. A version a read path would refuse is never presented as readable.

Semantic index coverage is currently unknown per version: every object carries `"embedded": null` and `"embedding_status": "UNKNOWN"`; the text channel says `embedded=unknown embedding_status=UNKNOWN`. Immutable ingestion metadata and an active organization profile cannot establish that all of a version's current chunks were indexed, so `embedding_profile` and `embedding_profile_hash` are not reported as actual indexed identities. This corrects the former always-boolean `embedded` field: clients must accept null as unknown, never coerce it to false. Routes, addresses, pagination and visibility gates retain their contracts, but consumers requiring a boolean must update. This is an M1 limitation of semantic inventory (C2); it proves neither absence nor completeness of vectors and does not mark a release goal complete.

A registered git code-source object (`object_type` `GIT_FILE`, R3a-1 KV-A04a)
additionally carries the code source's mirror age: `mirror_age_seconds` is a
non-negative integer derived from the code source's already-persisted last
successful mirror/sync moment — the same moment `knowvault_sources` exposes as
`last_successful_sync_at` — and `mirrored_at` is that moment in RFC3339 whenever
a moment is persisted. The moment is read from the membership-gated workspace
source-status projection inside the same authorized inventory read, so no new
read path, dependency or weakening of the visibility gates is introduced. A
document/evidence row carries neither member, so a document is never mislabelled
as a mirror. A code-source row therefore looks like:

```json
{
  "source_object_id": "object_01H9ABCDEFGHJKMNPQRSTVWXYZ",
  "source_version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
  "external_version_key": "native:commit:9f2c1d0e;blob:1a2b3c4d",
  "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
  "observed_at": "2026-09-10T08:30:00Z",
  "object_type": "GIT_FILE",
  "current": true,
  "version_state": "CURRENT",
  "mirror_age_seconds": 5400,
  "mirrored_at": "2026-09-10T07:00:00Z"
}
```

Alongside the `objects` page the response carries the current projection of the
workspace's typed skip ledger: `skipped` is the array of unresolved observations
in the workspace's bound scope revisions,
and `skipped_count` is its length. Each skipped row carries only the connector's
stable `external_id`, the closed typed `reason_code` and the RFC3339 `moment`
the skip was observed — never source content:

```json
{ "external_id": "native:skipped-a", "reason_code": "FOLDER_MEDIA_SIGNATURE_MISMATCH", "moment": "2026-09-10T08:30:00Z" }
```

A skipped observation has no readable version of its own and therefore no
`address` or `source_object_id`/`source_version_id` in the skip row. An older
readable version of that same object may still appear in `objects`; its presence
does not establish that the new observation succeeded. Its `reason_code` is a
closed, content-free code from the connector/extraction skip taxonomy (for
example `FOLDER_MEDIA_SIGNATURE_MISMATCH`, `FOLDER_OBJECT_OVERSIZED` or
`INGEST_EXTRACTION_SKIPPED`), and its `moment` is when the skip was observed.
The code comes from the object's own source kind (KV-A02, migration
`000095_stage3_source_object_skip.sql`): a non-`FOLDER` object that fails format
determination after its bytes were read is reported with its own source kind's
closed code — `GIT_UNSUPPORTED_MEDIA_TYPE` for a `GIT_FILE` object and
`MAIL_ATTACHMENT_UNSUPPORTED_MEDIA_TYPE` for a mail attachment — and neither is
ever reported as the folder-specific `FOLDER_UNSUPPORTED_TYPE`; only a
genuinely source-neutral extraction skip keeps the source-neutral
`INGEST_EXTRACTION_SKIPPED`. This holds identically for the ledger row and for
`knowvault_list_objects.skipped[].reason_code`. A skip is reported explicitly
rather than omitted silently; `skipped` and `skipped_count` are independent of
the `objects` pagination window, so paging `objects` never changes the skip
projection.

An authoritative `SUCCEEDED FULL` run with `coverage_complete=true` replaces
earlier skip state for that exact scope revision. Partial or incremental runs
cannot clear a skip merely by omitting the object. They can clear it through an
explicit successful per-object recovery, including re-observation of unchanged
bytes: ingestion appends a resolution only for a previously unresolved native
identity. It matches older digest-key versions through the sealed identity.
The resolution takes effect only when its sync run reaches `SUCCEEDED`;
`RUNNING` and `FAILED` runs never clear it, and a later new quarantine is visible
again. A repeat successful sync without a new skip appends no recovery facts.
The original skip history remains unchanged. Recovery records contain only
tenant-bound digests and owner/run references, not new source content; they
survive source-version content purge and do not reopen its read permission.
Physical tenant deletion is not currently implemented by a product operator:
`tenant-provision` creates tenants, and the purger processes source-version and
conversation content. A future tenant deletion owner must explicitly include
recovery records before their referenced skips and scope memberships; the
foreign keys enforce this order. This change does not claim that deletion
workflow has been delivered.

### Parameters

| field | type | required | notes |
| --- | --- | --- | --- |
| `workspace_id` | string | yes | The workspace whose objects are listed. |
| `all_versions` | boolean | no | `false` (default) lists only each object's current version; `true` lists every version. |
| `offset` | integer ≥ 0 | no | Zero-based row offset of the page. Defaults to 0. |
| `limit` | integer ≥ 1 | no | Page size in objects. Defaults to 100, capped at 1000. |

The schema is closed (`additionalProperties: false`): a missing or empty
`workspace_id`, a negative or wrong-typed `offset`/`limit`/`all_versions` or any
unknown member is rejected with JSON-RPC error `-32602` before the inventory
read is touched.

### Request

```json
{
  "jsonrpc": "2.0",
  "id": "wl1",
  "method": "tools/call",
  "params": {
    "name": "knowvault_list_objects",
    "arguments": { "workspace_id": "ws_alpha", "limit": 1 }
  }
}
```

The `content[].text` channel is not a banner: it carries the same page a
text-channel-only client (and a model) needs. Its first line states the tool,
the object count and the page cursor (`offset`, the effective `limit`,
`has_more`, `next_offset`); each remaining object line starts with `[n]` and
carries the identical `address` the `structuredContent` object carries (compact
JSON), then `object_type`, the version keys (`version_id`,
`external_version_key`, `content_hash`, `observed_at`), `current` and
`version_state`; each skipped row is one `skipped: external_id=… reason_code=…`
line with its moment. Every object and every skip is exactly one line, so the
addresses in the text channel are exactly the addresses in `structuredContent`.
When more objects remain, `next_offset` is the cursor to pass back as `offset`;
a `null` cursor means the page is the end.

### Response (example)

```json
{
  "jsonrpc": "2.0",
  "id": "wl1",
  "result": {
    "content": [{ "type": "text", "text": "knowvault_list_objects: 1 object(s); offset=0 limit=1 has_more=true next_offset=1\n[1] address={\"object\":{\"first_fragment_id\":\"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ\"},\"source\":{\"connection_id\":\"connection_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"object_type\":\"FILE\",\"source_object_id\":\"object_01H9ABCDEFGHJKMNPQRSTVWXYZ\"},\"span\":{\"fragment_count\":3,\"kind\":\"OBJECT\",\"ordinal_end\":3,\"ordinal_start\":1},\"version\":{\"content_hash\":\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\",\"external_version_key\":\"hash:sha256:abababababababababababababababababababababababababababababababab\",\"observed_at\":\"2026-08-13T10:00:00Z\",\"source_version_id\":\"version_01H9ABCDEFGHJKMNPQRSTVWXYZ\"}} object_type=FILE version_id=version_01H9ABCDEFGHJKMNPQRSTVWXYZ external_version_key=hash:sha256:abababababababababababababababababababababababababababababababab content_hash=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd observed_at=2026-08-13T10:00:00Z current=true version_state=CURRENT\nskipped: external_id=native:skipped-a reason_code=FOLDER_MEDIA_SIGNATURE_MISMATCH moment=2026-09-10T08:30:00Z" }],
    "structuredContent": {
      "objects": [
        {
          "source_object_id": "object_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "source_version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "external_version_key": "hash:sha256:abababababababababababababababababababababababababababababababab",
          "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
          "observed_at": "2026-08-13T10:00:00Z",
          "object_type": "FILE",
          "current": true,
          "version_state": "CURRENT",
          "address": {
            "source": {
              "source_object_id": "object_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "connection_id": "connection_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "object_type": "FILE"
            },
            "version": {
              "source_version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "external_version_key": "hash:sha256:abababababababababababababababababababababababababababababababab",
              "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
              "observed_at": "2026-08-13T10:00:00Z"
            },
            "object": { "first_fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ" },
            "span": { "kind": "OBJECT", "fragment_count": 3, "ordinal_start": 1, "ordinal_end": 3 }
          }
        }
      ],
      "offset": 0,
      "limit": 1,
      "has_more": true,
      "next_offset": 1,
      "skipped": [
        {
          "external_id": "native:skipped-a",
          "reason_code": "FOLDER_MEDIA_SIGNATURE_MISMATCH",
          "moment": "2026-09-10T08:30:00Z"
        }
      ],
      "skipped_count": 1
    },
    "isError": false
  }
}
```

### Denial

An unknown workspace, or one the caller is not a member of, yields the viewer's
single content-free not-found, mapped to JSON-RPC error `-32004` with message
`workspace objects not found`; the response carries no object row and never
echoes the requested workspace id. The call records a content-free admission
event through the existing audit journal before any object row is read, and its
outcome (including the denial class) afterwards. A denial is journalled as a
content-free `evidence.read.admitted` event with outcome `DENIED`, error code
`WORKSPACE_OBJECTS_DENIED` and a NULL `workspace_id`, so an unknown or foreign
workspace denial is actually recorded without failing the audit_event workspace
foreign key and without becoming an existence oracle. As with every knowledge
tool in this document, a V1-C SERVICE principal sees and may call this tool
exactly as a human session does; only the administrative tools stay closed to it.

### REST parity

`knowvault_list_objects` is also served over REST at

```
GET  /api/v1/workspaces/{workspace_id}/tools/list-objects
POST /api/v1/workspaces/{workspace_id}/tools/list-objects
```

with the same authorized implementation, the same projection and the same
pagination, so a REST client and an MCP client observe identical rows. The MCP
`arguments` map onto the query string: `offset`, `limit` and `all_versions`
(an absent query is the first page). The POST form is the same operation for
clients that invoke knowledge tools with a POST request: parameters travel in
the query string, the request body is not read, and the CSRF gate of every other
unsafe method applies. Unknown query keys, duplicates, an empty
value and a malformed encoding are `400 REQUEST_INVALID` before any row is read.
A `limit` of `0` or an omitted `limit` means the default page of 100; a requested
limit is capped at 1000 and the effective value is echoed as `limit`.

```json
{
  "objects": [
    {
      "source_object_id": "object_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "source_version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "external_version_key": "hash:sha256:abababababababababababababababababababababababababababababababab",
      "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "observed_at": "2026-08-13T10:00:00Z",
      "object_type": "FILE",
      "current": true,
      "version_state": "CURRENT",
      "address": {
        "source": {
          "source_object_id": "object_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "connection_id": "connection_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "object_type": "FILE"
        },
        "version": {
          "source_version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "external_version_key": "hash:sha256:abababababababababababababababababababababababababababababababab",
          "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
          "observed_at": "2026-08-13T10:00:00Z"
        },
        "object": { "first_fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ" },
        "span": { "kind": "OBJECT", "fragment_count": 3, "ordinal_start": 1, "ordinal_end": 3 }
      }
    }
  ],
  "offset": 0,
  "limit": 1,
  "has_more": true,
  "next_offset": 1
}
```

An unknown workspace or a non-member caller gets the same content-free denial as
the MCP tool, here `404 NOT_FOUND` with no object row and no workspace-id echo.
The route is declared as an `endpointKind` with an `openAPIRoutes` entry and an
`api/openapi.yaml` path, so the OpenAPI drift gate covers it. The MCP
`tools/list` advertisement and every other REST/MCP route are unchanged.

## `knowvault_search`

Read-only search by words and by meaning over the **current-version canonical document
fragments** of one workspace (R3a-1 Outcome 2 / KV-A02a). Each hit carries an
excerpt, a numeric score and the immutable address of the matched fragment
(source, version, object and exact span with text hash), plus the version id,
moment (`observed_at`) and content hash. A hit's address resolves the whole
object through `knowvault_read`. It resolves through the same
authorized Evidence viewer, admission-before-data journal and content-free
denial as `knowvault_read` and `knowvault_list_objects`.

Only current versions are searched by default; `all_versions: true` also
searches non-current versions. A fragment is searched only when it satisfies the
same fail-closed visibility gates the read path applies: the enabled binding is
`WORKSPACE_MANAGED`, the live unrevoked `workspace_managed_grant_confirmation`
covers the exact scope tuple, the scope membership is `ACTIVE`, and the
`source_version_retention` is `ACTIVE` and `queryable`.

Indexed results rank search chunks, with a table row represented once rather
than once per cell. Distinct chunks of the same file remain distinct. Fusion
uses the immutable chunk identity; a useful fragment and its address are
selected from live-authorized canonical evidence after ranking. Scores order
results descending, with chunk identity breaking ties deterministically.

The explicit page window carries `offset`, the effective `limit`, `has_more`
and, while more ranked candidates remain, `next_offset`. The default page is
20 hits and a requested limit is capped at 100. Follow the returned cursor,
which counts consumed authorized groups and can advance beyond the number of
displayed hits if access changes during a read.

The additive `partial` boolean reports incomplete candidate coverage or a page
shortened by the evidence-read budget. Search is a bounded ranking operation:
`has_more=false` ends its candidate set and does not prove absence elsewhere
when `partial=true`. A group is never partly returned to meet that budget;
the next offset continues with the unconsumed group. This flag is independent
of `profile.degraded` (an unavailable retrieval channel) and appears in REST,
MCP structured content and the MCP text banner. Full object data remains
available through paginated `knowvault_read`.

### Parameters

| field | type | required | notes |
| --- | --- | --- | --- |
| `workspace_id` | string | yes | The workspace whose current-version fragments are searched. |
| `query` | string | yes | Search text or a natural-language question; the lexical channel tokenizes its terms. |
| `all_versions` | boolean | no | `false` (default) searches only each object's current version; `true` searches every version. |
| `offset` | integer ≥ 0 | no | Zero-based hit offset of the page. Defaults to 0. |
| `limit` | integer ≥ 1 | no | Page size in hits. Defaults to 20, capped at 100. |

The schema is closed (`additionalProperties: false`): a missing or empty
`workspace_id`/`query`, a negative or wrong-typed `offset`/`limit`/`all_versions`
or any unknown member is rejected with JSON-RPC error `-32602` before the
evidence search is touched.

### Hybrid retrieval (S3)

The tool runs two channels over one question. The lexical channel matches
words; the vector channel matches meaning, by embedding the question under the
workspace's own embedding profile and searching the same index the passages
were indexed into. Each channel applies the workspace, the rights-bearing
source scope and the current-version state **inside its own query**, before
ranking — so a workspace's nearest neighbours are drawn from passages it may
read rather than from the whole tenant corpus. The two rank lists are fused by
reciprocal rank fusion with one fixed constant, and every surviving fragment is
then re-authorized against live state: a right revoked between indexing and now
removes the hit regardless of which channel found it.

Every hit therefore carries a `channel`: `lexical` (the words matched),
`vector` (the meaning matched), `hybrid` (both) or `term` (see below). A hit
served under a version state the path can establish also carries
`version_state`. `channel` is provenance, never an input.

The result carries the retrieval `profile` the call actually ran under: `mode`,
whether each channel ran, the fusion and its constant, whether a reranker ran
(it does not in this contour) and `degraded`. A true `degraded` means a
declared channel could not answer — no embedding channel is mounted, or the
endpoint refused — so a hybrid answer that was in fact lexical-only never reads
as hybrid.

The profile is **not** a parameter of this tool and never will be. A model that
chooses the retrieval algorithm has made the algorithm part of its answer, and
an ablation whose profile the model could have influenced measures nothing. An
owner of the workspace selects it for measurement on the
`X-KnowVault-Search-Profile` request header (`lexical`, `vector`, `hybrid`);
the choice is authorized, written to the audit journal and echoed in `profile`.
A non-owner presenting the header is ignored and audited, and an argument named
`profile` is rejected as an unknown member like any other.

### The `term` channel

When the query text names an entry of the workspace's **own** term catalogue,
its definition comes back as a separate addressed hit in `terms`, with
`channel` set to `term`, on top of the ranked results and never instead of
them. A name the workspace uses for two different things returns two such hits,
and the product does not choose between them any more than it chooses between
two documents.

Nothing about this is a dictionary or a rule inside the product. The catalogue
is workspace data produced by ingest, a `term` hit is an ordinary addressable
fragment read through the same gate as any other, and only an explicit
definition (a canonical name, a synonym or an abbreviation the ingest read out
of a document) counts — a word that merely occurred near others does not. A
workspace whose catalogue defines nothing for the question has no `terms`
member at all.

### Request

```json
{
  "jsonrpc": "2.0",
  "id": "se1",
  "method": "tools/call",
  "params": {
    "name": "knowvault_search",
    "arguments": { "workspace_id": "ws_alpha", "query": "KnowVault", "limit": 1 }
  }
}
```

The `content[].text` channel is not a banner: it carries the same page a
text-channel-only client (and a model) needs. Its first line states the tool,
the hit count and the page cursor (`offset`, the effective `limit`, `has_more`,
`next_offset`); each following hit is one line starting with `[n]` that carries
the identical `address` the `structuredContent` hit carries (compact JSON), then
`fragment_id`, `score`, `version_id`, `observed_at` and `excerpt`. A multi-line
excerpt is flattened so one hit is always one line and the addresses in the text
channel are exactly the addresses in `structuredContent`. When more hits remain,
`next_offset` is the cursor to pass back as `offset`; a `null` cursor means the
page is the end.

### Response (example)

```json
{
  "jsonrpc": "2.0",
  "id": "se1",
  "result": {
    "content": [{ "type": "text", "text": "knowvault_search: 1 hit(s); offset=0 limit=1 has_more=true next_offset=1\n[1] address={\"object\":{\"extraction_id\":\"extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"fragment_id\":\"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"ordinal\":3},\"source\":{\"connection_id\":\"connection_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"source_object_id\":\"object_01H9ABCDEFGHJKMNPQRSTVWXYZ\"},\"span\":{\"anchor\":\"eyJsb2NhdG9yIjoiZmlsZTovL3ZvbC0xL3Byb2plY3RzL2FscGhhL2RvYy5tZCIsIm9mZnNldCI6MTIwfQ==\",\"length\":58,\"offset\":0,\"text_hash\":\"hmac-sha256:k1:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b\",\"total_length\":58},\"version\":{\"content_hash\":\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\",\"external_version_key\":\"hash:sha256:abababababababababababababababababababababababababababababababab\",\"observed_at\":\"2026-08-13T10:00:00Z\",\"source_version_id\":\"version_01H9ABCDEFGHJKMNPQRSTVWXYZ\"}} fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ score=3 version_id=version_01H9ABCDEFGHJKMNPQRSTVWXYZ observed_at=2026-08-13T10:00:00Z excerpt=…the alpha project document mentions KnowVault in full…" }],
    "structuredContent": {
      "results": [
        {
          "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "excerpt": "…the alpha project document mentions KnowVault in full…",
          "score": 3,
          "version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "observed_at": "2026-08-13T10:00:00Z",
          "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
          "address": {
            "source": {
              "source_object_id": "object_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "connection_id": "connection_01H9ABCDEFGHJKMNPQRSTVWXYZ"
            },
            "version": {
              "source_version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "external_version_key": "hash:sha256:abababababababababababababababababababababababababababababababab",
              "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
              "observed_at": "2026-08-13T10:00:00Z"
            },
            "object": {
              "extraction_id": "extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "ordinal": 3,
              "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"
            },
            "span": {
              "offset": 0,
              "length": 58,
              "total_length": 58,
              "text_hash": "hmac-sha256:k1:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b",
              "anchor": "eyJsb2NhdG9yIjoiZmlsZTovL3ZvbC0xL3Byb2plY3RzL2FscGhhL2RvYy5tZCIsIm9mZnNldCI6MTIwfQ=="
            }
          }
        }
      ],
      "offset": 0,
      "limit": 1,
      "has_more": true,
      "next_offset": 1
    },
    "isError": false
  }
}
```

### Denial and audit

An unknown workspace, or one the caller is not a member of, yields the viewer's
single content-free not-found, mapped to JSON-RPC error `-32004` with message
`workspace documents not found`; the response carries no hit and never echoes
the requested workspace id. The call records a content-free admission event
through the existing audit journal before any fragment row is read, and its
outcome (including the denial class) afterwards. A denial is journalled as a
content-free `evidence.read.admitted` event with outcome `DENIED`, error code
`WORKSPACE_SEARCH_DENIED` and a NULL `workspace_id`, so an unknown or foreign
workspace denial is actually recorded without failing the audit_event workspace
foreign key and without becoming an existence oracle. Neither the query nor any
document content is recorded.

### REST parity

`knowvault_search` is also served over REST at

```
GET  /api/v1/workspaces/{workspace_id}/tools/search?query=KnowVault
POST /api/v1/workspaces/{workspace_id}/tools/search?query=KnowVault
```

with the same authorized implementation, the same projection and the same
pagination as the MCP tool, so a REST client and an MCP client observe identical
hits. The MCP `arguments` map onto the query string: `query` (required), and the
optional `offset`, `limit` and `all_versions`. The POST form is the same
operation for clients that invoke knowledge tools with a POST request:
parameters travel in the query string, the request body is not read, and the
CSRF gate of every other unsafe method applies. A missing or whitespace-only
`query`, unknown query keys, duplicates, an empty value and a malformed encoding
are `400 REQUEST_INVALID` before any fragment is read. A `limit` of `0` or an
omitted `limit` means the default page of 20; a requested limit is capped at 100
and the effective value is echoed as `limit`.

```json
{
  "results": [
    {
      "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "excerpt": "…the alpha project document mentions KnowVault in full…",
      "score": 3,
      "version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "observed_at": "2026-08-13T10:00:00Z",
      "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "address": {
        "source": {
          "source_object_id": "object_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "connection_id": "connection_01H9ABCDEFGHJKMNPQRSTVWXYZ"
        },
        "version": {
          "source_version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "external_version_key": "hash:sha256:abababababababababababababababababababababababababababababababab",
          "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
          "observed_at": "2026-08-13T10:00:00Z"
        },
        "object": {
          "extraction_id": "extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "ordinal": 3,
          "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"
        },
        "span": {
          "offset": 0,
          "length": 58,
          "total_length": 58,
          "text_hash": "hmac-sha256:k1:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b",
          "anchor": "eyJsb2NhdG9yIjoiZmlsZTovL3ZvbC0xL3Byb2plY3RzL2FscGhhL2RvYy5tZCIsIm9mZnNldCI6MTIwfQ=="
        }
      }
    }
  ],
  "offset": 0,
  "limit": 1,
  "has_more": true,
  "next_offset": 1
}
```

An unknown workspace or a non-member caller gets the same content-free denial as
the MCP tool, here `404 NOT_FOUND` with no hit and no workspace-id echo. The
route is declared as an `endpointKind` with an `openAPIRoutes` entry and an
`api/openapi.yaml` path, so the OpenAPI drift gate covers it. The MCP
`tools/list` advertisement and every other REST/MCP route are unchanged.

## `knowvault_grep`

Exact regular-expression grep over the canonical text of one workspace's
document/evidence objects (R3a-1 Outcome 2 / KV-A02c). It resolves through the
same authorized evidence path as `knowvault_search`, `knowvault_list_objects`
and `knowvault_read`: it walks the workspace object inventory (the
current version of each object by default, every version with
`all_versions: true`) and reads each object version's whole canonical text
through the existing authorized whole-object read, so admission-before-data, the
R1 audit journal and the content-free denial stay exactly the existing ones. It
introduces no new store, index, read path or migration.

The `pattern` is a Go regular expression (RE2, linear time). A malformed
expression is refused with `-32602` before any object row is read. A zero-length
match is not a retrievable span and is not returned.

The optional `ref` scopes the scan to code sources. When it is supplied, only
the workspace's registered git code-source objects (`object_type` `GIT_FILE`)
whose immutable version identity matches the named ref are scanned: the ref is
resolved from object-inventory metadata alone, before any fragment content is
read, and every version of those objects is considered (a ref is an immutable
identity, so the current-version default would hide a non-current ref). The
identity is the object version's `external_version_key`, and a ref matches it
exactly, matches it with the `native:` prefix stripped, or matches one of its
`;`-separated `key:value` tokens, so a caller can name the immutable identity a
registered git branch resolved to (for example the `commit:<sha>` token). When
`ref` is supplied the response's `address.version.ref` is the ref and the version
inside `canonical_address` is the ref; `address.version.source_version_id` still
shows the underlying immutable version id. `all_versions` does not narrow a
ref-scoped scan (the ref is the selector). An unknown or foreign ref, or a
workspace with no such code source, is refused with the same content-free `-32004`
as a denied workspace: no match, excerpt or address and no workspace-id echo. A
`ref` that is empty, longer than 256 characters, or contains whitespace, a
control character or a colon is refused with `-32602` before any read.

The code-source identity this tool scopes by is the workspace object
inventory's `external_version_key` of a registered git object of type
`GIT_FILE` — for example the `native:commit:<sha>;blob:<sha>` identity the git
connector publishes — resolved from inventory metadata before any content is
read. A ref-scoped hit of such an object also carries the canon `file:lines`
locator: `path` is the repository-relative file path the git adapter stamped as
the object's authorized external identity, `line`/`column` are the 1-based
half-open start position of the match in the file and `end_line`/`end_column`
its 1-based half-open end position, computed from the match's byte offsets in
the canonical file text. A document/evidence hit and every no-ref hit carry no
`path`, `line`, `column`, `end_line` or `end_column` member, so a document span
is never mislabelled as a code file; the `address` and `offset`/`length` members
are unchanged.

Every match carries the immutable address: `source` (source object, connection),
`version` (source version, external version key, content hash, moment), `object`
(extraction, ordinal, anchor fragment) and the `span` of the whole canonical
object text with its canonical `text_hash`, plus a nested `match` locating the
matched half-open byte range (`offset`, `length`) inside that span and the hash
of exactly the matched bytes (`match_hash`). The top-level `offset` and `length`
repeat the matched range. `canonical_address` is the string round-trippable
`internal/address` value of the whole object version in the compact form
`kv1:<object>:<version>:<span>:<hash16>`; `address.Parse` of it
returns the same source/object/version and a span whose keyed digest verifies
against the reassembled text, and `knowvault_read` with that `address` and a
`cursor` resolves and pages the whole object. To open one match directly, pass
`canonical_address`, its match `offset`, and a `limit` to `knowvault_read` and
omit `cursor`; this starts the read at the matched byte window.

Each match also returns `read_fragments`: at most eight complete fragments
intersecting that match, in source ordinal order. Each entry has exactly
`canonical_address`, `fragment_id` and `length` (the full UTF-8 byte length).
These addresses name the true source version even for a Git ref-scoped match;
each organization-keyed digest covers that entire fragment's exact bytes.
`read_fragments_total` counts all intersecting fragments and
`read_fragments_has_more` reports whether the list exceeds eight. If it does,
the match's existing whole-object address and byte range still provide access
to every byte. The returned fragment addresses are read selectors, not proof
that the caller has already read their content.

To read a complete supporting fragment, pass its `read_fragments` address to
`knowvault_read` at offset zero, normally in one call. Honor the read result's
`has_more` and `next_offset` for a longer fragment; a single long line can exceed
the read page limit. The original whole-object address, match offset/length
and match hash retain their prior meanings. Fragment geometry and identity are
validated before emission; malformed source spans fail the whole response
content-free. This projection adds no data fetch or authorization path.

Hash-family note for this tool: the example `span.text_hash`,
`address.match.hash` and `match_hash` values below are the **unkeyed** canonical
`sha256:` of the whole object text and of exactly the matched bytes
(`address.WholeHash`), not `evidence_fragment.text_hash`. The org-keyed ADR-0077
digest of the addressed whole object appears only in `canonical_address`'s
`<hash16>` field, exactly as in `knowvault_read`, and must never be replaced by a
bare SHA-256 of plaintext.

Only objects under the same fail-closed visibility gates the evidence
read/search path applies are matched: the enabled `WORKSPACE_MANAGED` binding,
the live unrevoked `workspace_managed_grant_confirmation` covering the exact
scope tuple, `ACTIVE` scope membership and `ACTIVE`/`queryable`
`source_version_retention`.

Results are ordered deterministically by immutable address (source object,
source version, ordinal) and then by match offset, and paginated with an explicit
window: `offset`, the effective `limit`, `has_more` and, while more remains,
`next_offset`. A limit is never silent truncation — continuing from `next_offset`
until `has_more` is `false` and concatenating the `matches` arrays reproduces the
complete match set. The default page is 20 matches and a requested limit is
capped at 100; the effective value is always echoed as `limit`.

The `content[].text` channel is not a banner: one line per match carries the
match's excerpt, score-shape members and both its `address` JSON and its exact
`canonical_address` kv1 string (the value of
`structuredContent.matches[].canonical_address`), followed by the trailing
page-cursor line and a `read_hint` with the direct call shape
`knowvault_read(address=canonical_address,offset=offset,limit=4096); omit
cursor`. A model that reads only the text channel can therefore re-address any
hit — including a ref-scoped code hit — into a `knowvault_read` call without
parsing `structuredContent`. The text channel also carries the same complete
`read_fragments` addresses, total and overflow flag, with a hint to read those
addresses fully and continue if the read response is paginated.

The optional `address` is a complete canonical `kv1:` text address returned by
this or another knowledge tool. It selects exactly the addressed object anchor
and immutable version, and runs the regex over that object's assembled
canonical text through the existing authorized whole-object read. This path
does not walk the workspace inventory. The selected version remains subject to
the same authorization and retention checks as `knowvault_read`; an address
does not grant historical access by itself.
`address` is mutually exclusive with `ref` and `all_versions`; use `address`
for an exact object/version selector or omit it for the workspace scan. A
`ref` remains a Git immutable version identity selector for `GIT_FILE` objects,
never a repository path and never a document selector. A malformed, foreign,
revoked, purged or span-mismatched address is refused content-free according to
the existing read semantics.

### Parameters

| field | type | required | notes |
| --- | --- | --- | --- |
| `workspace_id` | string | yes | The workspace whose object canonical text is grepped. |
| `pattern` | string | yes | The Go regular expression (RE2) matched against the canonical text. |
| `all_versions` | boolean | no | `false` (default) matches only each object's current version; `true` matches every version. |
| `offset` | integer ≥ 0 | no | Zero-based match offset of the page. Defaults to 0. |
| `limit` | integer ≥ 1 | no | Page size in matches. Defaults to 20, capped at 100. |
| `ref` | string | no | Named ref of a registered git code source. When present, only the workspace's `GIT_FILE` object versions whose immutable identity matches `ref` are scanned, and the ref becomes the address version. |
| `address` | string | no | Complete canonical `kv1:` text address of one object/version. Searches only that authorized object without an inventory scan; mutually exclusive with `ref` and `all_versions`. |

The schema is closed (`additionalProperties: false`): a missing or empty
`workspace_id`/`pattern`, a malformed `pattern`, a negative or wrong-typed
`offset`/`limit`/`all_versions`, a `ref` that is empty, over 256 characters or
carries whitespace, a control character or a colon, a malformed/non-text
`address`, an `address` combined with `ref` or `all_versions`, or any unknown member is
rejected with JSON-RPC error `-32602` before any object row is read.

### Request

```json
{
  "jsonrpc": "2.0",
  "id": "gr1",
  "method": "tools/call",
  "params": {
    "name": "knowvault_grep",
    "arguments": { "workspace_id": "ws_alpha", "pattern": "KnowVault\\s+in\\s+full", "limit": 1 }
  }
}
```

### Response (example)

```json
{
  "jsonrpc": "2.0",
  "id": "gr1",
  "result": {
    "content": [{ "type": "text", "text": "[1] address={\"match\":{\"hash\":\"sha256:1f4d3c2b5a6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708\",\"length\":17,\"offset\":39},\"object\":{\"extraction_id\":\"extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"fragment_id\":\"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"ordinal\":1},\"source\":{\"connection_id\":\"connection_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"source_object_id\":\"object_01H9ABCDEFGHJKMNPQRSTVWXYZ\"},\"span\":{\"fragment_count\":1,\"length\":58,\"offset\":0,\"ordinal_end\":1,\"ordinal_start\":1,\"text_hash\":\"sha256:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b\",\"total_length\":58},\"version\":{\"content_hash\":\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\",\"external_version_key\":\"hash:sha256:abababababababababababababababababababababababababababababababab\",\"observed_at\":\"2026-08-13T10:00:00Z\",\"source_version_id\":\"version_01H9ABCDEFGHJKMNPQRSTVWXYZ\"}} canonical_address=kv1:object_01H9ABCDEFGHJKMNPQRSTVWXYZ~fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ:version_01H9ABCDEFGHJKMNPQRSTVWXYZ:text.0-58:6b1c0f2e9a4d4c1b fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ offset=39 length=17 version_id=version_01H9ABCDEFGHJKMNPQRSTVWXYZ observed_at=2026-08-13T10:00:00Z content_hash=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd match_hash=sha256:1f4d3c2b5a6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708 excerpt=…the alpha project document mentions KnowVault in full…\noffset=0 limit=1 has_more=true next_offset=1\n" }],
    "structuredContent": {
      "matches": [
        {
          "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "offset": 39,
          "length": 17,
          "excerpt": "…the alpha project document mentions KnowVault in full…",
          "match_hash": "sha256:1f4d3c2b5a6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708",
          "version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "observed_at": "2026-08-13T10:00:00Z",
          "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
          "address": {
            "source": {
              "source_object_id": "object_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "connection_id": "connection_01H9ABCDEFGHJKMNPQRSTVWXYZ"
            },
            "version": {
              "source_version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "external_version_key": "hash:sha256:abababababababababababababababababababababababababababababababab",
              "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
              "observed_at": "2026-08-13T10:00:00Z"
            },
            "object": {
              "extraction_id": "extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "ordinal": 1,
              "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"
            },
            "span": {
              "offset": 0,
              "length": 58,
              "total_length": 58,
              "text_hash": "sha256:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b",
              "fragment_count": 1,
              "ordinal_start": 1,
              "ordinal_end": 1
            },
            "match": {
              "offset": 39,
              "length": 17,
              "hash": "sha256:1f4d3c2b5a6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708"
            }
          },
          "canonical_address": "kv1:object_01H9ABCDEFGHJKMNPQRSTVWXYZ~fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ:version_01H9ABCDEFGHJKMNPQRSTVWXYZ:text.0-58:6b1c0f2e9a4d4c1b"
        }
      ],
      "offset": 0,
      "limit": 1,
      "has_more": true,
      "next_offset": 1
    },
    "isError": false
  }
}
```

### Code-source request (named `ref`)

The same tool greps the workspace's registered git code sources at one immutable
ref by passing `ref`. Here the caller first read `knowvault_list_objects` and saw
the code file's version identity
`native:commit:9f2c4a1b7d3e5f6081a2b3c4d5e6f708192a3b4;blob:4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b`.
The `commit:` token `9f2c4a1b7d3e5f6081a2b3c4d5e6f708192a3b4` is the named ref.

```json
{
  "jsonrpc": "2.0",
  "id": "gr2",
  "method": "tools/call",
  "params": {
    "name": "knowvault_grep",
    "arguments": { "workspace_id": "ws_alpha", "pattern": "func main\\(", "ref": "9f2c4a1b7d3e5f6081a2b3c4d5e6f708192a3b4", "limit": 1 }
  }
}
```

Only the `GIT_FILE` objects of `ws_alpha` whose version identity matches that
ref are scanned, so a hit at another ref (for a file that differs there) is not
reported. The response is the canonical match shape, with the ref as the address
version and the underlying immutable version id still visible:

```json
{
  "jsonrpc": "2.0",
  "id": "gr2",
  "result": {
    "content": [{ "type": "text", "text": "[1] address={\"match\":{\"hash\":\"sha256:1f4d3c2b5a6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708\",\"length\":10,\"offset\":0},\"object\":{\"extraction_id\":\"extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"fragment_id\":\"fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"ordinal\":1},\"source\":{\"connection_id\":\"connection_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"source_object_id\":\"object_01H9ABCDEFGHJKMNPQRSTVWXYZ\"},\"span\":{\"fragment_count\":1,\"length\":42,\"offset\":0,\"ordinal_end\":1,\"ordinal_start\":1,\"text_hash\":\"sha256:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b\",\"total_length\":42},\"version\":{\"content_hash\":\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\",\"external_version_key\":\"native:commit:9f2c4a1b7d3e5f6081a2b3c4d5e6f708192a3b4;blob:4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b\",\"observed_at\":\"2026-08-13T10:00:00Z\",\"ref\":\"9f2c4a1b7d3e5f6081a2b3c4d5e6f708192a3b4\",\"source_version_id\":\"version_01H9ABCDEFGHJKMNPQRSTVWXYZ\"}} canonical_address=kv1:object_01H9ABCDEFGHJKMNPQRSTVWXYZ~fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ:9f2c4a1b7d3e5f6081a2b3c4d5e6f708192a3b4:text.0-42:6b1c0f2e9a4d4c1b fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ offset=0 length=10 version_id=version_01H9ABCDEFGHJKMNPQRSTVWXYZ observed_at=2026-08-13T10:00:00Z content_hash=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd match_hash=sha256:1f4d3c2b5a6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708 excerpt=func main() { … path=cmd/knowvaultd/main.go line=1 column=1 end_line=1 end_column=10\noffset=0 limit=1 has_more=false next_offset=null\n" }],
    "structuredContent": {
      "matches": [
        {
          "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "offset": 0,
          "length": 10,
          "excerpt": "func main() { …",
          "match_hash": "sha256:1f4d3c2b5a6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708",
          "version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "observed_at": "2026-08-13T10:00:00Z",
          "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
          "path": "cmd/knowvaultd/main.go",
          "line": 1,
          "column": 1,
          "end_line": 1,
          "end_column": 10,
          "address": {
            "source": {
              "source_object_id": "object_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "connection_id": "connection_01H9ABCDEFGHJKMNPQRSTVWXYZ"
            },
            "version": {
              "source_version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "external_version_key": "native:commit:9f2c4a1b7d3e5f6081a2b3c4d5e6f708192a3b4;blob:4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b",
              "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
              "observed_at": "2026-08-13T10:00:00Z",
              "ref": "9f2c4a1b7d3e5f6081a2b3c4d5e6f708192a3b4"
            },
            "object": {
              "extraction_id": "extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "ordinal": 1,
              "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ"
            },
            "span": {
              "offset": 0,
              "length": 42,
              "total_length": 42,
              "text_hash": "sha256:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b",
              "fragment_count": 1,
              "ordinal_start": 1,
              "ordinal_end": 1
            },
            "match": {
              "offset": 0,
              "length": 10,
              "hash": "sha256:1f4d3c2b5a6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708"
            }
          },
          "canonical_address": "kv1:object_01H9ABCDEFGHJKMNPQRSTVWXYZ~fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ:9f2c4a1b7d3e5f6081a2b3c4d5e6f708192a3b4:text.0-42:6b1c0f2e9a4d4c1b"
        }
      ],
      "offset": 0,
      "limit": 1,
      "has_more": false,
      "next_offset": null
    },
    "isError": false
  }
}
```

An unknown ref, or a ref that names no code-source object of the workspace, is
the same content-free `-32004` as a denied workspace; an empty, over-long or
colon/whitespace-carrying `ref` is `-32602` before any read.

### Denial and audit

An unknown workspace, or one the caller is not a member of, yields the evidence
path's single content-free not-found, mapped to JSON-RPC error `-32004` with
message `workspace documents not found`; the response carries no match, excerpt
or address and never echoes the requested workspace id. The call records a
content-free admission event through the existing audit journal before any object
row is read, and its outcome (including the denial class) afterwards, exactly
like `knowvault_list_objects` and `knowvault_search`. A denial is journalled as
a content-free `evidence.read.admitted` event with outcome `DENIED`, error code
`WORKSPACE_OBJECTS_DENIED` and a NULL `workspace_id`, so an unknown or foreign
workspace denial is recorded without failing the audit_event workspace foreign
key and without becoming an existence oracle. Neither the pattern nor any
document content is recorded.

### REST parity

`knowvault_grep` is also served over REST at

```
GET  /api/v1/workspaces/{workspace_id}/tools/grep?pattern=KnowVault%5Cs%2Bin%5Cs%2Bfull
POST /api/v1/workspaces/{workspace_id}/tools/grep?pattern=KnowVault%5Cs%2Bin%5Cs%2Bfull
```

with the same authorized implementation, the same projection and the same
pagination as the MCP tool, so a REST client and an MCP client observe identical
matches. The route dispatches through the identical `EvidenceGrep` capability
`knowvault_grep` composes, so admission-before-data, the R1 audit journal and
the content-free denial stay exactly the existing ones. The MCP `arguments` map
onto the query string: `pattern` (required), and the optional `offset`, `limit`,
`all_versions`, `ref` and `address`. `address` selects one exact canonical
object/version without an inventory scan and is mutually exclusive with `ref`
and `all_versions`; `ref` is only a Git immutable version identity, not a path.
The POST form is the same operation for clients that invoke
knowledge tools with a POST request: parameters travel in the query string, the
request body is not a parameter channel, and a non-empty body is refused as
`400 REQUEST_INVALID` rather than being silently ignored. The CSRF gate of every
other unsafe method applies. A missing or whitespace-only `pattern`, a pattern
longer than 4096 characters, a malformed RE2 expression, a negative or
non-decimal `offset`/`limit`, a `ref` that is empty, over 256 characters or
carries whitespace, a control character or a colon, a malformed/non-text
`address`, an `address` combined with `ref` or `all_versions`, unknown query keys,
duplicates, an empty value and a malformed encoding are `400 REQUEST_INVALID`
before any object row is read. A `limit` of `0` or an omitted `limit` means the
default page of 20; a requested limit is capped at 100 and the effective value
is echoed as `limit`. A `ref` returns the same code-source-scoped projection as
the MCP tool (the ref as the address version), and an unknown or foreign ref is
the same content-free `404 NOT_FOUND`.

```json
{
  "matches": [
    {
      "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "offset": 39,
      "length": 17,
      "excerpt": "…the alpha project document mentions KnowVault in full…",
      "match_hash": "sha256:1f4d3c2b5a6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708",
      "version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "observed_at": "2026-08-13T10:00:00Z",
      "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "canonical_address": "kv1:object_01H9ABCDEFGHJKMNPQRSTVWXYZ~fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ:version_01H9ABCDEFGHJKMNPQRSTVWXYZ:text.0-58:6b1c0f2e9a4d4c1b"
    }
  ],
  "offset": 0,
  "limit": 1,
  "has_more": true,
  "next_offset": 1
}
```

Each `address` member is the same immutable address object the MCP tool returns
(source, version, object, span and nested `match`); the example above omits it
for brevity. An unknown workspace or a non-member caller gets the same
content-free denial as the MCP tool, here `404 NOT_FOUND` with no match and no
workspace-id echo; a service mounted without the grep capability fails closed as
`503 SERVICE_UNAVAILABLE`. The route is declared as an `endpointKind` with an
`openAPIRoutes` entry and an `api/openapi.yaml` path item describing both
methods, so the OpenAPI drift gate covers it. The MCP `tools/list` advertisement
and every other REST/MCP route are unchanged.

## `knowvault_related`

Read-only canonical cross-source relations of one addressed object in a
workspace (R3a-1 Outcome 2 / KV-A03-related). For the object named by
`fragment_id` or by the canonical `address`, it returns the relations the
cross-source Evidence-graph capability persists, page by page, with the
direction selecting which side of the relation the addressed object occupies:

- `referencing` — relations whose object is the addressed object (who
  references it);
- `references` — relations whose subject is the addressed object (what it
  references);
- `both` (default) — either side.

It resolves through the same authorized relation source as the cross-source
Evidence-graph read, so admission-before-data, the audit journal and the
content-free denial are the existing ones. The production composition wires the
relation source (`internal/platform/composition/relations.go`) into the mounted
evidence service, so `tools/list` advertises `knowvault_related` and a
`tools/call` naming it is served; a deployment whose evidence service does not
implement the relation capability keeps the tool unadvertised and fails closed
with `-32000`. It introduces no new store, index or migration; it is also served
over REST as the parity route described under *REST parity* below.

Every relation carries the *related* object's immutable address (source,
version, object and exact span with `text_hash`), the `relation_kind`, a bounded
`excerpt`, the version id, the moment (`observed_at`) and the content hash. A
hit's address resolves the whole related object through
`knowvault_read`. Results are ordered deterministically and paginated
with an explicit window: the effective `limit`, `has_more` and, while more
remains, `next_cursor`. A limit is never silent truncation — continuing from
`next_cursor` until `has_more` is `false` and concatenating the `relations`
arrays returns every relation exactly once. The default page is 50 relations and
a requested limit is capped at 200; the effective value is always echoed as
`limit`. The relation source's own bounded expansion cap is never silent: when it
is reached the final page reports `truncated: true` (with `has_more: false`) and
the content text says so.

### Parameters

| field | type | required | notes |
| --- | --- | --- | --- |
| `workspace_id` | string | yes | The workspace that owns the addressed object. |
| `fragment_id` | string | one of | The addressed object's fragment id. Required unless `address` is supplied. |
| `address` | string | one of | Canonical compact `internal/address` value (`kv1:<object>:<version>:<span>:<hash16>`). Parsed with `address.Parse`; when `fragment_id` is absent it selects the object, and when both are present they must name the same object (`address.Object == fragment_id`). |
| `direction` | string | no | `referencing`, `references` or `both` (default). |
| `cursor` | string | no | Stable result-set cursor. Omit for the first page; pass the `next_cursor` of the previous page to continue. A cursor this server did not produce is refused with `-32602`. |
| `limit` | integer ≥ 1 | no | Page size in relations. Defaults to 50, capped at 200. |

The schema is closed (`additionalProperties: false`): a missing or empty
`workspace_id`, neither selector, an unknown member, an unknown `direction`, a
negative/wrong-typed `limit` or a malformed `cursor` is rejected with JSON-RPC
error `-32602` before the relation source is touched. A supplied `address` whose
`object` differs from an explicit `fragment_id` is refused the same way before
any read.

### Request

```json
{
  "jsonrpc": "2.0",
  "id": "rl1",
  "method": "tools/call",
  "params": {
    "name": "knowvault_related",
    "arguments": {
      "workspace_id": "ws_alpha",
      "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "direction": "both",
      "limit": 1
    }
  }
}
```

### Response (example)

```json
{
  "jsonrpc": "2.0",
  "id": "rl1",
  "result": {
    "content": [{ "type": "text", "text": "knowvault_related: 1 relation(s); direction=both limit=1 has_more=true next_cursor=v1:1 truncated=false\n[1] address={\"object\":{\"extraction_id\":\"extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"fragment_id\":\"fragment_01H9ABCDEFGHJKMNPQRSTVWXY\",\"ordinal\":3},\"source\":{\"connection_id\":\"connection_01H9ABCDEFGHJKMNPQRSTVWXYZ\",\"source_object_id\":\"object_01H9ABCDEFGHJKMNPQRSTVWXYZ\"},\"span\":{\"anchor\":\"eyJsb2NhdG9yIjoiZmlsZTovL3ZvbC0xL3Byb2plY3RzL2FscGhhL2RvYy5tZCIsIm9mZnNldCI6MTIwfQ==\",\"length\":58,\"offset\":0,\"text_hash\":\"hmac-sha256:k1:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b\",\"total_length\":58},\"version\":{\"content_hash\":\"cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\",\"external_version_key\":\"hash:sha256:abababababababababababababababababababababababababababababababab\",\"observed_at\":\"2026-08-13T10:00:00Z\",\"source_version_id\":\"version_01H9ABCDEFGHJKMNPQRSTVWXYZ\"}} relation_kind=context.mentions excerpt=…the alpha project document references KnowVault in full… fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXY version_id=version_01H9ABCDEFGHJKMNPQRSTVWXYZ observed_at=2026-08-13T10:00:00Z content_hash=cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd\n" }],
    "structuredContent": {
      "relations": [
        {
          "relation_kind": "context.mentions",
          "excerpt": "…the alpha project document references KnowVault in full…",
          "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXY",
          "version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
          "observed_at": "2026-08-13T10:00:00Z",
          "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
          "address": {
            "source": {
              "source_object_id": "object_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "connection_id": "connection_01H9ABCDEFGHJKMNPQRSTVWXYZ"
            },
            "version": {
              "source_version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "external_version_key": "hash:sha256:abababababababababababababababababababababababababababababababab",
              "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
              "observed_at": "2026-08-13T10:00:00Z"
            },
            "object": {
              "extraction_id": "extraction_01H9ABCDEFGHJKMNPQRSTVWXYZ",
              "ordinal": 3,
              "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXY"
            },
            "span": {
              "offset": 0,
              "length": 58,
              "total_length": 58,
              "text_hash": "hmac-sha256:k1:6b1c0f2e9a4d4c1b8f3a2d5e7c9b0a1f4e6d8c2b3a5f7e9d1c3b5a7f9e1d3c5b",
              "anchor": "eyJsb2NhdG9yIjoiZmlsZTovL3ZvbC0xL3Byb2plY3RzL2FscGhhL2RvYy5tZCIsIm9mZnNldCI6MTIwfQ=="
            }
          }
        }
      ],
      "direction": "both",
      "limit": 1,
      "has_more": true,
      "next_cursor": "v1:1",
      "truncated": false
    },
    "isError": false
  }
}
```

### Denial and audit

An unknown workspace, an object the caller is not a member of, or one named only
by a foreign `address`, yields the relation source's single content-free denial,
mapped to JSON-RPC error `-32004` with message `workspace relations not found`;
the response carries no relation, excerpt or address and never echoes the
requested workspace id. The call records a content-free admission event through
the existing audit journal before any relation row is read, and its outcome
(including the denial class) afterwards, exactly like `knowvault_search` and
`knowvault_read`. Neither the object selector nor any content is
recorded.

### REST parity

`knowvault_related` is also served over REST at

```
GET  /api/v1/workspaces/{workspace_id}/tools/related?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&direction=both&limit=1
POST /api/v1/workspaces/{workspace_id}/tools/related?fragment_id=fragment_01H9ABCDEFGHJKMNPQRSTVWXYZ&direction=both&limit=1
```

with the same authorized implementation, the same projection and the same
pagination as the MCP tool, so a REST client and an MCP client observe identical
relations. The route dispatches through the identical `EvidenceRelated`
capability `knowvault_related` composes, so admission-before-data, the R1 audit
journal and the content-free denial stay exactly the existing ones. The MCP
`arguments` map onto the query string: `fragment_id` or the canonical `address`
(at least one, and if both are supplied they must name the same object), and the
optional `direction`, `cursor` and `limit`. `direction` is exactly
`referencing`, `references` or `both` (default `both`); `cursor` is the stable
`v1:<offset>` form returned as `next_cursor`. The POST form is the same
operation for clients that invoke knowledge tools with a POST request:
parameters travel in the query string, the request body is not a parameter
channel, and a non-empty body is refused as `400 REQUEST_INVALID` rather than
being silently ignored. The CSRF gate of every other unsafe method applies.

The response is exactly the MCP `structuredContent` projection:

```json
{
  "relations": [
    {
      "relation_kind": "context.mentions",
      "excerpt": "…the alpha project document references KnowVault in full…",
      "fragment_id": "fragment_01H9ABCDEFGHJKMNPQRSTVWXY",
      "version_id": "version_01H9ABCDEFGHJKMNPQRSTVWXYZ",
      "observed_at": "2026-08-13T10:00:00Z",
      "content_hash": "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd",
      "address": { "source": {}, "version": {}, "object": {}, "span": {} }
    }
  ],
  "direction": "both",
  "limit": 1,
  "has_more": true,
  "next_cursor": "v1:1",
  "truncated": false
}
```

Each `address` member is the same immutable address object the MCP tool returns
(source, version, object and span with `text_hash`); the example above abbreviates
its nested members. A malformed or foreign `cursor`, an unknown `direction`, a
missing selector, an unparsable `address` or an `address` whose object differs
from an explicit `fragment_id` is `400 REQUEST_INVALID` before the capability is
touched, along with unknown query keys, duplicates, an empty value and a
malformed encoding. A missing `limit` or `limit=0` means the default page of 50;
a requested limit is capped at 200 and the effective value is echoed as `limit`.
An unknown workspace or a non-member caller gets the same content-free denial as
the MCP tool, here `404 NOT_FOUND` with no relation and no workspace-id echo; a
service mounted without the relation capability fails closed as
`503 SERVICE_UNAVAILABLE`. The route is declared as an `endpointKind` with an
`openAPIRoutes` entry and an `api/openapi.yaml` path item describing both
methods, so the OpenAPI drift gate covers it. The MCP `tools/list` advertisement
and every other REST/MCP route are unchanged.

## Sessions that used wiki-rag

This section is the reconfiguration contract for a session (or agent
configuration) that was pointed at a wiki-rag endpoint and used its tool names.
KnowVault does not advertise or accept those names — `wiki_search`,
`wiki_get_page`, `wiki_list_pages`, `wiki_find_related`, `code_search`,
`code_get_file` appear in neither `tools/list` nor a dispatched `tools/call`: a
call naming one is refused as an unknown tool with JSON-RPC `-32602` and no
result content (owner decision 12.09.2026). The tool set is KnowVault's own and
is wider than wiki-rag: addresses, versions, moments, skip reasons, pagination
without truncation, and code and tables in one workspace.

A session that used wiki-rag is reconfigured by changing only the endpoint and
the tool names; the mapping and the replacement parameters are:

| wiki-rag tool | KnowVault tool | parameter change |
| --- | --- | --- |
| `wiki_search` | `knowvault_search` | pass `workspace_id` and `query`; optional `all_versions`, `offset`, `limit`. Results carry `excerpt`, `score`, the canonical `address`, `version_id` and `observed_at`. |
| `wiki_get_page` | `knowvault_read` | pass `workspace_id` and `fragment_id`, or the canonical `address` (`kv1:<object>:<version>:<span>:<hash16>`); page a fragment with `offset`/`limit`, or read the whole object page by page with `cursor` and reassemble it against `whole_hash`. Optional `expected_span_hash`. |
| `wiki_list_pages` | `knowvault_list_objects` | pass `workspace_id`; optional `all_versions`, `offset`, `limit`. |
| `wiki_find_related` | `knowvault_related` | pass `workspace_id` and `fragment_id` (or the canonical `address`); optional `direction` (`referencing`/`references`/`both`), `cursor`, `limit`. |
| `code_search` | `knowvault_grep` | pass `workspace_id` and `pattern`; the workspace inventory includes registered git code sources, and the optional `ref` scopes the scan to the code-source object versions whose immutable version identity matches that named ref (the `external_version_key` token from `knowvault_list_objects`, e.g. its `commit:` token). Each hit's `address.version.ref` and the version in `canonical_address` are the supplied `ref`; each ref-scoped hit also carries its `path` and 1-based `line`/`column`/`end_line`/`end_column` file:lines locator. |
| `code_get_file` | `knowvault_read` (locate the match first with `knowvault_grep` if needed) | pass `workspace_id` and the code object's `fragment_id`, or its canonical `address` (including an address whose version is the named code-source `ref`); read the file page by page with `cursor`, or a byte window with `offset`/`limit`. A named-ref address is resolved from the object inventory's `GIT_FILE`/`external_version_key` identity before any content is read, so the `canonical_address` a ref-scoped `knowvault_grep` hit returns round-trips through `knowvault_read`. |

Concretely, a session that sent

```json
{ "name": "wiki_search", "arguments": { "wiki": "alpha", "query": "KnowVault" } }
```

to `https://wiki-rag.example/mcp` changes only the endpoint and the tool name:

```json
{
  "jsonrpc": "2.0",
  "id": "m1",
  "method": "tools/call",
  "params": {
    "name": "knowvault_search",
    "arguments": { "workspace_id": "ws_alpha", "query": "KnowVault" }
  }
}
```

sent to `https://<knowvault-host>/api/v1/mcp`. The wiki-rag workspace selector
(`wiki`/`project`) and page selector (`page`) are not decoded anywhere on the
list or read path: only the canonical `workspace_id`/`fragment_id` names and the
canonical `address` are accepted, and the result shapes are the canonical ones
documented above. A `tools/list` against KnowVault never returns a wiki-rag name,
and a `tools/call` naming one is refused with `-32602` and no result content.

## External-agent MCP probe

`scripts/mcp-external-client.ps1` is a self-contained PowerShell probe (no
dependency, no route, no migration) that acts as an external MCP agent against
the streamable-HTTP endpoint above. It reads every input from the environment
and embeds no secret, so an operator points it at a deployment with:

```powershell
$env:KNOWVAULT_MCP_ENDPOINT             = 'https://knowvault.example/api/v1/mcp'
$env:KNOWVAULT_MCP_MEMBER_TOKEN         = '<human member session bearer token>'
$env:KNOWVAULT_MCP_SERVICE_TOKEN        = 'kva_...'
$env:KNOWVAULT_MCP_WORKSPACE_ID         = 'ws_alpha'
$env:KNOWVAULT_MCP_FOREIGN_WORKSPACE_ID = 'ws_other'
pwsh -File scripts/mcp-external-client.ps1
```

The probe prints one `ok:` line per checked outcome and exits non-zero on the
first failed assertion. Optional `KNOWVAULT_MCP_EXPIRED_TOKEN` (expired or
foreign), `KNOWVAULT_MCP_QUERY` (a term present in the member workspace) and
`KNOWVAULT_MCP_PAGE_LIMIT` (the page size the probe drives) refine the run; when
`KNOWVAULT_MCP_EXPIRED_TOKEN` is unset the probe uses a fixed non-member token so
the unauthorized path is still exercised. Expected outcomes:

- member `initialize` returns `serverInfo.name = "knowvault"`, and member
  `tools/list` advertises only `knowvault_*` names, includes
  `knowvault_search`, `knowvault_read`, `knowvault_list_objects`,
  `knowvault_related`, `knowvault_grep`, `knowvault_sources` and
  `knowvault_refresh`, and advertises no `wiki_search`, `wiki_get_page`,
  `wiki_list_pages`, `wiki_find_related`, `code_search` or `code_get_file`;
- a `tools/call` naming a wiki-rag tool is refused `-32602` with no result
  content;
- `knowvault_search` returns an addressed hit; following its address into
  `knowvault_read` returns an explicit window (`offset`, `length`, `limit`,
  `has_more`, `next_offset`) whose `text_hash` is the addressed span hash;
- paging the whole object from the empty `cursor` through `next_cursor` until
  `has_more` is false: each cursor-page `knowvault_read` call passes
  `include_text_base64: true`, so the probe decodes every
  `structuredContent.text_base64` page, appends the page bytes and asserts
  each page starts at the reassembled offset, that all pages agree on
  `whole_hash`, and that the reassembled bytes hash to the `whole_hash` the
  read reported with a length equal to `total_bytes`;
- `knowvault_search`, `knowvault_read`, `knowvault_list_objects` and
  `knowvault_sources` against the foreign workspace each return the existing
  content-free `-32004` with no result and no workspace-id echo;
- the service-principal token maps to workspace membership: `tools/list` shows
  the canonical knowledge tools and none of the administrative tools, and the
  foreign workspace is denied `-32004` content-free;
- an expired or foreign token gets `401 UNAUTHENTICATED` and no tool-list
  content beyond names.
