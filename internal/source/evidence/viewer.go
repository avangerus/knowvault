// Package evidence is the authorized Evidence viewer for P2/I1/S1d. It runs on
// the application (not worker) role and returns an Evidence fragment's decrypted
// normalized text and canonical anchor only to a caller who passes the full
// fail-closed authorization gate. An unauthorized viewer, a cross-tenant caller
// and an ACL_UNKNOWN caller all receive the same not-found: there is no
// existence oracle.
package evidence

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// auditSink is the minimal audit writer the viewer appends its journal event
// to. The real sink is an *audit.Store backed by the same database; a test may
// substitute a recorder to prove exactly-one emission without a database.
type auditSink interface {
	Append(ctx context.Context, access database.AccessContext, input audit.EventInput) (audit.Event, error)
}

// ErrNotFound is returned for every denied read: not authorized, not current,
// cross-tenant or non-existent. It never distinguishes these cases.
var ErrNotFound = errors.New("evidence: fragment not readable")

// fragmentProvenance carries the immutable catalog identifiers of one
// evidence_fragment row; every value is non-content metadata.
type fragmentProvenance struct {
	IsCurrentVersion      bool
	HasExternalID         bool
	ExternalIDDigest      string
	ExtractionID          string
	SourceVersionID       string
	Ordinal               int64
	ExternalVersionKey    string
	ContentHash           string
	ObservedAt            time.Time
	SourceObjectID        string
	ConnectionID          string
	ObjectType            string
	CanonicalFormat       string
	ParserProfileRevision string
	EvidenceTextHash      string
	AnchorHash            string
}

// Fragment is the viewer's result: the exact canonical text a permitted user
// sees, the canonical anchor that re-resolves it, and the immutable catalog
// metadata that places the fragment in the provenance chain (ADR-0073 §1.2).
// SourcePath is content metadata decrypted only through the same authorized
// repository as the text. Other provenance fields contain catalog identifiers.
type Fragment struct {
	FragmentID string
	Text       []byte
	Anchor     []byte
	SourcePath string
	// IsCurrentVersion is observed under the same tenant-bound authorized read;
	// false does not promise a readable replacement version exists.
	IsCurrentVersion bool
	// Equality projections accompany the plaintext so a search candidate can
	// be checked against the immutable catalog row before answer disclosure.
	// They carry no source content.
	EvidenceTextHash string
	AnchorHash       string

	ExtractionID          string
	SourceVersionID       string
	Ordinal               int64
	ExternalVersionKey    string
	ContentHash           string
	ObservedAt            time.Time
	SourceObjectID        string
	ConnectionID          string
	ObjectType            string
	CanonicalFormat       string
	ParserProfileRevision string
}

// ObjectInventoryItem describes one object/version. Its optional external
// identity is source content and passes the fragment readability gate before
// disclosure. The full canonical text and anchor require a separate read.
type ObjectInventoryItem struct {
	hasExternalID    bool
	externalIDDigest string
	SourceObjectID   string
	ObjectType       string
	// ExternalID is the object's authorized external identity, decrypted
	// through the object's own activated external-object-id owner branch
	// (R3a-1 code sources, extended to documents): for a file it is the
	// source-relative path the connector stamped. It is content
	// metadata, so readObjects discloses it only after the same
	// app.evidence_fragment_readable access-point gate the object's content
	// read passes; a caller must not project it onto a surface that was not
	// already authorized to disclose the object identity.
	ExternalID         string
	ConnectionID       string
	LifecycleState     string
	SourceVersionID    string
	ExternalVersionKey string
	ContentHash        string
	ObservedAt         time.Time
	VersionState       string
	Current            bool
	FragmentCount      int64
	FirstFragmentID    string
	FirstOrdinal       int64
	LastOrdinal        int64
	// MirrorAgeSeconds and MirroredAt are the code-source mirror age of one
	// GIT_FILE object (R3a-1 KV-A04a). MirroredAt is the code source's
	// already-persisted last successful mirror/sync moment, exactly the
	// moment app.workspace_source_status_v3 exposes to the workspace
	// knowvault_sources tool; MirrorAgeSeconds is the non-negative elapsed
	// time since that moment. A document/evidence object has no code-source
	// mirror and keeps both zero/nil, so it is never mislabelled as a mirror.
	MirrorAgeSeconds int64
	MirroredAt       *time.Time
	// EmbeddingProfileID and EmbeddingProfileHash retain legacy ingest
	// metadata from one immutable chunk of this version. Empty values do not
	// prove absence of vectors: the indexer can embed lexical chunks without
	// changing them. Non-empty values do not prove a successful index write,
	// the active profile, or coverage of every current-extraction chunk.
	// Public inventory must not expose these fields as actual index status.
	EmbeddingProfileID   string
	EmbeddingProfileHash string
}

// ObjectInventoryPage is one explicit page of a workspace's object inventory.
// HasMore true means more rows remain after this page; NextOffset is the
// stable cursor the caller passes back as offset to fetch the next page, so a
// limit is never silent truncation. Skipped is the typed, content-free skip
// projection of the same workspace (R3a-1 KV-A02): one entry per object the
// workspace's bound scopes skipped, with the closed reason code and the moment.
type ObjectInventoryPage struct {
	Items      []ObjectInventoryItem
	HasMore    bool
	NextOffset int64
	Skipped    []ObjectInventorySkip
}

// ObjectInventorySkip is one typed, content-free skip of a workspace object. A
// skipped observation has no readable version of its own (an older version may
// still exist), so it carries only the connector's stable external id, the closed
// reason code and the moment the skip was observed — never source content.
type ObjectInventorySkip struct {
	ExternalID string
	ReasonCode string
	ObservedAt time.Time
}

// skipLedgerRow is one raw public.source_object_skip ledger row of the
// authorized skip projection, read before its native identity is decrypted.
// scopeID and scopeRevision key the source scope the skip belongs to (the
// identity is unique per scope revision); syncRunID is the stable tie-break
// when two rows share observedAt. digest_key_version is carried because the
// digest is key-version scoped: a rotated digester key writes a second
// PK-distinct row for the same native object rather than updating the first.
type skipLedgerRow struct {
	scopeID       string
	scopeRevision int64
	digest        string
	keyVersion    int64
	artifactID    string
	reasonCode    string
	observedAt    time.Time
	syncRunID     string
}

// skipIdentityEvidence is the sealed plaintext of one skip identity (KV-A02b):
// the native external id plus the org-keyed digest the ledger row also stores.
// The read path returns a skip only when the decrypted digest equals the stored
// digest, so a tampered ledger row is withheld fail closed.
type skipIdentityEvidence struct {
	ExternalID string `json:"external_id"`
	Digest     string `json:"digest"`
}

// Viewer reads authorized Evidence for one organization.
type Viewer struct {
	db    *database.Store
	codec *artifactcrypto.Codec
	audit auditSink

	// authorizeFn and readFn are the two database-backed steps of Read. They are
	// nil in production (where the real methods run) and exist so the unit tests
	// can prove the admission-before-data ordering and the fail-closed refusal
	// without a database. They never widen authorization: the real read repeats
	// the readability gate at the access point.
	authorizeFn func(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) (bool, error)
	readFn      func(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) (Fragment, error)

	// readObjectFn is the whole-object assembly step of ReadObject. It is nil
	// in production (where readAuthorizedObject runs) and exists so the unit
	// tests can prove the admission-before-data ordering, the content-free
	// denial class and the fail-closed refusal without a database. It never
	// widens authorization: the real assembly repeats the readability gate at
	// the access point for every fragment it opens.
	readObjectFn func(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) (WholeObject, error)

	// Exact-version reads have independent seams so tests can prove that the
	// requested immutable source version is carried through authorization and
	// the governed fetch without changing current-only Read or ReadObject.
	authorizeExactFn  func(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, expectedVersionID string) (bool, error)
	readExactFn       func(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, expectedVersionID string) (Fragment, error)
	readObjectExactFn func(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, expectedVersionID string) (WholeObject, error)

	// authorizeWorkspaceFn is the workspace-membership decision seam for
	// ListObjects. It is nil in production (where authorizeWorkspace runs) and
	// exists so the inventory denial journalling can be proven without a
	// database. It never widens authorization: the production fetch repeats the
	// live-membership gate at the access point.
	authorizeWorkspaceFn func(ctx context.Context, access database.AccessContext, workspaceID string) (bool, error)
}

// NewViewer builds the viewer with its own artifact repository bound to the
// Evidence read branches. The read is gated by app.evidence_fragment_readable
// before any ciphertext is fetched. The viewer is bound to the audit journal so
// every authorized read first appends one admission event and then the existing
// citation.opened outcome event.
func NewViewer(db *database.Store, codec *artifactcrypto.Codec) (*Viewer, error) {
	if db == nil || codec == nil {
		return nil, errors.New("evidence: viewer dependencies are required")
	}
	sink, err := audit.NewStore(db)
	if err != nil {
		return nil, errors.New("evidence: viewer audit sink is required")
	}
	return &Viewer{db: db, codec: codec, audit: sink}, nil
}

// repositoryForWorkspace creates a repository whose authorization callback is
// a real database gate.  The workspace is request-scoped and is never stored
// in the generic AccessContext, so a repository cannot accidentally retain one
// caller's workspace for the next request.
func repositoryForWorkspace(workspaceID string) (*repository.Repository, error) {
	authorize := func(ctx context.Context, transaction database.Transaction, _ database.AccessContext, fragmentID string) error {
		var readable bool
		if err := transaction.QueryRow(ctx, `SELECT app.evidence_fragment_readable($1, $2)`, fragmentID, workspaceID).Scan(&readable); err != nil {
			return err
		}
		if !readable {
			return ErrNotFound
		}
		return nil
	}
	// authorizeExternalID is the access point for the object-level external
	// identity (the repository-relative path of a code source). The object
	// identity is disclosed only while at least one fragment of that object is
	// readable in this workspace under the same fail-closed
	// app.evidence_fragment_readable gate the content read passes, so an
	// object whose content is hidden never leaks its path.
	authorizeExternalID := func(ctx context.Context, transaction database.Transaction, access database.AccessContext, sourceObjectID string) error {
		var readable bool
		if err := transaction.QueryRow(ctx, `
			WITH object_fragments AS MATERIALIZED (
				SELECT f.id
				FROM public.source_version v
				JOIN public.evidence_fragment f
				  ON f.organization_id = v.organization_id AND f.source_version_id = v.id
				WHERE v.organization_id = $1 AND v.source_object_id = $2
			)
			SELECT EXISTS (
				SELECT 1
				FROM object_fragments f
				WHERE app.evidence_fragment_readable(f.id, $3)
			)`, access.OrganizationID, sourceObjectID, workspaceID).Scan(&readable); err != nil {
			return err
		}
		if !readable {
			return ErrNotFound
		}
		return nil
	}
	text, err := repository.NewBinding(artifactcrypto.EvidenceNormalizedText,
		"app.evidence_fragment_bind_normalized_text", "app.evidence_fragment_read_normalized_text", authorize)
	if err != nil {
		return nil, err
	}
	anchor, err := repository.NewBinding(artifactcrypto.EvidenceAnchor,
		"app.evidence_fragment_bind_anchor", "app.evidence_fragment_read_anchor", authorize)
	if err != nil {
		return nil, err
	}
	metadata, err := repository.NewBinding(artifactcrypto.EvidenceMetadata,
		"app.evidence_fragment_bind_metadata", "app.evidence_fragment_read_metadata", authorize)
	if err != nil {
		return nil, err
	}
	externalID, err := repository.NewBinding(artifactcrypto.SourceObjectExternalID,
		"app.source_object_bind_external_object_id", "app.source_object_read_external_object_id", authorizeExternalID)
	if err != nil {
		return nil, err
	}
	locator, err := repository.NewBinding(artifactcrypto.SourceObjectCanonicalLocator,
		"app.source_object_bind_canonical_locator", "app.source_object_read_canonical_locator", authorizeExternalID)
	if err != nil {
		return nil, err
	}
	repo, err := repository.New(text, anchor, metadata, externalID, locator)
	if err != nil {
		return nil, err
	}
	return repo, nil
}

// objectTypeGitFile is the catalog object_type of a registered git code-source
// file (observation.GitAdapter publishes "GIT_FILE"). Its inventory carries
// mirror-specific metadata in addition to the common source path.
const objectTypeGitFile = "GIT_FILE"

// readObjectExternalID decrypts one source object's authorized external
// identity through the object's own activated owner branch. The repository
// authorize step re-checks app.evidence_fragment_readable against a fragment of
// that object in the caller's workspace (repositoryForWorkspace), so the
// identity is disclosed only to a caller the content read would also serve. An
// absent or unreadable artifact is the single content-free ErrNotFound. The
// object type, connection and HMAC-keyed digest are selected by the caller's
// tenant-bound catalog query. PostgreSQL rows additionally prove that their
// sealed canonical locator carries the same connection, lineage and digest;
// FILE/GIT and legacy identities keep their existing path projection.
func (v *Viewer) readObjectExternalID(ctx context.Context, transaction database.Transaction, repo *repository.Repository, access database.AccessContext, sourceObjectID, objectType, connectionID, opaqueID string) (string, error) {
	if repo == nil || sourceObjectID == "" || objectType == "" {
		return "", ErrNotFound
	}
	owner, envelope, err := repo.Fetch(ctx, transaction, access, artifactcrypto.SourceObjectExternalID, sourceObjectID)
	if err != nil {
		return "", err
	}
	plaintext, err := v.codec.Open(owner, envelope)
	if err != nil {
		return "", err
	}
	if objectType == "POSTGRESQL_QUERY_ROW" {
		identity, err := parsePostgreSQLQueryIdentity(string(plaintext))
		if err != nil {
			return "", ErrNotFound
		}
		locatorOwner, locatorEnvelope, err := repo.Fetch(ctx, transaction, access, artifactcrypto.SourceObjectCanonicalLocator, sourceObjectID)
		if err != nil {
			return "", err
		}
		locatorPlaintext, err := v.codec.Open(locatorOwner, locatorEnvelope)
		if err != nil {
			return "", err
		}
		if err := validatePostgreSQLQueryCanonicalLocator(string(locatorPlaintext), connectionID, identity.LineageID, opaqueID); err != nil {
			return "", err
		}
		return sourcePostgreSQLQueryDisplayFromIdentity(identity, opaqueID)
	}
	if objectType != "FILE" && objectType != "GIT_FILE" && objectType != "EMAIL" && objectType != "EMAIL_ATTACHMENT" {
		return "", ErrNotFound
	}
	return sourceExternalPath(string(plaintext))
}

// readSkipExternalID decrypts one skip identity through the identity branch's
// tenant-fenced SECURITY DEFINER read function and returns the native external
// id only when the identity artifact's sealed digest matches the digest the
// ledger row stores. Every failure — an absent/foreign/purged artifact, a
// malformed envelope, or a digest mismatch — returns ok=false, so a tampered
// ledger entry is withheld fail closed rather than disclosed.
func (v *Viewer) readSkipExternalID(ctx context.Context, transaction database.Transaction, access database.AccessContext, artifactID, storedDigest string) (string, bool) {
	if artifactID == "" || storedDigest == "" {
		return "", false
	}
	var (
		resourceID, wrappedDEKHash, kekReference, aadHash, plaintextHash string
		ciphertext, nonce, wrappedDEK                                    []byte
		sizeBytes                                                        int
		kekVersion                                                       int64
	)
	err := transaction.QueryRow(ctx, `SELECT resource_id, ciphertext, size_bytes, nonce, wrapped_dek,
			wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
		FROM app.source_object_skip_read_external_id($1)`, artifactID).Scan(
		&resourceID, &ciphertext, &sizeBytes, &nonce, &wrappedDEK,
		&wrappedDEKHash, &kekReference, &kekVersion, &aadHash, &plaintextHash)
	if err != nil {
		return "", false
	}
	owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.SourceObjectExternalID, access.OrganizationID, resourceID)
	if err != nil {
		return "", false
	}
	envelope := artifactcrypto.NewEnvelopeFromStorage(owner, artifactcrypto.CipherAES256GCM, ciphertext, sizeBytes, nonce,
		wrappedDEK, wrappedDEKHash, kekReference, kekVersion, aadHash, plaintextHash)
	if !envelope.Valid() {
		return "", false
	}
	plaintext, err := v.codec.Open(owner, envelope)
	if err != nil {
		return "", false
	}
	var identity skipIdentityEvidence
	if err := jsonv2.Unmarshal(plaintext, &identity); err != nil {
		return "", false
	}
	if identity.ExternalID == "" || subtle.ConstantTimeCompare([]byte(identity.Digest), []byte(storedDigest)) != 1 {
		return "", false
	}
	return identity.ExternalID, true
}

// selectSkipIdentities decrypts each authorized skip ledger row through the
// supplied verifier and projects at most one ObjectInventorySkip per decrypted
// native external id within one (source scope, scope revision). Deduping on the
// native identity — not on the versioned digest — keeps the inventory correct
// across a digester key rotation: the same source object written under two
// digest_key_version values yields one skip, the one with the greatest
// observed_at (sync_run_id tie-break, digest key version last), so the newest
// reason code and moment win.
// Two genuinely different native ids in the same scope still project as two
// skips. The output order is deterministic (native external id, reason code,
// observed_at) and independent of map iteration. A row whose verifier declines
// (a missing artifact or a non-matching digest) contributes nothing, so the
// fail-closed withholding is unchanged.
func selectSkipIdentities(ledger []skipLedgerRow, decrypt func(skipLedgerRow) (string, bool)) []ObjectInventorySkip {
	type skipKey struct {
		scopeID       string
		scopeRevision int64
		externalID    string
	}
	type selectedSkip struct {
		skip       ObjectInventorySkip
		syncRunID  string
		keyVersion int64
	}
	selected := map[skipKey]selectedSkip{}
	order := []skipKey{}
	for _, row := range ledger {
		externalID, ok := decrypt(row)
		if !ok {
			continue
		}
		key := skipKey{scopeID: row.scopeID, scopeRevision: row.scopeRevision, externalID: externalID}
		existing, found := selected[key]
		skip := ObjectInventorySkip{ExternalID: externalID, ReasonCode: row.reasonCode, ObservedAt: row.observedAt}
		if !found {
			selected[key] = selectedSkip{skip: skip, syncRunID: row.syncRunID, keyVersion: row.keyVersion}
			order = append(order, key)
			continue
		}
		newer := row.observedAt.After(existing.skip.ObservedAt) ||
			(row.observedAt.Equal(existing.skip.ObservedAt) && row.syncRunID > existing.syncRunID) ||
			(row.observedAt.Equal(existing.skip.ObservedAt) && row.syncRunID == existing.syncRunID && row.keyVersion > existing.keyVersion)
		if newer {
			selected[key] = selectedSkip{skip: skip, syncRunID: row.syncRunID, keyVersion: row.keyVersion}
		}
	}
	projected := make([]ObjectInventorySkip, 0, len(order))
	for _, key := range order {
		projected = append(projected, selected[key].skip)
	}
	sort.SliceStable(projected, func(i, j int) bool {
		if projected[i].ExternalID != projected[j].ExternalID {
			return projected[i].ExternalID < projected[j].ExternalID
		}
		if projected[i].ReasonCode != projected[j].ReasonCode {
			return projected[i].ReasonCode < projected[j].ReasonCode
		}
		return projected[i].ObservedAt.Before(projected[j].ObservedAt)
	})
	return projected
}

// Read returns the fragment's decrypted text and anchor if and only if the
// caller (from the trusted access context) is authorized for it in the given
// workspace. Every denial is ErrNotFound.
//
// Outcome 2 (audit before data) orders the flow as four steps. The content-free
// access decision runs first, so a denied read stays indistinguishable and
// appends nothing. Only after an ALLOW decision is the mandatory admission
// event persisted; if it cannot be recorded the read fails closed with the same
// content-free ErrNotFound and no fragment is ever fetched. The governed fetch
// then runs (repeating the gate at the access point), and a failure after
// admission is matched by a failure outcome event. The existing citation.opened
// outcome is appended last and is unchanged.
func (v *Viewer) Read(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) (Fragment, error) {
	authorize := v.authorizeFn
	if authorize == nil {
		authorize = v.authorizeAuthorized
	}
	read := v.readFn
	if read == nil {
		read = v.readAuthorized
	}

	authorized, err := authorize(ctx, access, workspaceID, fragmentID)
	if err != nil || !authorized {
		return Fragment{}, ErrNotFound
	}
	// Admission first: nothing is fetched or returned until the admission
	// journal event is durable. A failed admission is the same content-free
	// refusal a denial gets and leaves no partial result.
	if err := v.emitAdmission(ctx, access, workspaceID, fragmentID); err != nil {
		return Fragment{}, ErrNotFound
	}
	result, err := read(ctx, access, workspaceID, fragmentID)
	if err != nil {
		// A governed read that fails after admission leaves the admission event
		// plus its matching failure outcome, never the admission alone.
		_ = v.emitReadFailed(ctx, access, workspaceID, fragmentID)
		return Fragment{}, ErrNotFound
	}
	if err := v.emitOpened(ctx, access, workspaceID, result); err != nil {
		// The success outcome could not land: record the matching failure
		// outcome and keep the fail-closed refusal.
		_ = v.emitReadFailed(ctx, access, workspaceID, fragmentID)
		return Fragment{}, ErrNotFound
	}
	return result, nil
}

// WholeObject is the authorized text assembly of one immutable extraction.
// Representation distinguishes verified canonical input from legacy ordered
// fragment concatenation. The whole hash always identifies the bytes actually
// returned, preserving old whole addresses without claiming lost whitespace.
type WholeObject struct {
	Fragment       Fragment
	Text           []byte
	Representation WholeTextRepresentation
	// Fragments locate each authorized fragment in the assembled byte stream.
	// They let a page cite its own fragment instead of borrowing the anchor.
	Fragments     []ObjectFragmentSpan
	FragmentCount int64
	FirstOrdinal  int64
	LastOrdinal   int64
}

type ObjectFragmentSpan struct {
	FragmentID string
	Ordinal    int64
	Offset     int
	Length     int
}

// ReadObject returns the assembled text of the fragment's source version
// to a caller authorized for the addressed anchor fragment. It is the additive
// whole-object read the workspace read tool composes when a request carries a
// page cursor (R3a-1 KV-A02a); it reuses the same fail-closed authorization
// seam, admission-before-data ordering, audit journal and content-free
// ErrNotFound denial the single-fragment Read uses, so the two read modes can
// never drift apart. The anchor is read first and exactly as Read does; the
// remaining fragments of the same version are then opened one by one through the
// same workspace-scoped, access-point-re-checked artifact repository, so a
// fragment that becomes unreadable closes the whole assembly with no partial
// content. A denial is journalled as the content-free classed denied admission
// the workspace inventory and search surfaces already append, and still returns
// the single ErrNotFound.
func (v *Viewer) ReadObject(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) (WholeObject, error) {
	if v == nil || workspaceID == "" || fragmentID == "" {
		return WholeObject{}, ErrNotFound
	}
	authorize := v.authorizeFn
	if authorize == nil {
		authorize = v.authorizeAuthorized
	}
	read := v.readObjectFn
	if read == nil {
		read = v.readAuthorizedObject
	}

	authorized, err := authorize(ctx, access, workspaceID, fragmentID)
	if err != nil || !authorized {
		// A denied or unknown object appends the content-free denied admission
		// event with its class and discloses no text, so the denial is
		// journalled without becoming an existence oracle. A denial whose
		// journal record could not land is surfaced but the caller still sees
		// the unchanged content-free ErrNotFound.
		if denyErr := v.emitObjectDenied(ctx, access, workspaceID); denyErr != nil {
			return WholeObject{}, fmt.Errorf("%w: %w", ErrNotFound, denyErr)
		}
		return WholeObject{}, ErrNotFound
	}
	// Admission first: nothing is assembled or returned until the admission
	// journal event is durable. A failed admission is the same content-free
	// refusal and leaves no partial result.
	if err := v.emitAdmission(ctx, access, workspaceID, fragmentID); err != nil {
		return WholeObject{}, ErrNotFound
	}
	result, err := read(ctx, access, workspaceID, fragmentID)
	if err != nil {
		_ = v.emitReadFailed(ctx, access, workspaceID, fragmentID)
		return WholeObject{}, ErrNotFound
	}
	if err := v.emitOpened(ctx, access, workspaceID, result.Fragment); err != nil {
		_ = v.emitReadFailed(ctx, access, workspaceID, fragmentID)
		return WholeObject{}, ErrNotFound
	}
	return result, nil
}

// ListObjects returns one explicit page of the current-version inventory of a
// workspace's document/evidence objects to a caller whose current membership is
// live. It is the additive read the workspace inventory MCP tool composes; it
// reuses the same admission-before-data ordering, audit journal and
// content-free ErrNotFound denial the fragment Read uses. With allVersions
// false only the object's current version is returned; with true every version
// of every workspace-bound object is returned. offset/limit page the result
// with the same stable ordering, and a page never silently truncates: the
// caller sees HasMore and the NextOffset cursor.
func (v *Viewer) ListObjects(ctx context.Context, access database.AccessContext, workspaceID string, allVersions bool, offset, limit int64) (ObjectInventoryPage, error) {
	if v == nil || v.db == nil || workspaceID == "" || offset < 0 || limit < 1 {
		return ObjectInventoryPage{}, ErrNotFound
	}
	authorize := v.authorizeWorkspaceFn
	if authorize == nil {
		authorize = v.authorizeWorkspace
	}
	authorized, err := authorize(ctx, access, workspaceID)
	if err != nil || !authorized {
		// A denied or unknown workspace appends the content-free denied
		// admission event (with its class) and discloses no row, so the denial
		// is journalled without becoming an existence oracle. The append error
		// is surfaced through the returned error instead of being discarded, so
		// a denial whose journal record could not land is observable; the caller
		// still sees the unchanged content-free ErrNotFound.
		if denyErr := v.emitInventoryDenied(ctx, access, workspaceID); denyErr != nil {
			return ObjectInventoryPage{}, fmt.Errorf("%w: %w", ErrNotFound, denyErr)
		}
		return ObjectInventoryPage{}, ErrNotFound
	}
	// Admission first: nothing is read until the admission event is durable. A
	// failed admission is the same content-free refusal and leaves no page.
	if err := v.emitWorkspaceEvent(ctx, access, workspaceID, audit.OutcomeSuccess, audit.ActionEvidenceReadAdmitted, ""); err != nil {
		return ObjectInventoryPage{}, ErrNotFound
	}
	items, skips, hasMore, err := v.readObjects(ctx, access, workspaceID, allVersions, offset, limit)
	if err != nil {
		_ = v.emitWorkspaceEvent(ctx, access, workspaceID, audit.OutcomeFailed, audit.ActionEvidenceReadFailed, auditInventoryReadFailedCode)
		return ObjectInventoryPage{}, ErrNotFound
	}
	page := ObjectInventoryPage{Items: items, HasMore: hasMore, Skipped: skips}
	if hasMore {
		page.NextOffset = offset + int64(len(items))
	}
	return page, nil
}

// authorizeWorkspace resolves the content-free membership decision for one
// workspace without fetching any object row. A denied, absent or non-member
// workspace is reported as false.
func (v *Viewer) authorizeWorkspace(ctx context.Context, access database.AccessContext, workspaceID string) (bool, error) {
	if v == nil || v.db == nil {
		return false, ErrNotFound
	}
	authorized := false
	err := v.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM public.workspace w
				JOIN public.workspace_member wm
				  ON wm.organization_id = w.organization_id AND wm.workspace_id = w.id
				 AND wm.principal_id = app.current_principal_id()
				 AND wm.valid_to_revision IS NULL AND wm.removed_at IS NULL
				WHERE w.organization_id = $1 AND w.id = $2
			)`, access.OrganizationID, workspaceID).Scan(&authorized); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return authorized, nil
}

// readObjects is the governed fetch performed only after admission. It repeats
// the live-membership gate at the access point and returns one page of the
// workspace's object inventory in the stable (source_object_id, source_version_id)
// order. It asks for one row more than the page so HasMore is exact.
//
// The workspace binding is expressed as a single correlated EXISTS over the
// enabled scope, so an object reachable through two or more enabled
// workspace_revision_source scopes still produces exactly one row per
// (source_object_id, source_version_id): the query never multiplies rows across
// memberships, and paging over (source_object_id, source_version_id) can neither
// duplicate nor omit a row. The EXISTS carries the same fail-closed visibility
// gates app.evidence_fragment_readable applies — WORKSPACE_MANAGED access mode,
// a live unrevoked workspace_managed_grant_confirmation binding and a queryable
// source_version_retention — so a version the read path refuses is never
// presented as readable.
func (v *Viewer) readObjects(ctx context.Context, access database.AccessContext, workspaceID string, allVersions bool, offset, limit int64) ([]ObjectInventoryItem, []ObjectInventorySkip, bool, error) {
	items := []ObjectInventoryItem{}
	skips := []ObjectInventorySkip{}
	fetch := limit + 1
	// The object-level external identity (a code source's repository-relative
	// path) lives behind the object's own activated owner branch. The
	// repository re-checks app.evidence_fragment_readable at the access point,
	// so the identity is disclosed only for an object whose content read the
	// caller would be served anyway.
	repo, err := repositoryForWorkspace(workspaceID)
	if err != nil {
		return nil, nil, false, err
	}
	err = v.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID); err != nil {
			return err
		}
		var authorized bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM public.workspace w
				JOIN public.workspace_member wm
				  ON wm.organization_id = w.organization_id AND wm.workspace_id = w.id
				 AND wm.principal_id = app.current_principal_id()
				 AND wm.valid_to_revision IS NULL AND wm.removed_at IS NULL
				WHERE w.organization_id = $1 AND w.id = $2
			)`, access.OrganizationID, workspaceID).Scan(&authorized); err != nil {
			return err
		}
		if !authorized {
			return ErrNotFound
		}
		rows, err := tx.Query(ctx, `
			SELECT o.id, o.object_type, o.connection_id, o.lifecycle_state,
			       v.id, v.external_version_key, v.content_hash, v.observed_at, v.state,
			       COALESCE(fc.fragment_count, 0), COALESCE(fc.first_fragment_id, ''),
			       COALESCE(fc.first_ordinal, 0), COALESCE(fc.last_ordinal, 0),
			       mirror.mirrored_at,
			       -- Legacy ingest metadata only: this immutable chunk profile
			       -- does not attest the current index or whole-version coverage.
			       COALESCE(embedded.profile_id, ''), COALESCE(embedded.profile_hash, ''),
			       o.external_object_id_artifact_id IS NOT NULL,
			       o.external_object_id_digest
			FROM public.source_object o
			JOIN public.source_version v
			  ON v.organization_id = o.organization_id AND v.source_object_id = o.id
			LEFT JOIN LATERAL (
				SELECT count(*)::bigint AS fragment_count,
				       (array_agg(f.id ORDER BY f.ordinal))[1] AS first_fragment_id,
				       min(f.ordinal) AS first_ordinal,
				       max(f.ordinal) AS last_ordinal
				FROM public.evidence_fragment f
				JOIN public.source_version_active_extraction ae
				  ON ae.organization_id = f.organization_id
				 AND ae.source_version_id = f.source_version_id
				 AND ae.extraction_id = f.extraction_id
				WHERE f.organization_id = o.organization_id
				  AND f.source_version_id = v.id
			) fc ON true
			-- R3a-1 KV-A04a: the code-source mirror age. A GIT_FILE object
			-- additionally carries the code source's already-persisted last
			-- successful mirror/sync moment, read through the same
			-- membership-gated workspace source-status projection the
			-- knowvault_sources tool exposes. A document object is never
			-- joined, so it keeps the byte-identical prior projection and
			-- no mirror member.
			LEFT JOIN LATERAL (
				SELECT status.last_successful_sync_at AS mirrored_at
				FROM app.workspace_source_status_v3($2) AS status
				WHERE status.connection_id = o.connection_id
				  AND status.last_successful_sync_at IS NOT NULL
				ORDER BY status.last_successful_sync_at DESC
				LIMIT 1
			) mirror ON o.object_type = 'GIT_FILE'
			LEFT JOIN LATERAL (
				SELECT profile.embedding_profile_id AS profile_id,
				       chunk.embedding_profile_hash AS profile_hash
				FROM public.search_chunk chunk
				JOIN public.organization_search_profile profile
				  ON profile.organization_id = chunk.organization_id
				 AND profile.embedding_profile_hash = chunk.embedding_profile_hash
				WHERE chunk.organization_id = o.organization_id
				  AND chunk.source_version_id = v.id
				  AND chunk.embedding_profile_hash IS NOT NULL
				ORDER BY profile.activation_revision DESC, chunk.id
				LIMIT 1
			) embedded ON true
			WHERE o.organization_id = $1
			  AND o.lifecycle_state = 'ACTIVE'
			  AND ($3 OR o.current_version_id = v.id)
			  AND EXISTS (
			      SELECT 1
			      FROM public.source_object_scope os
			      JOIN public.workspace w
			        ON w.organization_id = o.organization_id AND w.id = $2
			      JOIN public.workspace_revision_source wrs
			        ON wrs.organization_id = w.organization_id AND wrs.workspace_id = w.id
			       AND wrs.workspace_revision = w.current_revision
			       AND wrs.source_scope_id = os.source_scope_id
			       AND wrs.source_scope_revision = os.source_scope_revision
			       AND wrs.enabled
			       AND wrs.access_mode = 'WORKSPACE_MANAGED'
			      JOIN public.workspace_managed_grant_confirmation c
			        ON c.organization_id = w.organization_id AND c.workspace_id = w.id
			       AND c.workspace_source_id = wrs.workspace_source_id
			       AND c.source_scope_id = os.source_scope_id
			       AND c.source_scope_revision = os.source_scope_revision
			       AND c.scope_config_hash = wrs.scope_config_hash
			       AND c.access_mode = 'WORKSPACE_MANAGED'
			      WHERE os.organization_id = o.organization_id
			        AND os.source_object_id = o.id
			        AND os.membership_state = 'ACTIVE'
			        AND NOT EXISTS (
			            SELECT 1 FROM public.workspace_managed_grant_revocation gr
			            WHERE gr.organization_id = c.organization_id
			              AND gr.confirmation_id = c.confirmation_id
			        )
			        AND NOT EXISTS (
			            SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation ar
			            WHERE ar.organization_id = c.organization_id
			              AND ar.grant_id = c.confirmation_actor_grant_id
			        )
			  )
			  AND EXISTS (
			      SELECT 1
			      FROM public.source_version_retention vr
			      WHERE vr.organization_id = v.organization_id
			        AND vr.source_version_id = v.id
			        AND vr.state = 'ACTIVE'
			        AND vr.queryable
			  )
			ORDER BY o.id, v.id
			LIMIT $4 OFFSET $5`, access.OrganizationID, workspaceID, allVersions, fetch, offset)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var item ObjectInventoryItem
			if err := rows.Scan(
				&item.SourceObjectID, &item.ObjectType, &item.ConnectionID, &item.LifecycleState,
				&item.SourceVersionID, &item.ExternalVersionKey, &item.ContentHash, &item.ObservedAt, &item.VersionState,
				&item.FragmentCount, &item.FirstFragmentID, &item.FirstOrdinal, &item.LastOrdinal,
				&item.MirroredAt, &item.EmbeddingProfileID, &item.EmbeddingProfileHash,
				&item.hasExternalID, &item.externalIDDigest,
			); err != nil {
				return err
			}
			items = append(items, item)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		// The typed skip ledger (R3a-1 KV-A02) of the same workspace, resolved
		// in the same governed read. The additive migration may not yet be
		// applied to a database that predates it, so the relation is probed
		// first and the projection degrades to empty rather than failing every
		// inventory read during a rolling migration. One row per workspace-bound
		// scope revision and external id is projected, keeping the latest
		// observation so a re-run never duplicates an object. The current-state
		// owner projection excludes history superseded by a complete scan or by a
		// successful per-object resolution, including unchanged-version recovery
		// in a partial scan. Failed/in-progress runs cannot clear a skip.
		//
		// Fail-closed gate parity with the object rows above: a skip is visible
		// only while the workspace-bound scope revision resolves to an enabled,
		// current-revision WORKSPACE_MANAGED workspace_revision_source whose
		// live workspace_managed_grant_confirmation still matches the exact
		// scope tuple and scope_config_hash, and that confirmation is neither
		// itself revoked (workspace_managed_grant_revocation) nor backed by a
		// revoked confirmation actor grant
		// (workspace_source_confirmation_actor_grant_revocation). A revocation
		// or a stale tuple therefore empties the skipped set exactly as it
		// empties the readable object rows, and the content-free external id,
		// reason code and moment are withheld with it.
		//
		// The object rows additionally require a queryable
		// source_version_retention, which the object join can express because a
		// readable object always resolves a current source_version. A skipped
		// observation did not produce its own source_version (an older readable
		// version may remain), so the version-level retention gate is not
		// applicable to skips and is deliberately absent here; the scope-level
		// authority gate above is the whole gate for a skip.
		present, err := relationPresent(ctx, tx, "public.source_object_skip_resolution")
		if err != nil {
			return err
		}
		if present {
			skipRows, err := tx.Query(ctx, `
				SELECT ranked.external_id_digest, ranked.digest_key_version,
				       ranked.external_id_artifact_id, ranked.reason_code, ranked.observed_at,
				       ranked.source_scope_id, ranked.source_scope_revision, ranked.sync_run_id
				FROM (
					SELECT s.external_id_digest, s.digest_key_version, s.external_id_artifact_id,
					       s.reason_code, s.observed_at,
					       s.source_scope_id, s.source_scope_revision, s.sync_run_id,
					       row_number() OVER (
					           PARTITION BY s.source_scope_id, s.source_scope_revision, s.external_id_digest
					           ORDER BY s.observed_at DESC, s.sync_run_id DESC
					       ) AS rn
					FROM app.source_object_current_skips() s
					JOIN public.workspace w
					  ON w.organization_id = s.organization_id AND w.id = $2
					JOIN public.workspace_revision_source wrs
					  ON wrs.organization_id = w.organization_id
					 AND wrs.workspace_id = w.id
					 AND wrs.workspace_revision = w.current_revision
					 AND wrs.source_scope_id = s.source_scope_id
					 AND wrs.source_scope_revision = s.source_scope_revision
					 AND wrs.enabled
					 AND wrs.access_mode = 'WORKSPACE_MANAGED'
					JOIN public.workspace_managed_grant_confirmation c
					  ON c.organization_id = w.organization_id
					 AND c.workspace_id = w.id
					 AND c.workspace_source_id = wrs.workspace_source_id
					 AND c.source_scope_id = s.source_scope_id
					 AND c.source_scope_revision = s.source_scope_revision
					 AND c.scope_config_hash = wrs.scope_config_hash
					 AND c.access_mode = 'WORKSPACE_MANAGED'
					WHERE s.organization_id = $1
					  AND NOT EXISTS (
					      SELECT 1 FROM public.workspace_managed_grant_revocation gr
					      WHERE gr.organization_id = c.organization_id
					        AND gr.confirmation_id = c.confirmation_id
					  )
					  AND NOT EXISTS (
					      SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation ar
					      WHERE ar.organization_id = c.organization_id
					        AND ar.grant_id = c.confirmation_actor_grant_id
					  )
				) ranked
				WHERE ranked.rn = 1
				ORDER BY ranked.source_scope_id, ranked.source_scope_revision,
				         ranked.external_id_digest, ranked.reason_code`, access.OrganizationID, workspaceID)
			if err != nil {
				return err
			}
			ledger := []skipLedgerRow{}
			for skipRows.Next() {
				var row skipLedgerRow
				if err := skipRows.Scan(&row.digest, &row.keyVersion, &row.artifactID, &row.reasonCode, &row.observedAt,
					&row.scopeID, &row.scopeRevision, &row.syncRunID); err != nil {
					skipRows.Close()
					return err
				}
				ledger = append(ledger, row)
			}
			if err := skipRows.Err(); err != nil {
				skipRows.Close()
				return err
			}
			skipRows.Close()
			// The ledger row carries only the digest; the native identity is
			// decrypted from the sealed artifact and must match the digest the
			// row stores. A missing artifact or a tampered digest withholds the
			// skip (fail closed) rather than returning unverified content, so a
			// caller that must not see the identity gets nothing and the page
			// never leaks a partially verified row. Decryption is deliberately
			// after the cursor is drained: the artifact read is a second query on
			// the same transaction. The projection then dedupes the verified
			// native identities across digest key versions, so a digester key
			// rotation cannot surface the same skipped object twice.
			skips = append(skips, selectSkipIdentities(ledger, func(row skipLedgerRow) (string, bool) {
				return v.readSkipExternalID(ctx, tx, access, row.artifactID, row.digest)
			})...)
		}
		// Reveal source identities only on this returned page, after the content
		// readability gate, and only if an identity artifact exists. Legacy
		// objects without that artifact keep their prior inventory projection.
		pageCount := len(items)
		if int64(pageCount) > limit {
			pageCount = int(limit)
		}
		for index := 0; index < pageCount; index++ {
			// An object with no fragment has no readable content and therefore
			// no authorized external identity to disclose; it keeps the empty
			// identity rather than failing the page the way the content read
			// would.
			if items[index].FirstFragmentID == "" || !items[index].hasExternalID {
				continue
			}
			externalID, err := v.readObjectExternalID(ctx, tx, repo, access, items[index].SourceObjectID,
				items[index].ObjectType, items[index].ConnectionID, items[index].externalIDDigest)
			if err != nil {
				return err
			}
			items[index].ExternalID = externalID
		}
		return nil
	})
	if err != nil {
		return nil, nil, false, err
	}
	// Current is derived from the version state, not from a second read: at most
	// one version per object is CURRENT (source_version_one_current).
	for index := range items {
		items[index].Current = items[index].VersionState == "CURRENT"
		// R3a-1 KV-A04a: the mirror age is derived from the code source's
		// already-persisted last successful mirror/sync moment, so a code
		// source row exposes a non-negative age and a missing/future moment
		// is reported as zero rather than a negative age. Only a GIT_FILE row
		// ever resolved a moment, so a document row keeps zero/nil.
		if items[index].MirroredAt != nil {
			age := int64(time.Since(*items[index].MirroredAt).Seconds())
			if age < 0 {
				age = 0
			}
			items[index].MirrorAgeSeconds = age
		}
	}
	if int64(len(items)) > limit {
		return items[:limit], skips, true, nil
	}
	return items, skips, false, nil
}

// relationPresent reports whether a relation exists in the current schema, so
// an additive-migration projection can degrade to empty on a database that
// has not yet applied the migration instead of failing the whole read.
func relationPresent(ctx context.Context, tx database.Transaction, name string) (bool, error) {
	var present bool
	if err := tx.QueryRow(ctx, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&present); err != nil {
		return false, err
	}
	return present, nil
}

// SearchHit is one lexical match over an authorized workspace: the decrypted
// fragment (its canonical text, anchor and full provenance), the excerpt that
// placed the match and the numeric score used to order it. It carries the same
// Fragment projection the single-fragment read returns, so a hit's address is
// the address the read tool resolves.
type SearchHit struct {
	Fragment Fragment
	Excerpt  string
	Score    int64
}

// SearchPage is one explicit page of a workspace's lexical search hits. HasMore
// true means more matches remain after this page; NextOffset is the stable
// cursor the caller passes back as offset to fetch the next page, so a limit is
// never silent truncation.
type SearchPage struct {
	Hits       []SearchHit
	HasMore    bool
	NextOffset int64
}

// SearchFragments performs a deterministic lexical search over the authorized
// canonical document fragments of one workspace to a caller whose current
// membership is live. It is the additive read the workspace search MCP tool
// composes; it reuses the same admission-before-data ordering, audit journal
// and content-free ErrNotFound denial the fragment Read and the object
// inventory use. With allVersions false only each object's current version is
// searched; with true retained versions readable through the exact-version
// gate are also searched. Matches are ordered by score desc and then by
// immutable address, so paging over offset/limit does not repeat a stable hit.
// A fragment is only searched when it satisfies the same visibility gates the
// read path applies: the enabled binding is WORKSPACE_MANAGED, the live
// unrevoked grant confirmation covers the exact scope tuple and the
// source_version_retention is ACTIVE and queryable. A raw query with no lexical
// term is refused with the same content-free ErrNotFound. A recognized question
// envelope without a subject returns an empty page after live admission.
func (v *Viewer) SearchFragments(ctx context.Context, access database.AccessContext, workspaceID, query string, allVersions bool, offset, limit int64) (SearchPage, error) {
	if v == nil || v.db == nil || workspaceID == "" || offset < 0 || limit < 1 {
		return SearchPage{}, ErrNotFound
	}
	if len(viewerSearchTerms(query)) == 0 {
		return SearchPage{}, ErrNotFound
	}
	terms := viewerSearchTerms(LexicalSearchQuery(query))
	if err := v.AdmitSearch(ctx, access, workspaceID); err != nil {
		return SearchPage{}, err
	}
	// A recognized question envelope without a subject still passes the live
	// admission gate, but must not scan the corpus for its function words.
	if len(terms) == 0 {
		return SearchPage{}, nil
	}
	hits, err := v.searchFragments(ctx, access, workspaceID, terms, allVersions)
	if err != nil {
		_ = v.emitWorkspaceEvent(ctx, access, workspaceID, audit.OutcomeFailed, audit.ActionEvidenceReadFailed, auditSearchReadFailedCode)
		return SearchPage{}, ErrNotFound
	}
	return pageSearchHits(hits, offset, limit), nil
}

// AdmitSearch journals admission before any external index or corpus read.
// Indexed retrieval shares the same workspace authority as the legacy scan.
func (v *Viewer) AdmitSearch(ctx context.Context, access database.AccessContext, workspaceID string) error {
	if v == nil || v.db == nil || ctx == nil || access.Validate() != nil || workspaceID == "" {
		return ErrNotFound
	}
	authorize := v.authorizeWorkspaceFn
	if authorize == nil {
		authorize = v.authorizeWorkspace
	}
	authorized, err := authorize(ctx, access, workspaceID)
	if err != nil || !authorized {
		// A denied or unknown workspace appends the content-free denied
		// admission event (with its search class) and discloses no hit, so the
		// denial is journalled without becoming an existence oracle. The
		// append error is surfaced through the returned error instead of being
		// discarded; the caller still sees the unchanged content-free
		// ErrNotFound.
		if denyErr := v.emitSearchDenied(ctx, access, workspaceID); denyErr != nil {
			return fmt.Errorf("%w: %w", ErrNotFound, denyErr)
		}
		return ErrNotFound
	}
	// Admission first: nothing is read until the admission event is durable. A
	// failed admission is the same content-free refusal and leaves no page.
	if err := v.emitWorkspaceEvent(ctx, access, workspaceID, audit.OutcomeSuccess, audit.ActionEvidenceReadAdmitted, "", auditSearchRequestCode); err != nil {
		return ErrNotFound
	}
	return nil
}

func pageSearchHits(hits []SearchHit, offset, limit int64) SearchPage {
	sort.SliceStable(hits, func(i, j int) bool {
		if hits[i].Score != hits[j].Score {
			return hits[i].Score > hits[j].Score
		}
		a, b := hits[i].Fragment, hits[j].Fragment
		if a.SourceObjectID != b.SourceObjectID {
			return a.SourceObjectID < b.SourceObjectID
		}
		if a.SourceVersionID != b.SourceVersionID {
			return a.SourceVersionID < b.SourceVersionID
		}
		if a.Ordinal != b.Ordinal {
			return a.Ordinal < b.Ordinal
		}
		return a.FragmentID < b.FragmentID
	})
	start := offset
	if start > int64(len(hits)) {
		start = int64(len(hits))
	}
	end := start + limit
	if end > int64(len(hits)) {
		end = int64(len(hits))
	}
	page := SearchPage{Hits: append([]SearchHit(nil), hits[start:end]...)}
	if end < int64(len(hits)) {
		page.HasMore = true
		page.NextOffset = end
	}
	return page
}

// searchFragments is the governed fetch performed only after admission. It
// repeats the live-membership gate at the access point, selects candidate
// fragments with the same visibility gates app.evidence_fragment_readable
// applies, then decrypts each candidate's canonical text through the
// workspace-scoped, access-point-re-checked artifact repository and keeps the
// lexically matching ones. The candidate rows are drained before the per-row
// gated fetches run, so the read never issues a nested query on an open cursor.
func (v *Viewer) searchFragments(ctx context.Context, access database.AccessContext, workspaceID string, terms []string, allVersions bool) ([]SearchHit, error) {
	repo, err := repositoryForWorkspace(workspaceID)
	if err != nil {
		return nil, err
	}
	hits := []SearchHit{}
	err = v.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID); err != nil {
			return err
		}
		var authorized bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1
				FROM public.workspace w
				JOIN public.workspace_member wm
				  ON wm.organization_id = w.organization_id AND wm.workspace_id = w.id
				 AND wm.principal_id = app.current_principal_id()
				 AND wm.valid_to_revision IS NULL AND wm.removed_at IS NULL
				WHERE w.organization_id = $1 AND w.id = $2
			)`, access.OrganizationID, workspaceID).Scan(&authorized); err != nil {
			return err
		}
		if !authorized {
			return ErrNotFound
		}
		rows, err := tx.Query(ctx, `
			SELECT f.id, f.extraction_id, f.source_version_id, f.ordinal,
			       v.external_version_key, v.content_hash, v.observed_at,
			       v.source_object_id, o.connection_id, f.text_hash, f.anchor_hash
			FROM public.evidence_fragment f
			JOIN public.source_version v
			  ON v.organization_id = f.organization_id AND v.id = f.source_version_id
			JOIN public.source_object o
			  ON o.organization_id = v.organization_id AND o.id = v.source_object_id
			WHERE f.organization_id = $1
			  AND o.lifecycle_state = 'ACTIVE'
			  AND ($3 OR o.current_version_id = v.id)
			  AND EXISTS (
			      SELECT 1
			      FROM public.source_object_scope os
			      JOIN public.workspace w
			        ON w.organization_id = o.organization_id AND w.id = $2
			      JOIN public.workspace_revision_source wrs
			        ON wrs.organization_id = w.organization_id AND wrs.workspace_id = w.id
			       AND wrs.workspace_revision = w.current_revision
			       AND wrs.source_scope_id = os.source_scope_id
			       AND wrs.source_scope_revision = os.source_scope_revision
			       AND wrs.enabled
			       AND wrs.access_mode = 'WORKSPACE_MANAGED'
			      JOIN public.workspace_managed_grant_confirmation c
			        ON c.organization_id = w.organization_id AND c.workspace_id = w.id
			       AND c.workspace_source_id = wrs.workspace_source_id
			       AND c.source_scope_id = os.source_scope_id
			       AND c.source_scope_revision = os.source_scope_revision
			       AND c.scope_config_hash = wrs.scope_config_hash
			       AND c.access_mode = 'WORKSPACE_MANAGED'
			      WHERE os.organization_id = o.organization_id
			        AND os.source_object_id = o.id
			        AND os.membership_state = 'ACTIVE'
			        AND NOT EXISTS (
			            SELECT 1 FROM public.workspace_managed_grant_revocation gr
			            WHERE gr.organization_id = c.organization_id
			              AND gr.confirmation_id = c.confirmation_id
			        )
			        AND NOT EXISTS (
			            SELECT 1 FROM public.workspace_source_confirmation_actor_grant_revocation ar
			            WHERE ar.organization_id = c.organization_id
			              AND ar.grant_id = c.confirmation_actor_grant_id
			        )
			  )
			  AND EXISTS (
			      SELECT 1
			      FROM public.source_version_retention vr
			      WHERE vr.organization_id = v.organization_id
			        AND vr.source_version_id = v.id
			        AND vr.state = 'ACTIVE'
			        AND vr.queryable
			  )
			ORDER BY o.id, v.id, f.ordinal, f.id`, access.OrganizationID, workspaceID, allVersions)
		if err != nil {
			return err
		}
		candidates := make([]Fragment, 0, 64)
		for rows.Next() {
			var fragment Fragment
			if err := rows.Scan(
				&fragment.FragmentID, &fragment.ExtractionID, &fragment.SourceVersionID, &fragment.Ordinal,
				&fragment.ExternalVersionKey, &fragment.ContentHash, &fragment.ObservedAt,
				&fragment.SourceObjectID, &fragment.ConnectionID, &fragment.EvidenceTextHash,
				// Both equality projections travel with a search hit, not just
				// the text one. A hit that carries only half of them cannot be
				// compared against the same fragment as another channel saw it,
				// which is exactly what fusion has to do.
				&fragment.AnchorHash,
			); err != nil {
				rows.Close()
				return err
			}
			candidates = append(candidates, fragment)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		versionRepos := make(map[string]*repository.Repository)
		for _, candidate := range candidates {
			candidateRepo := repo
			if allVersions {
				candidateRepo = versionRepos[candidate.SourceVersionID]
				if candidateRepo == nil {
					candidateRepo, err = repositoryForWorkspaceVersion(workspaceID, candidate.SourceVersionID)
					if err != nil {
						return err
					}
					versionRepos[candidate.SourceVersionID] = candidateRepo
				}
				if err := setExactReadGUCs(ctx, tx, workspaceID, candidate.SourceVersionID); err != nil {
					return err
				}
			}
			textOwner, textEnvelope, err := candidateRepo.Fetch(ctx, tx, access, artifactcrypto.EvidenceNormalizedText, candidate.FragmentID)
			if err != nil {
				// Candidate selection is not disclosure authority. Current-only
				// searches retain the current gate; all_versions uses the exact
				// version gate, including live rights and both retention states.
				if errors.Is(err, ErrNotFound) {
					continue
				}
				return err
			}
			text, err := v.codec.Open(textOwner, textEnvelope)
			if err != nil {
				return err
			}
			score, excerpt, ok := viewerLexicalMatch(text, terms)
			if !ok {
				continue
			}
			if allVersions {
				// Return the same complete, freshly authorized provenance as an
				// exact read, rather than treating the candidate row as proof.
				fragment, _, err := v.readExactFragmentInTransaction(ctx, tx, candidateRepo, access,
					workspaceID, candidate.FragmentID, candidate.SourceVersionID)
				if errors.Is(err, ErrNotFound) {
					continue
				}
				if err != nil {
					return err
				}
				hits = append(hits, SearchHit{Fragment: fragment, Excerpt: excerpt, Score: score})
				continue
			}
			anchorOwner, anchorEnvelope, err := repo.Fetch(ctx, tx, access, artifactcrypto.EvidenceAnchor, candidate.FragmentID)
			if err != nil {
				if errors.Is(err, ErrNotFound) {
					continue
				}
				return err
			}
			anchor, err := v.codec.Open(anchorOwner, anchorEnvelope)
			if err != nil {
				return err
			}
			candidate.Text = text
			candidate.Anchor = anchor
			hits = append(hits, SearchHit{Fragment: candidate, Excerpt: excerpt, Score: score})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return hits, nil
}

// viewerSearchTerms lowers and tokenizes a query into the distinct lexical terms
// the match counts. Only Unicode letters, digits, underscore and hyphen are term
// characters; every other separator is dropped, and duplicate terms collapse so
// a repeated word cannot inflate a fragment's score.
func viewerSearchTerms(query string) []string {
	fields := strings.FieldsFunc(strings.ToLower(query), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-'
	})
	seen := make(map[string]struct{}, len(fields))
	terms := make([]string, 0, len(fields))
	for _, field := range fields {
		if field == "" {
			continue
		}
		if _, ok := seen[field]; ok {
			continue
		}
		seen[field] = struct{}{}
		terms = append(terms, field)
	}
	return terms
}

// viewerExcerptRunes bounds an excerpt to a fixed rune window around the first
// match, so a hit never returns the whole fragment by accident.
const viewerExcerptRunes = 240

// viewerLexicalMatch returns the term-frequency score and a bounded excerpt when
// at least one term occurs in the canonical text. The match is case-insensitive
// over the whole canonical text, and the excerpt is snapped to rune boundaries
// and marked with an ellipsis on a truncated side.
func viewerLexicalMatch(text []byte, terms []string) (int64, string, bool) {
	if len(text) == 0 {
		return 0, "", false
	}
	lower := strings.ToLower(string(text))
	var score int64
	firstMatch := -1
	for _, term := range terms {
		count := strings.Count(lower, term)
		if count == 0 {
			continue
		}
		score += int64(count)
		if index := strings.Index(lower, term); index >= 0 && (firstMatch < 0 || index < firstMatch) {
			firstMatch = index
		}
	}
	if score == 0 {
		return 0, "", false
	}
	return score, viewerExcerpt(string(text), lower, firstMatch), true
}

// viewerExcerpt slices a rune window around a case-insensitive match. It maps
// the match's byte index in the lowered copy back to a rune index so the excerpt
// is taken from the original casing.
func viewerExcerpt(text, lower string, matchIndex int) string {
	if matchIndex < 0 {
		matchIndex = 0
	}
	if matchIndex > len(lower) {
		matchIndex = len(lower)
	}
	runes := []rune(text)
	runeIndex := utf8.RuneCountInString(lower[:matchIndex])
	start := runeIndex - viewerExcerptRunes/3
	if start < 0 {
		start = 0
	}
	end := start + viewerExcerptRunes
	if end > len(runes) {
		end = len(runes)
		start = end - viewerExcerptRunes
		if start < 0 {
			start = 0
		}
	}
	excerpt := string(runes[start:end])
	if start > 0 {
		excerpt = "…" + excerpt
	}
	if end < len(runes) {
		excerpt += "…"
	}
	return excerpt
}

// Search audit classes carry no query, fragment, tenant or infrastructure cause.
// The request reason distinguishes successful search admission from inventory;
// denial and read failure retain their existing error codes.
const (
	auditSearchRequestCode    = "WORKSPACE_SEARCH_REQUEST"
	auditSearchDeniedCode     = "WORKSPACE_SEARCH_DENIED"
	auditSearchReadFailedCode = "WORKSPACE_SEARCH_READ_FAILED"
)

// emitSearchDenied appends the content-free denied admission event for a search
// request the caller may not serve. Like the inventory denial it records a NULL
// workspace, so a denial must never fail the audit_event workspace foreign key
// and must never let a reader of the journal distinguish an unknown workspace
// from a forbidden one. The append error is returned so a denial whose journal
// record could not land is not silently discarded.
func (v *Viewer) emitSearchDenied(ctx context.Context, access database.AccessContext, workspaceID string) error {
	if v == nil || v.audit == nil {
		return errors.New("evidence: search audit requires the audit journal")
	}
	eventID, err := v.eventID()
	if err != nil {
		return err
	}
	principal := access.PrincipalID
	errorCode := auditSearchDeniedCode
	input := audit.EventInput{
		EventID:          eventID,
		WorkspaceID:      nil,
		ActorType:        audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID: &principal,
		Action:           audit.ActionEvidenceReadAdmitted,
		ResourceType:     audit.ResourceCitation,
		ResourceID:       workspaceID,
		RequestID:        access.RequestID,
		Outcome:          audit.OutcomeDenied,
		ErrorCode:        &errorCode,
		OccurredAt:       time.Now().UTC(),
	}
	_, err = v.audit.Append(ctx, access, input)
	return err
}

// auditInventoryDeniedCode and auditInventoryReadFailedCode are the closed,
// content-free error codes carried by an inventory denial and an inventory read
// failure; each names no object, tenant or infrastructure cause.
const (
	auditInventoryDeniedCode     = "WORKSPACE_OBJECTS_DENIED"
	auditInventoryReadFailedCode = "WORKSPACE_OBJECTS_READ_FAILED"
)

// emitWorkspaceEvent appends one content-free workspace admission/outcome event
// through the same audit journal the fragment Read uses. It names the workspace
// as its resource and carries no object, version or source content. An empty
// errorCode means a successful admission; a denial or failure supplies the
// closed class. It backs both the object inventory and the lexical search
// surface, so neither can drift from the other's admitting-before-data shape.
func (v *Viewer) emitWorkspaceEvent(ctx context.Context, access database.AccessContext, workspaceID string, outcome audit.Outcome, action audit.Action, errorCode string, reasonCodes ...string) error {
	if v == nil || v.audit == nil {
		return errors.New("evidence: inventory audit requires the audit journal")
	}
	eventID, err := v.eventID()
	if err != nil {
		return err
	}
	principal := access.PrincipalID
	input := audit.EventInput{
		EventID:          eventID,
		WorkspaceID:      &workspaceID,
		ActorType:        audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID: &principal,
		Action:           action,
		ResourceType:     audit.ResourceCitation,
		ResourceID:       workspaceID,
		RequestID:        access.RequestID,
		Outcome:          outcome,
		OccurredAt:       time.Now().UTC(),
		Metadata:         audit.Metadata{ReasonCodes: append([]string(nil), reasonCodes...)},
	}
	if errorCode != "" {
		input.ErrorCode = &errorCode
	}
	_, err = v.audit.Append(ctx, access, input)
	return err
}

// emitInventoryDenied appends the content-free denied admission event for an
// inventory request the caller may not serve. It deliberately records a NULL
// workspace, exactly like the hidden-/unknown-workspace audit convention: a
// denial must never fail the audit_event workspace foreign key, and it must
// never let a reader of the journal distinguish an unknown workspace from a
// forbidden one. The append error is returned to the caller so a denial whose
// journal record could not land is not silently discarded.
func (v *Viewer) emitInventoryDenied(ctx context.Context, access database.AccessContext, workspaceID string) error {
	if v == nil || v.audit == nil {
		return errors.New("evidence: inventory audit requires the audit journal")
	}
	eventID, err := v.eventID()
	if err != nil {
		return err
	}
	principal := access.PrincipalID
	errorCode := auditInventoryDeniedCode
	input := audit.EventInput{
		EventID:          eventID,
		WorkspaceID:      nil,
		ActorType:        audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID: &principal,
		Action:           audit.ActionEvidenceReadAdmitted,
		ResourceType:     audit.ResourceCitation,
		ResourceID:       workspaceID,
		RequestID:        access.RequestID,
		Outcome:          audit.OutcomeDenied,
		ErrorCode:        &errorCode,
		OccurredAt:       time.Now().UTC(),
	}
	_, err = v.audit.Append(ctx, access, input)
	return err
}

// authorizeAuthorized resolves the content-free access decision for one
// workspace and fragment without fetching any fragment content. A denied or
// unreadable fragment is reported as false and appends nothing, preserving the
// no-oracle denial.
func (v *Viewer) authorizeAuthorized(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) (bool, error) {
	if v == nil || v.db == nil {
		return false, ErrNotFound
	}
	authorized := false
	err := v.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID); err != nil {
			return err
		}
		var readable bool
		if err := tx.QueryRow(ctx, `SELECT app.evidence_fragment_readable($1, $2)`, fragmentID, workspaceID).Scan(&readable); err != nil {
			return err
		}
		authorized = readable
		return nil
	})
	if err != nil {
		return false, err
	}
	return authorized, nil
}

// readAuthorized is the governed fetch performed only after admission. It
// repeats the authorization check at the access point, so a revocation
// committed after the decision still closes the read and returns no fragment.
func (v *Viewer) readAuthorized(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) (Fragment, error) {
	var result Fragment
	repo, err := repositoryForWorkspace(workspaceID)
	if err != nil {
		return Fragment{}, ErrNotFound
	}
	err = v.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		// The SQL read functions repeat the same authorization check at the
		// access point.  This transaction-local setting carries the request's
		// workspace without widening the generic database access context.
		if _, err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID); err != nil {
			return err
		}
		var readable bool
		if err := tx.QueryRow(ctx, `SELECT app.evidence_fragment_readable($1, $2)`, fragmentID, workspaceID).Scan(&readable); err != nil {
			return err
		}
		if !readable {
			return ErrNotFound
		}
		textOwner, textEnvelope, err := repo.Fetch(ctx, tx, access, artifactcrypto.EvidenceNormalizedText, fragmentID)
		if err != nil {
			return err
		}
		text, err := v.codec.Open(textOwner, textEnvelope)
		if err != nil {
			return err
		}
		anchorOwner, anchorEnvelope, err := repo.Fetch(ctx, tx, access, artifactcrypto.EvidenceAnchor, fragmentID)
		if err != nil {
			return err
		}
		anchor, err := v.codec.Open(anchorOwner, anchorEnvelope)
		if err != nil {
			return err
		}
		var provenance fragmentProvenance
		if err := tx.QueryRow(ctx, `
			SELECT f.extraction_id, f.source_version_id, f.ordinal,
			       v.external_version_key, v.content_hash, v.observed_at,
			       v.source_object_id, o.connection_id, o.object_type,
			       extraction.canonical_format, extraction.parser_profile_revision,
			       f.text_hash, f.anchor_hash, o.external_object_id_artifact_id IS NOT NULL,
			       o.external_object_id_digest, COALESCE(o.current_version_id = v.id, false)
			FROM public.evidence_fragment f
			JOIN public.source_version v
			  ON v.organization_id = f.organization_id AND v.id = f.source_version_id
			JOIN public.source_object o
			  ON o.organization_id = v.organization_id AND o.id = v.source_object_id
			JOIN public.source_extraction extraction
			  ON extraction.organization_id = f.organization_id AND extraction.id = f.extraction_id
			WHERE f.organization_id = $1 AND f.id = $2
		`, access.OrganizationID, fragmentID).Scan(
			&provenance.ExtractionID, &provenance.SourceVersionID, &provenance.Ordinal,
			&provenance.ExternalVersionKey, &provenance.ContentHash, &provenance.ObservedAt,
			&provenance.SourceObjectID, &provenance.ConnectionID, &provenance.ObjectType,
			&provenance.CanonicalFormat, &provenance.ParserProfileRevision,
			&provenance.EvidenceTextHash, &provenance.AnchorHash, &provenance.HasExternalID,
			&provenance.ExternalIDDigest, &provenance.IsCurrentVersion,
		); err != nil {
			// The readability gate above already passed, so a missing or
			// drifting row is treated as a denial, not a distinguishable error.
			return ErrNotFound
		}
		var sourcePath string
		if provenance.HasExternalID {
			sourcePath, err = v.readObjectExternalID(ctx, tx, repo, access, provenance.SourceObjectID,
				provenance.ObjectType, provenance.ConnectionID, provenance.ExternalIDDigest)
			if err != nil {
				return err
			}
		}
		result = Fragment{
			FragmentID: fragmentID, Text: text, Anchor: anchor, SourcePath: sourcePath,
			IsCurrentVersion: provenance.IsCurrentVersion,
			ExtractionID:     provenance.ExtractionID, SourceVersionID: provenance.SourceVersionID,
			Ordinal: provenance.Ordinal, ExternalVersionKey: provenance.ExternalVersionKey,
			ContentHash: provenance.ContentHash, ObservedAt: provenance.ObservedAt,
			SourceObjectID: provenance.SourceObjectID, ConnectionID: provenance.ConnectionID,
			ObjectType: provenance.ObjectType, CanonicalFormat: provenance.CanonicalFormat,
			ParserProfileRevision: provenance.ParserProfileRevision,
			EvidenceTextHash:      provenance.EvidenceTextHash, AnchorHash: provenance.AnchorHash,
		}
		return nil
	})
	if err != nil {
		// Every failure mode — denied, missing, cross-tenant, infra — collapses
		// into the one indistinguishable not-found (ADR-0073 §1.2).
		return Fragment{}, ErrNotFound
	}
	return result, nil
}

// readAuthorizedObject is the whole-object assembly performed only after
// admission. It resolves the addressed anchor fragment exactly as readAuthorized
// does and re-checks app.evidence_fragment_readable at the access point, then
// opens every fragment of the anchor's active extraction in ascending ordinal
// order through the same workspace-scoped repository (which repeats the
// readability gate for each fragment). Every failure mode — denied, missing,
// cross-tenant, a fragment that became unreadable mid-assembly or infrastructure
// — collapses into ErrNotFound with no partial text.
func (v *Viewer) readAuthorizedObject(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) (WholeObject, error) {
	repo, err := repositoryForWorkspace(workspaceID)
	if err != nil {
		return WholeObject{}, ErrNotFound
	}
	var result WholeObject
	err = v.db.Read(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.workspace_id', $1, true)`, workspaceID); err != nil {
			return err
		}
		var readable bool
		if err := tx.QueryRow(ctx, `SELECT app.evidence_fragment_readable($1, $2)`, fragmentID, workspaceID).Scan(&readable); err != nil {
			return err
		}
		if !readable {
			return ErrNotFound
		}
		var provenance fragmentProvenance
		if err := tx.QueryRow(ctx, `
			SELECT f.extraction_id, f.source_version_id, f.ordinal,
			       v.external_version_key, v.content_hash, v.observed_at,
			       v.source_object_id, o.connection_id, o.object_type,
			       extraction.canonical_format, extraction.parser_profile_revision,
			       f.text_hash, f.anchor_hash, o.external_object_id_artifact_id IS NOT NULL,
			       o.external_object_id_digest, COALESCE(o.current_version_id = v.id, false)
			FROM public.evidence_fragment f
			JOIN public.source_version v
			  ON v.organization_id = f.organization_id AND v.id = f.source_version_id
			JOIN public.source_object o
			  ON o.organization_id = v.organization_id AND o.id = v.source_object_id
			JOIN public.source_extraction extraction
			  ON extraction.organization_id = f.organization_id AND extraction.id = f.extraction_id
			WHERE f.organization_id = $1 AND f.id = $2
		`, access.OrganizationID, fragmentID).Scan(
			&provenance.ExtractionID, &provenance.SourceVersionID, &provenance.Ordinal,
			&provenance.ExternalVersionKey, &provenance.ContentHash, &provenance.ObservedAt,
			&provenance.SourceObjectID, &provenance.ConnectionID, &provenance.ObjectType,
			&provenance.CanonicalFormat, &provenance.ParserProfileRevision,
			&provenance.EvidenceTextHash, &provenance.AnchorHash, &provenance.HasExternalID,
			&provenance.ExternalIDDigest, &provenance.IsCurrentVersion,
		); err != nil {
			return ErrNotFound
		}
		textOwner, textEnvelope, err := repo.Fetch(ctx, tx, access, artifactcrypto.EvidenceNormalizedText, fragmentID)
		if err != nil {
			return err
		}
		text, err := v.codec.Open(textOwner, textEnvelope)
		if err != nil {
			return err
		}
		anchorOwner, anchorEnvelope, err := repo.Fetch(ctx, tx, access, artifactcrypto.EvidenceAnchor, fragmentID)
		if err != nil {
			return err
		}
		anchor, err := v.codec.Open(anchorOwner, anchorEnvelope)
		if err != nil {
			return err
		}
		var sourcePath string
		if provenance.HasExternalID {
			sourcePath, err = v.readObjectExternalID(ctx, tx, repo, access, provenance.SourceObjectID,
				provenance.ObjectType, provenance.ConnectionID, provenance.ExternalIDDigest)
			if err != nil {
				return err
			}
		}
		result.Fragment = Fragment{
			FragmentID: fragmentID, Text: text, Anchor: anchor, SourcePath: sourcePath,
			IsCurrentVersion: provenance.IsCurrentVersion,
			ExtractionID:     provenance.ExtractionID, SourceVersionID: provenance.SourceVersionID,
			Ordinal: provenance.Ordinal, ExternalVersionKey: provenance.ExternalVersionKey,
			ContentHash: provenance.ContentHash, ObservedAt: provenance.ObservedAt,
			SourceObjectID: provenance.SourceObjectID, ConnectionID: provenance.ConnectionID,
			ObjectType: provenance.ObjectType, CanonicalFormat: provenance.CanonicalFormat,
			ParserProfileRevision: provenance.ParserProfileRevision,
			EvidenceTextHash:      provenance.EvidenceTextHash, AnchorHash: provenance.AnchorHash,
		}
		// The ordinal sequence of one active extraction is gap-free
		// (UNIQUE(organization_id, extraction_id, ordinal)); the join through
		// source_version_active_extraction restricts the assembly to exactly the
		// extraction readAuthorized already gated. Candidate rows are drained
		// before the per-row gated fetches run, so no nested query is issued on
		// an open cursor.
		rows, err := tx.Query(ctx, `
			SELECT f.id, f.ordinal
			FROM public.evidence_fragment f
			JOIN public.source_version_active_extraction ae
			  ON ae.organization_id = f.organization_id
			 AND ae.source_version_id = f.source_version_id
			 AND ae.extraction_id = f.extraction_id
			WHERE f.organization_id = $1 AND f.source_version_id = $2 AND f.extraction_id = $3
			ORDER BY f.ordinal, f.id`, access.OrganizationID, provenance.SourceVersionID, provenance.ExtractionID)
		if err != nil {
			return err
		}
		ordered := make([]orderedObjectFragment, 0, 64)
		for rows.Next() {
			var item orderedObjectFragment
			if err := rows.Scan(&item.id, &item.ordinal); err != nil {
				rows.Close()
				return err
			}
			ordered = append(ordered, item)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		return v.readWholeFragmentsInTransaction(ctx, tx, repo, access, workspaceID, "", &result, ordered)
	})
	if err != nil {
		return WholeObject{}, ErrNotFound
	}
	return result, nil
}

// emitOpened appends one citation.opened event for an authorized evidence read.
// It names the authenticated principal and the allowlisted provenance the read
// already resolved — the fragment id (as the referenced evidence id), the
// source_version_id and connection_id it belongs to — and never any content.
// Denied reads never reach this method.
func (v *Viewer) emitOpened(ctx context.Context, access database.AccessContext, workspaceID string, fragment Fragment) error {
	if v == nil || v.audit == nil || fragment.FragmentID == "" {
		return nil
	}
	eventID, err := v.eventID()
	if err != nil {
		return err
	}
	principal := access.PrincipalID
	sourceVersionID := fragment.SourceVersionID
	connectionID := fragment.ConnectionID
	input := audit.EventInput{
		EventID:               eventID,
		WorkspaceID:           &workspaceID,
		ActorType:             audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID:      &principal,
		Action:                audit.ActionCitationOpened,
		ResourceType:          audit.ResourceCitation,
		ResourceID:            sourceVersionID,
		RequestID:             access.RequestID,
		Outcome:               audit.OutcomeSuccess,
		ReferencedEvidenceIDs: []string{fragment.FragmentID},
		Metadata: audit.Metadata{
			SourceConnectionID: &connectionID,
		},
		OccurredAt: time.Now().UTC(),
	}
	_, err = v.audit.Append(ctx, access, input)
	return err
}

// emitAdmission appends the admission event that must be durable before any
// authorized evidence fragment is fetched. It records the actor kind
// (HUMAN | SERVICE) and the access decision (OutcomeSuccess = admitted) and
// carries no fragment content. A failure is returned so Read can fail closed
// with the content-free refusal and never fetch or disclose a fragment.
func (v *Viewer) emitAdmission(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) error {
	if v == nil || v.audit == nil {
		return errors.New("evidence: admission requires the audit journal")
	}
	eventID, err := v.eventID()
	if err != nil {
		return err
	}
	principal := access.PrincipalID
	input := audit.EventInput{
		EventID:          eventID,
		WorkspaceID:      &workspaceID,
		ActorType:        audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID: &principal,
		Action:           audit.ActionEvidenceReadAdmitted,
		ResourceType:     audit.ResourceCitation,
		ResourceID:       fragmentID,
		RequestID:        access.RequestID,
		Outcome:          audit.OutcomeSuccess,
		OccurredAt:       time.Now().UTC(),
	}
	_, err = v.audit.Append(ctx, access, input)
	return err
}

// auditEvidenceReadFailedCode is the closed, content-free error code carried by
// a read failure outcome; it names no fragment, tenant or infrastructure cause.
const auditEvidenceReadFailedCode = "EVIDENCE_READ_FAILED"

// emitReadFailed appends the failure outcome that matches an admission event
// when the governed read (or its success outcome) fails after admission. It
// keeps the journal from ever holding an admission with no outcome.
func (v *Viewer) emitReadFailed(ctx context.Context, access database.AccessContext, workspaceID, fragmentID string) error {
	if v == nil || v.audit == nil {
		return errors.New("evidence: read failure outcome requires the audit journal")
	}
	eventID, err := v.eventID()
	if err != nil {
		return err
	}
	principal := access.PrincipalID
	errorCode := auditEvidenceReadFailedCode
	input := audit.EventInput{
		EventID:          eventID,
		WorkspaceID:      &workspaceID,
		ActorType:        audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID: &principal,
		Action:           audit.ActionEvidenceReadFailed,
		ResourceType:     audit.ResourceCitation,
		ResourceID:       fragmentID,
		RequestID:        access.RequestID,
		Outcome:          audit.OutcomeFailed,
		ErrorCode:        &errorCode,
		OccurredAt:       time.Now().UTC(),
	}
	_, err = v.audit.Append(ctx, access, input)
	return err
}

// auditObjectDeniedCode is the closed, content-free error class carried by a
// whole-object read denial; it names no fragment, workspace or infrastructure
// cause and is the same shape as the inventory and search denial classes.
const auditObjectDeniedCode = "WORKSPACE_OBJECT_DENIED"

// emitObjectDenied appends the content-free denied admission event for a
// whole-object read the caller may not serve. Like the inventory and search
// denials it records a NULL workspace, so the denial must never fail the
// audit_event workspace foreign key and must never let a reader of the journal
// distinguish an unknown workspace from a forbidden one. The append error is
// returned so a denial whose journal record could not land is not silently
// discarded.
func (v *Viewer) emitObjectDenied(ctx context.Context, access database.AccessContext, workspaceID string) error {
	if v == nil || v.audit == nil {
		return errors.New("evidence: object read denial requires the audit journal")
	}
	eventID, err := v.eventID()
	if err != nil {
		return err
	}
	principal := access.PrincipalID
	errorCode := auditObjectDeniedCode
	input := audit.EventInput{
		EventID:          eventID,
		WorkspaceID:      nil,
		ActorType:        audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID: &principal,
		Action:           audit.ActionEvidenceReadAdmitted,
		ResourceType:     audit.ResourceCitation,
		ResourceID:       workspaceID,
		RequestID:        access.RequestID,
		Outcome:          audit.OutcomeDenied,
		ErrorCode:        &errorCode,
		OccurredAt:       time.Now().UTC(),
	}
	_, err = v.audit.Append(ctx, access, input)
	return err
}

// eventID produces a unique, printable journal event identifier.
func (v *Viewer) eventID() (string, error) {
	var random [12]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("evidence: audit event id: %w", err)
	}
	return "aud_" + hex.EncodeToString(random[:]), nil
}
