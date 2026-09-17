package ingestion

import (
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"path"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/connector/folder"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/sandboxdispatch"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/docparser"
	"knowvault.local/verified-workspace/internal/source/eml"
	"knowvault.local/verified-workspace/internal/source/format"
	sourcehtml "knowvault.local/verified-workspace/internal/source/html"
	"knowvault.local/verified-workspace/internal/source/observation"
	"knowvault.local/verified-workspace/internal/source/ocrparser"
	"knowvault.local/verified-workspace/internal/source/pathcanon"
	"knowvault.local/verified-workspace/internal/source/pdfparser"
	"knowvault.local/verified-workspace/internal/source/pdfrenderparser"
)

const (
	extractorName = "knowvault-text-line-parser"
	// Historical retrieval projection changes did not bump this executable
	// identity. TEXT layout fidelity now has its own parser-profile revision.
	// Migration 000105 lets a retained question context reference the extraction
	// it observed without pinning the mutable active-extraction pointer.
	extractorVersion = "1.0"
	maxFragmentBytes = 4096
	// defaultParserRevision is the handler's unset value; a differing
	// h.parserRevision signals the WithParserRevision test override.
	defaultParserRevision = "text-v1"
)

// extractorArtifactHash pins the parser identity into the immutable extraction
// profile hash.
var extractorArtifactHash = canon.Hash([]byte(extractorName + "@" + extractorVersion))

// expectedMediaFamily is the one coarse family a format's owner is allowed to parse.
// It exists so the media/parser relation is checked in both directions rather than
// only rejecting non-text, and so adding a format cannot silently widen what bytes
// reach a parser.
func expectedMediaFamily(formatRevision string) folder.MediaFamily {
	if _, isOffice := format.OfficeRevision(formatRevision); isOffice {
		return folder.MediaFamilyOOXML
	}
	if _, isPDF := format.PDFRevision(formatRevision); isPDF {
		return folder.MediaFamilyPDF
	}
	switch formatRevision {
	case format.RevisionPNG:
		return folder.MediaFamilyPNG
	case format.RevisionJPEG:
		return folder.MediaFamilyJPEG
	}
	return folder.MediaFamilyText
}

// errMissingObserverIdentity is the internal failure raised when a worker-backed
// format reaches profile construction without the identity of the sandbox that
// observed it. It is a runtime failure rather than a quarantine because it can only
// mean the pipeline itself is wrong, not that the document is.
var errMissingObserverIdentity = errors.New("ingestion: worker-backed extraction lost its observer identity")

// observerRequired reports whether a format's canonical text is produced by an
// isolated parser sandbox and therefore must carry that sandbox into the immutable
// extraction identity. Formats parsed in process have no observer.
func observerRequired(formatRevision string) bool {
	_, isOffice := format.OfficeRevision(formatRevision)
	_, isPDF := format.PDFRevision(formatRevision)
	_, isOCR := format.OCRRevision(formatRevision)
	return isOffice || isPDF || isOCR
}

type ingestResult struct {
	// quarantineReason is the closed, content-free reason code of a per-object
	// extraction-phase quarantine. It is empty only when the object was ingested
	// (or a run-level failure was returned instead); every quarantine site below
	// sets a non-empty code, so no per-object skip is ever recorded with an empty
	// reason (R3a-1 KV-A02). The handler normalizes the carried code through the
	// closed ledger set before it reaches public.source_object_skip.reason_code.
	quarantineReason string
	versionCreated   bool
	evidence         int
}

// Extraction-phase quarantine reason codes the pipeline itself determines.
// Every one is an existing member of the closed KV-A02 ledger set
// (db/migrations/000095_stage3_source_object_skip.sql), so carrying them needs
// no new migration and cannot drift from the database CHECK. The media-family
// mismatch and parser-refusal sites keep sourceObjectSkipReasonExtraction: that
// is the contract the protected typed-skip suite records for a rejected
// document, and those two causes are the generic "extraction skipped" case.
const (
	quarantineReasonPathRejected      = "FOLDER_CONTAINMENT_VIOLATION"
	quarantineReasonFormatNotAdmitted = "FOLDER_UNSUPPORTED_TYPE"
	// A format-determination failure after the object's bytes were read carries
	// the code of the object's own source kind (KV-A02, r6 finding): a git
	// object and a mail attachment own the source-specific closed code their
	// connector defines, never the folder-specific one. Both codes are existing
	// members of sourceObjectSkipReasonCodes and the migration CHECK.
	quarantineReasonGitFormatNotAdmitted  = "GIT_UNSUPPORTED_MEDIA_TYPE"
	quarantineReasonMailFormatNotAdmitted = "MAIL_ATTACHMENT_UNSUPPORTED_MEDIA_TYPE"
)

// formatNotAdmittedReason selects the skip reason for a failed format
// determination from the observed object's source kind. Folder (and neutral
// document) objects keep the folder code; a git object and a mail attachment
// report their source-specific code, so the ledger row and the inventory
// projection never collapse a non-folder cause into FOLDER_UNSUPPORTED_TYPE.
func formatNotAdmittedReason(objectType string) string {
	switch objectType {
	case "GIT_FILE":
		return quarantineReasonGitFormatNotAdmitted
	case "EMAIL_ATTACHMENT":
		return quarantineReasonMailFormatNotAdmitted
	default:
		return quarantineReasonFormatNotAdmitted
	}
}

// searchChunkPlan is the in-transaction lexical projection of one Evidence
// unit. The plaintext remains transient in the same bounded extraction call;
// publishSearchChunks seals it immediately under the SearchChunkText owner
// branch and never places it in an outbox payload.
type searchChunkPlan struct {
	text       []byte
	fragmentID string
	ordinal    int64
	// fragmentIDs binds one retrieval unit to several Evidence fragments, in
	// order. A document chunk is one fragment (fragmentIDs stays empty); a
	// row of a structured projection is one card over all of that row's
	// cells, so retrieval sees the whole row while every citation is still
	// the exact cell it came from.
	fragmentIDs []string
}

// fragments returns the ordered Evidence fragments this chunk binds.
func (plan searchChunkPlan) fragments() []string {
	if len(plan.fragmentIDs) > 0 {
		return plan.fragmentIDs
	}
	if plan.fragmentID == "" {
		return nil
	}
	return []string{plan.fragmentID}
}

func catalogObjectType(observed *observation.Object) string {
	if observed == nil || observed.Kind == observation.KindDocument || observed.ObjectType == "DOCUMENT" {
		return "FILE"
	}
	return observed.ObjectType
}

func observationTitle(externalID, objectType string) string {
	if objectType == "EMAIL" {
		return "email:" + externalID
	}
	if objectType == "EMAIL_ATTACHMENT" {
		return "attachment:" + externalID
	}
	return path.Base(externalID)
}

func graphEntityType(objectType string) string {
	switch objectType {
	case "EMAIL", "EMAIL_ATTACHMENT":
		return "EMAIL"
	case "GIT_FILE":
		return "DOCUMENT"
	case "SQL_BUSINESS_OBJECT", "POSTGRESQL_QUERY_ROW":
		return "SQL_BUSINESS_OBJECT"
	default:
		return "DOCUMENT"
	}
}

// ingestObject reads one object's stable snapshot and, in a single fenced
// transaction, upserts its identity, version and (when new) its Extraction and
// Evidence, then atomically publishes the active set. Re-running with an
// unchanged object is a no-op; a changed object yields a new immutable version.
func (h *Handler) ingestObject(ctx context.Context, access database.AccessContext,
	claimed jobs.ClaimedJob, resolved resolvedScope, syncRunID, relativePath string, observed *observation.Object) (ingestResult, error) {
	var read folder.ReadResult
	objectType := "FILE"
	versionKey := ""
	if observed != nil {
		if observed.ExternalID != relativePath || observed.Document == nil || observed.PayloadKind != observation.PayloadBytes ||
			observed.Kind != resolved.sourceKind || observed.ContentHash == "" || observed.VersionKey == "" {
			return ingestResult{}, failure("INGEST_OBSERVATION_INVALID", nil)
		}
		objectType = catalogObjectType(observed)
		versionKey = observed.VersionKey
		read = folder.ReadResult{
			RelativePath: relativePath, MediaFamily: folder.MediaFamily(observed.Document.MediaFamily),
			MediaType: observed.Document.MediaType, SizeBytes: int64(len(observed.Document.Bytes)),
			ContentSHA256: observed.ContentHash, NativeVersionToken: observed.VersionKey,
			Content: observed.Document.Bytes,
		}
	} else {
		readResult, quarantine, err := h.connector.Read(ctx, resolved.scope, relativePath)
		if err != nil {
			return ingestResult{}, failure("INGEST_READ", err)
		}
		if quarantine != nil {
			// Preserve the connector's typed, content-free code verbatim instead
			// of collapsing the read-path quarantine into the generic extraction
			// code (KV-A02). The reason is never empty, and the handler still
			// normalizes an out-of-set code through the closed ledger set.
			reason := string(quarantine.Code)
			if reason == "" {
				reason = sourceObjectSkipReasonUnknown
			}
			return ingestResult{quarantineReason: reason}, nil
		}
		read = readResult
		versionKey = read.NativeVersionToken
	}
	if versionKey == "" {
		return ingestResult{}, failure("INGEST_VERSION_KEY", nil)
	}
	// Folder paths are still re-validated through the normative pathcanon
	// implementation. Remote sources use their connector-owned opaque identity;
	// treating an IMAP UID or Git path as a filesystem path would either reject
	// valid objects or create a second, divergent identity scheme.
	if resolved.sourceKind == observation.KindDocument {
		if _, err := pathcanon.Path(relativePath, resolved.pathCase); err != nil {
			return ingestResult{quarantineReason: quarantineReasonPathRejected}, nil
		}
	}
	var externalIDBytes, locatorBytes []byte
	var err error
	if observed != nil && observed.Kind != observation.KindDocument {
		externalIDBytes, err = canon.ObservationExternalIDBytes(resolved.connectionID, string(observed.Kind), observed.ExternalID)
		if err == nil {
			locatorBytes, err = canon.ObservationLocatorBytes(resolved.connectionID, string(observed.Kind), observed.ExternalID, observed.ParentExternalID, observed.PartPath)
		}
	} else {
		externalIDBytes, err = canon.FileLocatorBytes(resolved.connectionID, relativePath)
		if err == nil {
			locatorBytes, err = canon.FileLocatorBytes(resolved.connectionID, relativePath)
		}
	}
	if err != nil {
		return ingestResult{}, failure("INGEST_LOCATOR", err)
	}
	externalIDDigest := canon.HMACDigest(h.digester.Key, h.digester.KeyVersion, externalIDBytes)
	locatorDigest := canon.HMACDigest(h.digester.Key, h.digester.KeyVersion, locatorBytes)
	title := observationTitle(relativePath, objectType)

	// The object's format is resolved from its extension and admitted only if the
	// scope allows it (PARSER_CONTRACTS.md §2, SOURCE_CONTRACTS.md). Each format is
	// then proven structurally: the byte-level TEXT-anchor formats parse their
	// canonical bytes; EML is parsed into its exact MIME tree by internal/source/eml;
	// HTML is parsed into normalized visible text by internal/source/html (still a
	// TEXT line-range anchor). An unknown extension, a disallowed format, or bytes
	// that do not match the format quarantines with no fallback.
	_, formatRevision, ok := format.DetermineObservation(objectType, relativePath, read.MediaType, resolved.formats)
	if !ok {
		return ingestResult{quarantineReason: formatNotAdmittedReason(objectType)}, nil
	}
	// Cross-format isolation, both directions (ADR-0062 §2g): the coarse media family
	// the connector detected from the bytes must be the family this format's owner
	// parses. A .docx whose bytes are not an OOXML package, and a .txt whose bytes are
	// one, both quarantine — the extension never overrides the signature and the
	// signature never selects a different parser.
	if read.MediaFamily != expectedMediaFamily(formatRevision) {
		return ingestResult{quarantineReason: sourceObjectSkipReasonExtraction}, nil
	}
	// New text-anchor extractions bind the LF-preserving layout metadata to their
	// profile revision. Structural validation still uses formatRevision below;
	// the WithParserRevision override only changes the effective profile identity.
	parserRevision, validParserRevision := extractionParserRevision(formatRevision, h.parserRevision)
	if !validParserRevision {
		return ingestResult{}, failure("INGEST_PROFILE", canon.ErrTextFragmentLayout)
	}

	canonicalFormat, planned, observer, ok, retryable := h.plan(ctx, formatRevision, parserRevision, read.Content)
	if retryable {
		// The dispatcher did not transfer source bytes to a sandbox, so the durable
		// job may retry without turning an infrastructure outage into a permanent
		// per-object quarantine. After transfer, the dispatcher never returns this
		// sentinel and the object remains fail-closed quarantine.
		return ingestResult{}, failure("INGEST_PARSER_UNAVAILABLE", sandboxdispatch.ErrRetryBeforeTransfer)
	}
	if !ok {
		// Malformed, mismatched, empty or (for EML) unextractable/limit-breaching
		// input is a per-object quarantine, never a sync-run failure — one bad file
		// must not block the whole scope.
		return ingestResult{quarantineReason: sourceObjectSkipReasonExtraction}, nil
	}
	// A worker-backed format must carry the observer that produced its text into the
	// extraction identity; an in-process format has no observer to carry. Losing the
	// observer here would make a worker-image swap invisible to profile_hash, and the
	// "already extracted" short-circuit below would then keep the old Extraction.
	if observerRequired(formatRevision) != (observer != nil) {
		return ingestResult{}, failure("INGEST_OBSERVER", errMissingObserverIdentity)
	}

	profile := canon.ExtractionProfile{
		CanonicalFormat: canonicalFormat, ExtractorName: extractorName, ExtractorVer: extractorVersion,
		ArtifactHash: extractorArtifactHash, ParserRevision: parserRevision, Observer: observer,
	}
	for _, unit := range planned {
		if unit.ocrProfile != nil {
			profile.OCR = unit.ocrProfile
			break
		}
	}
	profileBytes, err := profile.ProfileBytes()
	if err != nil {
		return ingestResult{}, failure("INGEST_PROFILE", err)
	}
	profileHash := canon.Hash(profileBytes)

	result := ingestResult{}
	err = h.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		if _, err := tx.Exec(ctx, `SELECT app.lock_job_lease($1, $2, $3)`, claimed.ID, h.workerID, claimed.LeaseEpoch); err != nil {
			return err
		}
		// Fence every derived write to this candidate revision's live SYNCING
		// authority (ADR-0061 §3): a concurrent cutover that REVOKES a superseded
		// revision serializes on the activation row, so a superseded worker's whole
		// object transaction rolls back and creates no membership, version,
		// extraction or evidence.
		if _, err := tx.Exec(ctx, `SELECT app.assert_scope_revision_syncing($1, $2)`, resolved.scopeID, resolved.revision); err != nil {
			return err
		}

		objectID, objectCreated, err := h.ensureObject(ctx, tx, access, resolved, relativePath, title, objectType,
			externalIDDigest, locatorDigest, externalIDBytes, locatorBytes)
		if err != nil {
			return err
		}
		if objectCreated {
			if err := h.auditEntity(ctx, access, tx, audit.ActionSourceObjectIngested, audit.ResourceSourceObject, objectID, syncRunID, claimed.ID); err != nil {
				return err
			}
		}
		if err := h.injectFault("after_object"); err != nil {
			return err
		}

		versionID, created, err := h.ensureVersion(ctx, tx, access, objectID, versionKey, read.ContentSHA256)
		if err != nil {
			return err
		}
		if created {
			if err := h.auditEntity(ctx, access, tx, audit.ActionSourceVersionCreated, audit.ResourceSourceObject, versionID, syncRunID, claimed.ID); err != nil {
				return err
			}
		}
		if err := h.injectFault("after_version"); err != nil {
			return err
		}
		result.versionCreated = created

		var alreadyExtracted bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM public.source_extraction
			WHERE organization_id=$1 AND source_version_id=$2 AND profile_hash=$3 AND status='SUCCEEDED')`,
			access.OrganizationID, versionID, profileHash).Scan(&alreadyExtracted); err != nil {
			return err
		}
		if alreadyExtracted {
			if err := h.publishObjectPresence(ctx, tx, access, claimed, resolved.scopeID, resolved.revision, syncRunID, objectID, versionID, true); err != nil {
				return err
			}
			var extractionID string
			var fragmentIDs []string
			if h.graph != nil || h.searchRepository != nil {
				var err error
				extractionID, fragmentIDs, err = h.graphPublication(ctx, tx, access, versionID, profileHash)
				if err != nil {
					return err
				}
			}
			if h.graph != nil {
				if err := h.projectGraphForVersion(ctx, tx, access, resolved, objectID, versionID,
					extractionID, fragmentIDs[0], title, graphEntityType(objectType),
					graphTermInputs(title, planned, fragmentIDs)...); err != nil {
					return err
				}
			}
			if h.searchRepository != nil {
				units, err := buildUnits(canonicalFormat, parserRevision, objectID, planned)
				if err != nil {
					return err
				}
				if len(units) != len(fragmentIDs) {
					return failure("INGEST_SEARCH_PROJECTION_LINEAGE", nil)
				}
				plans := make([]searchChunkPlan, 0, len(units))
				for index, unit := range units {
					plans = append(plans, searchChunkPlan{
						text: documentChunkText(relativePath, unit.text), fragmentID: fragmentIDs[index], ordinal: int64(index + 1),
					})
				}
				if err := h.publishSearchChunks(ctx, tx, access, versionID, extractionID, plans); err != nil {
					return err
				}
			}
			// sync_run.evidence_published is the operator's "how much Evidence
			// does this scope serve after this run" counter, and it is what the
			// workspace source projection shows. This branch republishes the
			// graph and search projections for an already-extracted version, so
			// the run really does publish those fragments; leaving the counter
			// at zero made every repeat sync report evidence_published=0 beside
			// objects_ingested=N and sent a live investigation after a
			// non-existent "evidence was never produced" defect.
			result.evidence = len(fragmentIDs)
			return h.resolveObjectSkips(ctx, tx, access, resolved, syncRunID, objectID, relativePath)
		}

		count, err := h.extractAndPublish(ctx, tx, access, claimed, syncRunID, objectID, versionID, created,
			canonicalFormat, parserRevision, profileBytes, profileHash, planned, relativePath)
		if err != nil {
			return err
		}
		result.evidence = count
		if err := h.publishObjectPresence(ctx, tx, access, claimed, resolved.scopeID, resolved.revision, syncRunID, objectID, versionID, false); err != nil {
			return err
		}
		if h.graph != nil && count > 0 {
			extractionID, fragmentIDs, err := h.graphPublication(ctx, tx, access, versionID, profileHash)
			if err != nil {
				return err
			}
			if err := h.projectGraphForVersion(ctx, tx, access, resolved, objectID, versionID,
				extractionID, fragmentIDs[0], title, graphEntityType(objectType),
				graphTermInputs(title, planned, fragmentIDs)...); err != nil {
				return err
			}
		}
		return h.resolveObjectSkips(ctx, tx, access, resolved, syncRunID, objectID, relativePath)
	})
	if err != nil {
		return ingestResult{}, failure("INGEST_OBJECT", err)
	}
	return result, nil
}

// ensureObject resolves the stable SourceObject identity, creating and binding
// its three encrypted identity artifacts on first sight, and records ACTIVE
// scope membership. Overlapping scopes resolve to one object.
func (h *Handler) ensureObject(ctx context.Context, tx database.Transaction, access database.AccessContext,
	resolved resolvedScope, relativePath, title, objectType, externalIDDigest, locatorDigest string,
	externalIDBytes, locatorBytes []byte) (string, bool, error) {
	var objectID string
	err := tx.QueryRow(ctx, `SELECT id FROM public.source_object
		WHERE organization_id=$1 AND connection_id=$2 AND digest_key_version=$3 AND external_object_id_digest=$4`,
		access.OrganizationID, resolved.connectionID, h.digester.KeyVersion, externalIDDigest).Scan(&objectID)
	created := false
	switch {
	case err == nil:
		if _, err := tx.Exec(ctx, `UPDATE public.source_object SET last_seen_at=now()
			WHERE organization_id=$1 AND id=$2`, access.OrganizationID, objectID); err != nil {
			return "", false, err
		}
	case database.IsNotFound(err):
		created = true
		objectID, err = h.newID("object")
		if err != nil {
			return "", false, err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO public.source_object
			(organization_id, id, connection_id, object_type, digest_key_version,
			 external_object_id_digest, canonical_locator_digest, lifecycle_state, queryable)
			VALUES ($1, $2, $3, $4, $5, $6, $7, 'ACTIVE', false)`,
			access.OrganizationID, objectID, resolved.connectionID, objectType, h.digester.KeyVersion,
			externalIDDigest, locatorDigest); err != nil {
			return "", false, err
		}
		if err := h.storeArtifact(ctx, tx, access, artifactcrypto.SourceObjectCanonicalLocator, objectID, locatorBytes); err != nil {
			return "", false, err
		}
		if err := h.storeArtifact(ctx, tx, access, artifactcrypto.SourceObjectExternalID, objectID, externalIDBytes); err != nil {
			return "", false, err
		}
		if err := h.storeArtifact(ctx, tx, access, artifactcrypto.SourceObjectTitle, objectID, []byte(title)); err != nil {
			return "", false, err
		}
	default:
		return "", false, err
	}

	if _, err := tx.Exec(ctx, `INSERT INTO public.source_object_scope
		(organization_id, source_object_id, source_scope_id, source_scope_revision, membership_state)
		VALUES ($1, $2, $3, $4, 'ACTIVE')
		ON CONFLICT (organization_id, source_object_id, source_scope_id, source_scope_revision)
		DO UPDATE SET last_seen_at=now()`,
		access.OrganizationID, objectID, resolved.scopeID, resolved.revision); err != nil {
		return "", false, err
	}
	return objectID, created, nil
}

// ensureVersion preserves consecutive-observation idempotency, not global
// content deduplication. A -> B -> A requires a new immutable observation of A:
// the first A must remain SUPERSEDED and its retained addresses stay unchanged.
// Observation keys are internal; a connector still supplies only native/hash
// keys. The object lock serializes overlapping scopes on the current pointer.
func (h *Handler) ensureVersion(ctx context.Context, tx database.Transaction, access database.AccessContext,
	objectID, versionKey, contentHash string) (string, bool, error) {
	if !validSourceVersionKey(versionKey, contentHash) {
		return "", false, failure("INGEST_VERSION_KEY", nil)
	}
	var currentID, currentKey, currentHash, currentState *string
	if err := tx.QueryRow(ctx, `SELECT o.current_version_id, v.external_version_key, v.content_hash, v.state
		FROM public.source_object o LEFT JOIN public.source_version v
		ON v.organization_id=o.organization_id AND v.id=o.current_version_id
		WHERE o.organization_id=$1 AND o.id=$2 FOR UPDATE OF o`,
		access.OrganizationID, objectID).Scan(&currentID, &currentKey, &currentHash, &currentState); err != nil {
		return "", false, err
	}
	observationPrefix := "observation:" + canon.Hash([]byte(versionKey)) + ":"
	if currentID != nil && currentKey != nil &&
		(*currentKey == versionKey || strings.HasPrefix(*currentKey, observationPrefix)) {
		if currentHash == nil || *currentHash != contentHash || currentState == nil || *currentState != "CURRENT" {
			return "", false, failure("INGEST_VERSION_IDENTITY_CONFLICT", nil)
		}
		return *currentID, false, nil
	}
	var versionID, priorHash, priorState, retentionState string
	var queryable, extractionAllowed bool
	var priorFence int64
	err := tx.QueryRow(ctx, `SELECT v.id, v.content_hash, v.state, r.state, r.queryable, r.extraction_allowed, r.retention_fence
		FROM public.source_version v JOIN public.source_version_retention r
		ON r.organization_id=v.organization_id AND r.source_version_id=v.id
		WHERE v.organization_id=$1 AND v.source_object_id=$2 AND v.external_version_key=$3`, access.OrganizationID, objectID, versionKey).
		Scan(&versionID, &priorHash, &priorState, &retentionState, &queryable, &extractionAllowed, &priorFence)
	switch {
	case err == nil:
		if priorHash != contentHash {
			return "", false, failure("INGEST_VERSION_IDENTITY_CONFLICT", nil)
		}
		// A new observation must never bypass a historical retention closure.
		if retentionState != "ACTIVE" || !queryable || !extractionAllowed {
			return "", false, failure("INGEST_VERSION_CLOSED", nil)
		}
		// Reuse the existing privileged fence check to serialize with purge;
		// the worker intentionally has no direct UPDATE privilege on retention.
		if _, err := tx.Exec(ctx, `SELECT app.assert_version_writable($1, $2)`, versionID, priorFence); err != nil {
			return "", false, err
		}
		if priorState == "PENDING" {
			return versionID, false, nil
		}
		if priorState != "SUPERSEDED" || currentID == nil || currentState == nil || *currentState != "CURRENT" {
			return "", false, failure("INGEST_VERSION_CLOSED", nil)
		}
		// The previous current ID distinguishes separate returns to these same
		// bytes. Repeating the new current observation is handled above. Both
		// creation and publication share the caller's lease-fenced transaction.
		versionKey = observationPrefix + *currentID
	case database.IsNotFound(err):
		// First observation of this connector version uses its original key.
	default:
		return "", false, err
	}
	versionID, err = h.newID("version")
	if err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.source_version
		(organization_id, id, source_object_id, external_version_key, content_hash, observed_at, state)
		VALUES ($1, $2, $3, $4, $5, now(), 'PENDING')`,
		access.OrganizationID, versionID, objectID, versionKey, contentHash); err != nil {
		return "", false, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.source_version_retention
		(organization_id, source_version_id, state, queryable, extraction_allowed, retention_fence)
		VALUES ($1, $2, 'ACTIVE', true, true, 0)`, access.OrganizationID, versionID); err != nil {
		return "", false, err
	}
	return versionID, true, nil
}

func validSourceVersionKey(value, contentHash string) bool {
	if value == "" || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\t") {
		return false
	}
	if value == "hash:"+contentHash {
		return true
	}
	if !strings.HasPrefix(value, "native:") {
		return false
	}
	tail := strings.TrimPrefix(value, "native:")
	if len(tail) < 1 || len(tail) > 248 {
		return false
	}
	for _, r := range tail {
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return false
		}
	}
	return true
}

// plannedUnit is one Evidence unit resolved before the SourceObject id is known:
// its canonical text and the anchor coordinates for its format. The EMAIL anchor
// also needs the object id (bound at build time); the TEXT anchor does not. An
// Office unit already carries the finished anchor: canon built it during
// re-validation of the sandbox observation, so nothing rebuilds or reinterprets it
// here.
type plannedUnit struct {
	text               []byte
	lineStart, lineEnd int    // TEXT line-range anchor
	textLayoutMetadata []byte // TEXT whole-buffer layout metadata, built during planning
	mimePart           string // EMAIL MIME part path
	byteStart, byteEnd int    // EMAIL UTF-8 byte range within the part's canonical text
	officeAnchor       []byte // DOCX/PPTX/XLSX canonical anchor JCS, built by canon
	officeMetadata     []byte // DOCX/PPTX/XLSX per-fragment metadata
	pdfAnchor          []byte // PDF canonical anchor JCS, built by canon
	pdfMetadata        []byte // PDF per-fragment geometry/observer metadata
	ocrAnchor          []byte // OCR token-range anchor, built by canon
	ocrMetadata        []byte // OCR parser/model/box metadata
	ocrProfile         *canon.OCRProfile
}

func extractionParserRevision(formatRevision, override string) (string, bool) {
	revision := formatRevision
	if override != defaultParserRevision {
		revision = override
	}
	_, office := format.OfficeRevision(formatRevision)
	_, pdf := format.PDFRevision(formatRevision)
	if office || pdf {
		revision = canon.StructuralLayoutParserRevision(revision)
		return revision, canon.IsStructuralLayoutParserRevision(revision)
	}
	if !usesTextFragmentLayout(formatRevision) {
		return revision, true
	}
	revision = canon.TextLayoutParserRevision(revision)
	return revision, canon.IsTextLayoutParserRevision(revision)
}

func usesTextFragmentLayout(formatRevision string) bool {
	switch formatRevision {
	case format.RevisionText, format.RevisionSourceCode, format.RevisionCSV,
		format.RevisionJSON, format.RevisionXML, format.RevisionHTML:
		return true
	default:
		return false
	}
}

func plannedTextUnits(canonical []byte, parserRevision string) ([]plannedUnit, bool) {
	if !canon.IsTextLayoutParserRevision(parserRevision) {
		return nil, false
	}
	fragments := canon.Segment(canonical, maxFragmentBytes)
	if len(fragments) == 0 {
		return nil, false
	}
	layouts, err := canon.NewTextFragmentLayouts(canonical, fragments, parserRevision)
	if err != nil {
		return nil, false
	}
	planned := make([]plannedUnit, 0, len(fragments))
	for i, fragment := range fragments {
		metadata, err := layouts[i].Marshal()
		if err != nil {
			return nil, false
		}
		planned = append(planned, plannedUnit{
			text: fragment.Text, lineStart: fragment.LineStart, lineEnd: fragment.LineEnd,
			textLayoutMetadata: metadata,
		})
	}
	return planned, true
}

// plan resolves the object's canonical Evidence units and canonical format from
// its bytes, per its parser-profile revision. The TEXT-anchor formats canonicalize
// and line-segment the whole file; EML parses the MIME tree and byte-segments each
// extractable text part. ok is false (quarantine) for malformed, mismatched, empty
// or unextractable input, with no fallback (PARSER_CONTRACTS.md §2).
func (h *Handler) plan(ctx context.Context, formatRevision, parserRevision string, content []byte) (canonicalFormat string, planned []plannedUnit, observer *canon.ObserverIdentity, ok, retryable bool) {
	// Office resolves through the isolated parser sandbox (ADR-0062). The sandbox
	// only observes structure and reports raw text; internal/source/docparser has
	// already canonicalized that text and built every anchor and hash through canon
	// by the time Extract returns, so this branch consumes finished canonical units
	// and never re-derives them. With no sandbox configured an Office object
	// quarantines — there is no in-process fallback parser (PARSER_CONTRACTS.md §2).
	if officeFormat, isOffice := format.OfficeRevision(formatRevision); isOffice {
		if h.office == nil {
			return "", nil, nil, false, false
		}
		result, err := h.office.Extract(ctx, officeFormat, content)
		if errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) {
			return "", nil, nil, false, true
		}
		if err != nil || result == nil || len(result.Fragments) == 0 {
			return "", nil, nil, false, false
		}
		for _, fragment := range result.Fragments {
			metadata, err := officeFragmentMetadata(parserRevision, result.Parser, fragment)
			if err != nil {
				return "", nil, nil, false, false
			}
			planned = append(planned, plannedUnit{
				text: fragment.CanonicalText, officeAnchor: fragment.AnchorBytes, officeMetadata: metadata,
			})
		}
		// The sandbox identity the invoker already re-checked against its pin travels
		// on to the extraction profile, so this Extraction is bound to the exact build
		// that observed the document.
		if err := bindStructuralLayout(officeFormat, parserRevision, result.ObjectText, result.ObjectTextHash, planned); err != nil {
			return "", nil, nil, false, false
		}
		return officeFormat, planned, &canon.ObserverIdentity{
			Name:                       result.Parser.Name,
			Version:                    result.Parser.Version,
			ArtifactHash:               result.Parser.ArtifactHash,
			ObservationProfileRevision: result.Parser.ObservationProfileRevision,
			RuntimeProfileHash:         result.Parser.RuntimeProfileHash,
		}, true, false
	}
	// Text PDF has a separate closed observer/result contract. A missing or
	// rejecting observer quarantines the whole object. Only the explicit
	// ErrScannedOrMixedPDF classification can enter planScannedPDF; no generic
	// parser failure is treated as permission to invoke OCR.
	if pdfFormat, isPDF := format.PDFRevision(formatRevision); isPDF {
		if h.pdf == nil {
			return "", nil, nil, false, false
		}
		result, err := h.pdf.Extract(ctx, pdfFormat, content)
		if errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) {
			return "", nil, nil, false, true
		}
		if errors.Is(err, pdfparser.ErrScannedOrMixedPDF) {
			return h.planScannedPDF(ctx, pdfFormat, parserRevision, content)
		}
		if err != nil || result == nil {
			return "", nil, nil, false, false
		}
		if len(result.Fragments) == 0 {
			return "", nil, nil, false, false
		}
		for _, fragment := range result.Fragments {
			metadata, err := pdfFragmentMetadata(parserRevision, result.Parser, fragment)
			if err != nil {
				return "", nil, nil, false, false
			}
			planned = append(planned, plannedUnit{
				text: fragment.CanonicalText, pdfAnchor: fragment.AnchorBytes, pdfMetadata: metadata,
			})
		}
		if err := bindStructuralLayout(pdfFormat, parserRevision, result.ObjectText, result.ObjectTextHash, planned); err != nil {
			return "", nil, nil, false, false
		}
		return pdfFormat, planned, &canon.ObserverIdentity{
			Name:                       result.Parser.Name,
			Version:                    result.Parser.Version,
			ArtifactHash:               result.Parser.ArtifactHash,
			ObservationProfileRevision: result.Parser.ObservationProfileRevision,
			RuntimeProfileHash:         result.Parser.RuntimeProfileHash,
		}, true, false
	}
	if _, isOCR := format.OCRRevision(formatRevision); isOCR {
		if h.ocr == nil {
			return "", nil, nil, false, false
		}
		mediaFamily := ocrparser.FormatPNG
		if formatRevision == format.RevisionJPEG {
			mediaFamily = ocrparser.FormatJPEG
		}
		result, err := h.ocr.Extract(ctx, mediaFamily, content)
		if errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) {
			return "", nil, nil, false, true
		}
		if err != nil || result == nil {
			return "", nil, nil, false, false
		}
		if len(result.Fragments) == 0 {
			return "", nil, nil, false, false
		}
		profile := &canon.OCRProfile{ModelID: result.OCR.ModelID, ModelRevision: result.OCR.ModelRevision, ArtifactHash: result.OCR.ArtifactHash, ProfileRevision: result.OCR.ProfileRevision}
		for _, fragment := range result.Fragments {
			metadata, err := ocrFragmentMetadata(parserRevision, result.Parser, result.OCR, fragment)
			if err != nil {
				return "", nil, nil, false, false
			}
			planned = append(planned, plannedUnit{text: fragment.CanonicalText, ocrAnchor: fragment.AnchorBytes, ocrMetadata: metadata, ocrProfile: profile})
		}
		return "OCR", planned, &canon.ObserverIdentity{Name: result.Parser.Name, Version: result.Parser.Version, ArtifactHash: result.Parser.ArtifactHash, ObservationProfileRevision: result.Parser.ObservationProfileRevision}, true, false
	}
	if formatRevision == format.RevisionEML {
		doc, err := eml.Parse(content)
		if err != nil || len(doc.Parts) == 0 {
			return "", nil, nil, false, false
		}
		for _, part := range doc.Parts {
			for _, seg := range canon.Segment(part.Canonical, maxFragmentBytes) {
				planned = append(planned, plannedUnit{
					text: seg.Text, mimePart: part.MIMEPart, byteStart: seg.ByteStart, byteEnd: seg.ByteEnd,
				})
			}
		}
		if len(planned) == 0 {
			return "", nil, nil, false, false
		}
		return "EMAIL", planned, nil, true, false
	}
	// HTML resolves through the dedicated safe extractor: its normalized visible
	// text is the canonical text, already text-v1, that the TEXT line ranges index.
	// Active/embedded content is dropped, no URL is loaded, and a resource-bomb or
	// text-free document quarantines with no fallback (PARSER_CONTRACTS.md §5).
	if formatRevision == format.RevisionHTML {
		canonical, err := sourcehtml.Extract(content)
		if err != nil {
			return "", nil, nil, false, false
		}
		planned, ok = plannedTextUnits(canonical, parserRevision)
		if !ok {
			return "", nil, nil, false, false
		}
		return "TEXT", planned, nil, true, false
	}
	canonical, err := canon.Canonicalize(content)
	if err != nil {
		return "", nil, nil, false, false
	}
	if err := format.Validate(formatRevision, canonical); err != nil {
		return "", nil, nil, false, false
	}
	planned, ok = plannedTextUnits(canonical, parserRevision)
	if !ok {
		return "", nil, nil, false, false
	}
	return "TEXT", planned, nil, true, false
}

// planScannedPDF is the only render→OCR composition path. It is reachable only
// after the PDF observer returns the explicit ErrScannedOrMixedPDF
// classification; all ordinary PDF failures remain quarantined. Rendered PNG
// pages and OCR observations are held transiently and converted immediately to
// Go-owned token anchors. Renderer identity is folded into the immutable OCR
// artifact identity so a renderer replacement always mints a new Extraction.
func (h *Handler) planScannedPDF(ctx context.Context, pdfFormat, parserRevision string, content []byte) (string, []plannedUnit, *canon.ObserverIdentity, bool, bool) {
	if h.pdfRender == nil || h.ocr == nil {
		return "", nil, nil, false, false
	}
	rendered, err := h.pdfRender.Extract(ctx, pdfFormat, content)
	if errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) {
		return "", nil, nil, false, true
	}
	if err != nil || rendered == nil || rendered.ObservedFormat != pdfrenderparser.FormatPDF || len(rendered.Pages) == 0 {
		return "", nil, nil, false, false
	}
	rendererObserver := canon.ObserverIdentity{
		Name: rendered.Renderer.Name, Version: rendered.Renderer.Version,
		ArtifactHash:               rendered.Renderer.ArtifactHash,
		ObservationProfileRevision: rendered.Renderer.ProfileRevision,
	}
	if rendererObserver.Name == "" || rendererObserver.Version == "" || rendererObserver.ArtifactHash == "" || rendererObserver.ObservationProfileRevision == "" {
		return "", nil, nil, false, false
	}

	var planned []plannedUnit
	var observer *canon.ObserverIdentity
	var ocrProfile *canon.OCRProfile
	for _, page := range rendered.Pages {
		if page.Page < 1 || len(page.PNGBytes) == 0 {
			return "", nil, nil, false, false
		}
		result, err := h.ocr.Extract(ctx, ocrparser.FormatPNG, page.PNGBytes)
		if errors.Is(err, sandboxdispatch.ErrRetryBeforeTransfer) {
			return "", nil, nil, false, true
		}
		if err != nil || result == nil {
			return "", nil, nil, false, false
		}
		if len(result.Fragments) == 0 {
			return "", nil, nil, false, false
		}
		repaged, err := ocrparser.Repage(result, page.Page)
		if err != nil {
			return "", nil, nil, false, false
		}
		currentObserver := &canon.ObserverIdentity{Name: result.Parser.Name, Version: result.Parser.Version, ArtifactHash: result.Parser.ArtifactHash, ObservationProfileRevision: result.Parser.ObservationProfileRevision}
		if observer == nil {
			observer = currentObserver
			composite, err := canon.CompositeArtifactHash(result.OCR.ArtifactHash, rendererObserver)
			if err != nil {
				return "", nil, nil, false, false
			}
			ocrProfile = &canon.OCRProfile{ModelID: result.OCR.ModelID, ModelRevision: result.OCR.ModelRevision, ArtifactHash: composite, ProfileRevision: result.OCR.ProfileRevision}
		} else if *observer != *currentObserver || ocrProfile == nil || result.OCR.ModelID != ocrProfile.ModelID || result.OCR.ModelRevision != ocrProfile.ModelRevision || result.OCR.ProfileRevision != ocrProfile.ProfileRevision {
			return "", nil, nil, false, false
		}
		for _, fragment := range repaged.Fragments {
			metadata, err := ocrFragmentMetadata(parserRevision, repaged.Parser, repaged.OCR, fragment)
			if err != nil {
				return "", nil, nil, false, false
			}
			planned = append(planned, plannedUnit{text: fragment.CanonicalText, ocrAnchor: fragment.AnchorBytes, ocrMetadata: metadata, ocrProfile: ocrProfile})
		}
	}
	if observer == nil || ocrProfile == nil || len(planned) == 0 {
		return "", nil, nil, false, false
	}
	return "OCR", planned, observer, true, false
}

// evidenceUnit is a fully materialized Evidence fragment: its canonical text, its
// canonical anchor JCS and its metadata JCS, ready to persist.
type evidenceUnit struct {
	text        []byte
	anchorBytes []byte
	metadata    []byte
}

// buildUnits binds the objectID-dependent anchor identity into each planned unit.
// The EMAIL anchor's message id is the deterministic source-object identity
// (never the RFC Message-ID header — PARSER_CONTRACTS.md §5); the TEXT anchor is
// object-id-independent.
// documentChunkText renders one retrieval unit with its document context
// (knowvault-DECISIONS.md 11, "smart chunks"): the object's own path inside its
// source, then the unit's exact text.
//
// A retrieval unit taken alone says nothing about which document it came from —
// a Go function body names no file and no repository — so "where is source
// trust verification implemented?" could match the body but never name, rank or
// cite the file it lives in. The path is not a secret the chunk is smuggling:
// it is the object's own observation identity (observation.Object.ExternalID,
// the repository-relative path a GIT connector reports and the scope-relative
// path a folder connector reports), available to the publisher at exactly this
// point. This mirrors the structured side, where postgresqlRowCard already
// prefixes each row card with its qualified schema.relation.
//
// Only the retrieval projection carries it. The Evidence fragment stays the
// exact bytes of the document with its byte-range anchor, so a citation remains
// byte-exact and the anchor still addresses the source text and nothing else.
func documentChunkText(documentPath string, text []byte) []byte {
	documentPath = strings.TrimSpace(documentPath)
	if documentPath == "" || strings.ContainsAny(documentPath, "\r\n") || !utf8.ValidString(documentPath) {
		return append([]byte(nil), text...)
	}
	contextual := make([]byte, 0, len(documentPath)+1+len(text))
	contextual = append(contextual, documentPath...)
	contextual = append(contextual, '\n')
	contextual = append(contextual, text...)
	if !utf8.Valid(contextual) {
		return append([]byte(nil), text...)
	}
	return contextual
}

func buildUnits(canonicalFormat, parserRevision, objectID string, planned []plannedUnit) ([]evidenceUnit, error) {
	messageID := "source-object:" + objectID
	units := make([]evidenceUnit, 0, len(planned))
	for _, p := range planned {
		var anchorBytes, metadata []byte
		var err error
		if p.officeAnchor != nil {
			// Already canonical: canon built this anchor from the text it
			// canonicalized during re-validation. Rebuilding it here would create a
			// second place that decides what an Office anchor is.
			units = append(units, evidenceUnit{text: p.text, anchorBytes: p.officeAnchor, metadata: p.officeMetadata})
			continue
		}
		if p.pdfAnchor != nil {
			units = append(units, evidenceUnit{text: p.text, anchorBytes: p.pdfAnchor, metadata: p.pdfMetadata})
			continue
		}
		if p.ocrAnchor != nil {
			units = append(units, evidenceUnit{text: p.text, anchorBytes: p.ocrAnchor, metadata: p.ocrMetadata})
			continue
		}
		if canonicalFormat == "EMAIL" {
			anchorBytes, err = canon.EmailAnchorBytes(messageID, p.mimePart, p.byteStart, p.byteEnd)
			if err == nil {
				metadata, err = emailFragmentMetadata(parserRevision, p.mimePart, p.byteStart, p.byteEnd)
			}
		} else {
			anchorBytes, err = canon.TextAnchorBytes(p.lineStart, p.lineEnd)
			if err == nil {
				if canonicalFormat == "TEXT" && canon.IsTextLayoutParserRevision(parserRevision) {
					if len(p.textLayoutMetadata) == 0 {
						err = canon.ErrTextFragmentLayout
					} else {
						metadata = p.textLayoutMetadata
					}
				} else if len(p.textLayoutMetadata) > 0 {
					err = canon.ErrTextFragmentLayout
				} else {
					metadata, err = textFragmentMetadata(parserRevision, p.lineStart, p.lineEnd)
				}
			}
		}
		if err != nil {
			return nil, failure("INGEST_ANCHOR", err)
		}
		units = append(units, evidenceUnit{text: p.text, anchorBytes: anchorBytes, metadata: metadata})
	}
	return units, nil
}

// extractAndPublish materializes the Evidence units, writes the immutable
// Evidence set, recomputes the evidence-set hash, and atomically publishes the
// active extraction. When the version was newly created it becomes CURRENT.
func (h *Handler) extractAndPublish(ctx context.Context, tx database.Transaction, access database.AccessContext,
	claimed jobs.ClaimedJob, syncRunID, objectID, versionID string, versionCreated bool,
	canonicalFormat, parserRevision string, profileBytes []byte, profileHash string, planned []plannedUnit,
	documentPath string) (int, error) {
	units, err := buildUnits(canonicalFormat, parserRevision, objectID, planned)
	if err != nil {
		return 0, err
	}
	// Read and lock the version-retention row at its current fence: the extraction
	// records the exact fence it started at, and publication re-checks it, so a
	// later purge (S1e) that advances the fence fails this extraction closed.
	var retentionFence int64
	if err := tx.QueryRow(ctx, `SELECT retention_fence FROM public.source_version_retention
		WHERE organization_id=$1 AND source_version_id=$2`, access.OrganizationID, versionID).Scan(&retentionFence); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `SELECT app.assert_version_writable($1, $2)`, versionID, retentionFence); err != nil {
		return 0, err
	}

	extractionID, err := h.newID("extraction")
	if err != nil {
		return 0, err
	}
	var ocrUsed bool
	var ocrModelID, ocrModelRevision, ocrArtifactHash, ocrProfileRevision *string
	for _, unit := range planned {
		if unit.ocrProfile == nil {
			continue
		}
		if ocrUsed && (*ocrModelID != unit.ocrProfile.ModelID || *ocrModelRevision != unit.ocrProfile.ModelRevision || *ocrArtifactHash != unit.ocrProfile.ArtifactHash || *ocrProfileRevision != unit.ocrProfile.ProfileRevision) {
			return 0, failure("INGEST_OCR_PROFILE", nil)
		}
		ocrUsed = true
		modelID, modelRevision, artifactHash, profileRevision := unit.ocrProfile.ModelID, unit.ocrProfile.ModelRevision, unit.ocrProfile.ArtifactHash, unit.ocrProfile.ProfileRevision
		ocrModelID, ocrModelRevision, ocrArtifactHash, ocrProfileRevision = &modelID, &modelRevision, &artifactHash, &profileRevision
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.source_extraction
		(organization_id, id, source_version_id, retention_fence_at_start, canonical_format,
		 profile_json, profile_hash, extractor_name, extractor_version, extractor_artifact_hash,
		 normalization_version, parser_profile_revision, ocr_used, ocr_model_id,
		 ocr_model_revision, ocr_artifact_hash, ocr_profile_revision, status, started_at)
		VALUES ($1, $2, $3, $10, $11, $4, $5, $6, $7, $8, 'text-v1', $9,
		 $12, $13, $14, $15, $16, 'RUNNING', now())`,
		access.OrganizationID, extractionID, versionID, jsontext.Value(profileBytes), profileHash,
		extractorName, extractorVersion, extractorArtifactHash, parserRevision, retentionFence, canonicalFormat,
		ocrUsed, ocrModelID, ocrModelRevision, ocrArtifactHash, ocrProfileRevision); err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO public.source_extraction_retention
		(organization_id, extraction_id, state, queryable) VALUES ($1, $2, 'ACTIVE', true)`,
		access.OrganizationID, extractionID); err != nil {
		return 0, err
	}
	if err := h.injectFault("after_extraction"); err != nil {
		return 0, err
	}

	descriptors := make([]canon.EvidenceDescriptor, 0, len(units))
	searchPlans := make([]searchChunkPlan, 0, len(units))
	for i, unit := range units {
		ordinal := i + 1
		fragmentID, err := h.newID("fragment")
		if err != nil {
			return 0, err
		}
		// text_hash and anchor_hash are organization-scoped equality projections
		// (ADR-0077): keyed HMAC under the active digest key version.  The
		// artifacts' plaintext_hash remains an internal SHA-256 integrity value;
		// the keyed projections are persisted separately by the bind gates.
		textHash := canon.HMACDigest(h.digester.Key, h.digester.KeyVersion, unit.text)
		anchorHash := canon.HMACDigest(h.digester.Key, h.digester.KeyVersion, unit.anchorBytes)
		tokenCount := len(strings.Fields(string(unit.text)))
		if _, err := tx.Exec(ctx, `INSERT INTO public.evidence_fragment
			(organization_id, id, source_version_id, extraction_id, ordinal, text_hash,
			 text_digest_key_version, token_count, byte_count, anchor_hash, anchor_digest_key_version, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())`,
			access.OrganizationID, fragmentID, versionID, extractionID, ordinal, textHash,
			h.digester.KeyVersion, tokenCount, len(unit.text), anchorHash, h.digester.KeyVersion); err != nil {
			return 0, err
		}
		if err := h.storeKeyedArtifact(ctx, tx, access, artifactcrypto.EvidenceNormalizedText, fragmentID, unit.text,
			textHash, h.digester.KeyVersion); err != nil {
			return 0, err
		}
		if err := h.storeKeyedArtifact(ctx, tx, access, artifactcrypto.EvidenceAnchor, fragmentID, unit.anchorBytes,
			anchorHash, h.digester.KeyVersion); err != nil {
			return 0, err
		}
		if err := h.storeArtifact(ctx, tx, access, artifactcrypto.EvidenceMetadata, fragmentID, unit.metadata); err != nil {
			return 0, err
		}
		descriptors = append(descriptors, canon.EvidenceDescriptor{
			FragmentID: fragmentID, Ordinal: ordinal, TextHash: textHash, AnchorHash: anchorHash,
		})
		if h.searchRepository != nil {
			searchPlans = append(searchPlans, searchChunkPlan{
				text: documentChunkText(documentPath, unit.text), fragmentID: fragmentID, ordinal: int64(ordinal),
			})
		}
		if ordinal == 1 {
			if err := h.injectFault("inside_evidence"); err != nil {
				return 0, err
			}
		}
	}

	evidenceSetHash, err := canon.EvidenceSetHash(descriptors)
	if err != nil {
		return 0, failure("INGEST_EVIDENCE_SET", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE public.source_extraction
		SET status='SUCCEEDED', evidence_set_hash=$3, completed_at=now()
		WHERE organization_id=$1 AND id=$2`, access.OrganizationID, extractionID, evidenceSetHash); err != nil {
		return 0, err
	}
	if err := h.publishSearchChunks(ctx, tx, access, versionID, extractionID, searchPlans); err != nil {
		return 0, err
	}

	if err := h.injectFault("before_publication"); err != nil {
		return 0, err
	}
	// Publication is one lease-fenced SECURITY DEFINER call: it verifies the
	// SUCCEEDED extraction, the evidence-set hash, retention and the closed
	// ordinal set, moves the active pointer, and — for a newly created version —
	// performs the current-version cutover (supersede prior current, make this one
	// current, flip object queryability). None of that is a raw worker UPDATE, so
	// a stale worker cannot make Evidence queryable.
	if _, err := tx.Exec(ctx, `SELECT app.source_version_publish_extraction($1, $2, $3, $4, $5, $6, $7)`,
		versionID, extractionID, evidenceSetHash, versionCreated, claimed.ID, h.workerID, claimed.LeaseEpoch); err != nil {
		return 0, err
	}
	if err := h.auditEntity(ctx, access, tx, audit.ActionSourceExtractionActive, audit.ResourceSourceObject, extractionID, syncRunID, claimed.ID); err != nil {
		return 0, err
	}
	return len(units), nil
}

// publishSearchChunks emits the durable lexical projection for every
// Evidence unit in this extraction. It intentionally does not require an
// embedding profile: vector metadata is an optional all-or-nothing tuple and
// is added only by a separately qualified real provider. A failure in any
// chunk, artifact bind or outbox append aborts the caller transaction, so an
// extraction can never become active with a partial search projection.
func (h *Handler) publishSearchChunks(ctx context.Context, tx database.Transaction,
	access database.AccessContext, versionID, extractionID string, plans []searchChunkPlan) error {
	if h == nil || h.searchRepository == nil || len(plans) == 0 {
		return nil
	}
	var existingChunks, existingFragments, malformedChunks int64
	if err := tx.QueryRow(ctx, `
		WITH per_chunk AS (
			SELECT chunk.id, count(fragment.evidence_fragment_id) AS fragment_count
			  FROM public.search_chunk AS chunk
			  LEFT JOIN public.search_chunk_fragment AS fragment
			    ON fragment.organization_id = chunk.organization_id
			   AND fragment.search_chunk_id = chunk.id
			 WHERE chunk.organization_id=$1
			   AND chunk.source_version_id=$2
			   AND chunk.extraction_id=$3
			 GROUP BY chunk.id
		)
		SELECT count(*), coalesce(sum(fragment_count), 0),
		       count(*) FILTER (WHERE fragment_count < 1)
		  FROM per_chunk`,
		access.OrganizationID, versionID, extractionID).Scan(&existingChunks, &existingFragments, &malformedChunks); err != nil {
		return failure("INGEST_SEARCH_PROJECTION_STATE", err)
	}
	expected := int64(len(plans))
	expectedFragments := int64(0)
	for _, plan := range plans {
		expectedFragments += int64(len(plan.fragments()))
	}
	// A chunk always binds at least one Evidence fragment. Accepting a chunk
	// with none would make a replay look complete while silently dropping
	// Evidence lineage.
	if malformedChunks != 0 {
		return failure("INGEST_SEARCH_PROJECTION_PARTIAL", nil)
	}
	if existingChunks == expected && existingFragments == expectedFragments {
		return nil
	}
	// An extraction that was already projected under an earlier chunking shape
	// is complete too. SearchChunk rows are immutable and the extraction is
	// already attested, so re-shaping is not available and not wanted: the
	// question is only whether every Evidence fragment of this extraction is
	// already reachable from some chunk. The one-chunk-per-fragment shape this
	// bridge produced before row cards satisfies that exactly.
	if existingChunks == expectedFragments && existingFragments == expectedFragments {
		return nil
	}
	if existingChunks != 0 || existingFragments != 0 {
		return failure("INGEST_SEARCH_PROJECTION_PARTIAL", nil)
	}
	for _, plan := range plans {
		fragments := plan.fragments()
		if len(plan.text) == 0 || len(fragments) == 0 || plan.ordinal < 1 {
			return failure("INGEST_SEARCH_PROJECTION_INVALID", nil)
		}
		chunkID, err := h.newID("chunk")
		if err != nil {
			return failure("INGEST_SEARCH_PROJECTION_ID", err)
		}
		artifactID, err := h.newID("art")
		if err != nil {
			return failure("INGEST_SEARCH_PROJECTION_ID", err)
		}
		owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.SearchChunkText, access.OrganizationID, chunkID)
		if err != nil {
			return failure("INGEST_SEARCH_PROJECTION_OWNER", err)
		}
		envelope, err := h.codec.Seal(owner, plan.text)
		if err != nil {
			return failure("INGEST_SEARCH_PROJECTION_SEAL", err)
		}
		chunk := search.Chunk{
			ID: chunkID, OrganizationID: access.OrganizationID,
			SourceVersionID: versionID, ExtractionID: extractionID,
			ChunkHash: envelope.PlaintextHash(), TokenCount: int64(len(strings.Fields(string(plan.text)))),
		}
		if err := h.searchRepository.CreateChunk(ctx, tx, access, chunk, artifactID, envelope); err != nil {
			return failure("INGEST_SEARCH_PROJECTION_CREATE", err)
		}
		for index, fragmentID := range fragments {
			if fragmentID == "" {
				return failure("INGEST_SEARCH_PROJECTION_INVALID", nil)
			}
			if err := h.searchRepository.AddFragment(ctx, tx, access, chunkID, fragmentID, int64(index+1)); err != nil {
				return failure("INGEST_SEARCH_PROJECTION_FRAGMENT", err)
			}
		}
	}
	return nil
}

// storeArtifact seals plaintext under the object/fragment-scoped owner branch and
// binds it in one statement (the bind function inserts the ciphertext and sets
// the owner column atomically).
func (h *Handler) storeArtifact(ctx context.Context, tx database.Transaction, access database.AccessContext,
	field artifactcrypto.OwnerField, owningRowID string, plaintext []byte) error {
	owner, err := artifactcrypto.NewOwnerIdentity(field, access.OrganizationID, owningRowID)
	if err != nil {
		return err
	}
	envelope, err := h.codec.Seal(owner, plaintext)
	if err != nil {
		return err
	}
	artifactID, err := h.newID("art")
	if err != nil {
		return err
	}
	return h.repo.Store(ctx, tx, access, field, owningRowID, artifactID, envelope)
}

// storeKeyedArtifact is the explicit keyed-projection path.  It is separate
// from storeArtifact so a new owner branch cannot silently inherit an optional
// equality projection or accidentally write an Evidence anchor through the
// generic artifact API.
func (h *Handler) storeKeyedArtifact(ctx context.Context, tx database.Transaction, access database.AccessContext,
	field artifactcrypto.OwnerField, owningRowID string, plaintext []byte, projectionDigest string,
	projectionKeyVersion int) error {
	owner, err := artifactcrypto.NewOwnerIdentity(field, access.OrganizationID, owningRowID)
	if err != nil {
		return err
	}
	envelope, err := h.codec.Seal(owner, plaintext)
	if err != nil {
		return err
	}
	artifactID, err := h.newID("art")
	if err != nil {
		return err
	}
	return h.repo.StoreKeyedProjection(ctx, tx, access, field, owningRowID, artifactID, envelope,
		projectionDigest, projectionKeyVersion)
}

// textFragmentMetadata is the opaque per-fragment metadata for a TEXT line-range
// anchor: the parser profile revision and the 1-based line range.
func textFragmentMetadata(parserRevision string, lineStart, lineEnd int) ([]byte, error) {
	raw, err := jsonv2.Marshal(struct {
		ParserProfileRevision string `json:"parser_profile_revision"`
		LineStart             int    `json:"line_start"`
		LineEnd               int    `json:"line_end"`
	}{ParserProfileRevision: parserRevision, LineStart: lineStart, LineEnd: lineEnd})
	if err != nil {
		return nil, failure("INGEST_METADATA", err)
	}
	return raw, nil
}

// officeFragmentMetadata is the opaque per-fragment metadata for a DOCX/PPTX/XLSX
// anchor. It records the runtime's own extraction profile revision plus the exact
// sandbox identity the observation came from, so an Extraction can always be traced
// to the pinned artifact that observed the document — and a different sandbox build
// produces a different Extraction rather than silently reinterpreting this one.
func officeFragmentMetadata(parserRevision string, parser docparser.Parser, fragment docparser.Fragment) ([]byte, error) {
	meta := struct {
		ParserProfileRevision      string `json:"parser_profile_revision"`
		ObserverName               string `json:"observer_name"`
		ObserverVersion            string `json:"observer_version"`
		ObserverArtifactHash       string `json:"observer_artifact_hash"`
		ObservationProfileRevision string `json:"observation_profile_revision"`
		RuntimeProfileHash         string `json:"runtime_profile_hash,omitempty"`
		AnchorKind                 string `json:"anchor_kind"`
		TextStart                  int    `json:"text_start"`
		TextEnd                    int    `json:"text_end"`
	}{
		ParserProfileRevision:      parserRevision,
		ObserverName:               parser.Name,
		ObserverVersion:            parser.Version,
		ObserverArtifactHash:       parser.ArtifactHash,
		ObservationProfileRevision: parser.ObservationProfileRevision,
		RuntimeProfileHash:         parser.RuntimeProfileHash,
		AnchorKind:                 fragment.Anchor.Kind,
		TextStart:                  fragment.Anchor.TextStart,
		TextEnd:                    fragment.Anchor.TextEnd,
	}
	raw, err := jsonv2.Marshal(meta)
	if err != nil {
		return nil, failure("INGEST_METADATA", err)
	}
	return raw, nil
}

// pdfFragmentMetadata binds the PDF observer identity and the page geometry used
// to validate its boxes. The canonical anchor remains the canon-owned artifact;
// metadata is traceability context and cannot replace or widen that anchor.
func pdfFragmentMetadata(parserRevision string, parser pdfparser.Parser, fragment pdfparser.Fragment) ([]byte, error) {
	meta := struct {
		ParserProfileRevision      string  `json:"parser_profile_revision"`
		ObserverName               string  `json:"observer_name"`
		ObserverVersion            string  `json:"observer_version"`
		ObserverArtifactHash       string  `json:"observer_artifact_hash"`
		ObservationProfileRevision string  `json:"observation_profile_revision"`
		RuntimeProfileHash         string  `json:"runtime_profile_hash,omitempty"`
		AnchorKind                 string  `json:"anchor_kind"`
		Page                       int     `json:"page"`
		PageWidth                  float64 `json:"page_width"`
		PageHeight                 float64 `json:"page_height"`
		Rotation                   int     `json:"rotation"`
		TextStart                  int     `json:"text_start"`
		TextEnd                    int     `json:"text_end"`
	}{
		ParserProfileRevision:      parserRevision,
		ObserverName:               parser.Name,
		ObserverVersion:            parser.Version,
		ObserverArtifactHash:       parser.ArtifactHash,
		ObservationProfileRevision: parser.ObservationProfileRevision,
		RuntimeProfileHash:         parser.RuntimeProfileHash,
		AnchorKind:                 fragment.Anchor.Kind,
		Page:                       fragment.Anchor.Page,
		PageWidth:                  fragment.PageWidth,
		PageHeight:                 fragment.PageHeight,
		Rotation:                   fragment.Rotation,
		TextStart:                  fragment.Anchor.TextStart,
		TextEnd:                    fragment.Anchor.TextEnd,
	}
	raw, err := jsonv2.Marshal(meta)
	if err != nil {
		return nil, failure("INGEST_METADATA", err)
	}
	return raw, nil
}

// ocrFragmentMetadata is opaque traceability context for an OCR token-range
// fragment. The canonical anchor remains the canon-owned artifact; this record
// binds the observer, model/profile and token range for terminal replay.
func ocrFragmentMetadata(parserRevision string, parser ocrparser.Parser, ocr ocrparser.OCRIdentity, fragment ocrparser.Fragment) ([]byte, error) {
	meta := struct {
		ParserProfileRevision      string `json:"parser_profile_revision"`
		ObserverName               string `json:"observer_name"`
		ObserverVersion            string `json:"observer_version"`
		ObserverArtifactHash       string `json:"observer_artifact_hash"`
		ObservationProfileRevision string `json:"observation_profile_revision"`
		ModelID                    string `json:"model_id"`
		ModelRevision              string `json:"model_revision"`
		ModelArtifactHash          string `json:"model_artifact_hash"`
		OCRProfileRevision         string `json:"ocr_profile_revision"`
		AnchorKind                 string `json:"anchor_kind"`
		Page                       int    `json:"page"`
		TokenStartOrdinal          int    `json:"token_start_ordinal"`
		TokenEndOrdinal            int    `json:"token_end_ordinal"`
		TokenCount                 int    `json:"token_count"`
	}{
		ParserProfileRevision: parserRevision, ObserverName: parser.Name, ObserverVersion: parser.Version,
		ObserverArtifactHash: parser.ArtifactHash, ObservationProfileRevision: parser.ObservationProfileRevision,
		ModelID: ocr.ModelID, ModelRevision: ocr.ModelRevision, ModelArtifactHash: ocr.ArtifactHash,
		OCRProfileRevision: ocr.ProfileRevision, AnchorKind: "OCR", Page: fragment.Page,
		TokenStartOrdinal: fragment.TokenStartOrdinal, TokenEndOrdinal: fragment.TokenEndOrdinal,
		TokenCount: len(fragment.Tokens),
	}
	raw, err := jsonv2.Marshal(meta)
	if err != nil {
		return nil, failure("INGEST_METADATA", err)
	}
	return raw, nil
}

// emailFragmentMetadata is the opaque per-fragment metadata for an EMAIL anchor:
// the parser profile revision, the MIME part path and the UTF-8 byte range within
// that part's canonical text.
func emailFragmentMetadata(parserRevision, mimePart string, byteStart, byteEnd int) ([]byte, error) {
	raw, err := jsonv2.Marshal(struct {
		ParserProfileRevision string `json:"parser_profile_revision"`
		MIMEPart              string `json:"mime_part"`
		TextStart             int    `json:"text_start"`
		TextEnd               int    `json:"text_end"`
	}{ParserProfileRevision: parserRevision, MIMEPart: mimePart, TextStart: byteStart, TextEnd: byteEnd})
	if err != nil {
		return nil, failure("INGEST_METADATA", err)
	}
	return raw, nil
}
