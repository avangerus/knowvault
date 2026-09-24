package proposer

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/workspacecontext"
)

// proposalIDPrefix is the internal/source/ids.New prefix Store mints a
// workspace_context_proposal id with, matching proposalPrefix declared next
// to workspacecontext.Proposal.Valid.
const proposalIDPrefix = "ctxprop"

// Limits from S2-MODEL-CONTEXT-DESIGN.md "Proposer": "at most 200 open
// proposals per workspace; beyond that, only counters grow" and "at most 20
// evidence rows per proposal". maxProposalsPerRun (detector.go) is the third
// limit, "at most 3 proposals per run".
const (
	maxOpenProposalsPerWorkspace = 200
	maxEvidencePerProposal       = 20
)

// systemPrincipalID is the fixed, non-human actor ObserveRun writes
// proposals as. workspacecontext.RunEvent (A0) carries no caller identity —
// a proposal is derived by the system after a run completes, never on
// behalf of a live request — so this package supplies its own
// database.AccessContext instead of trusting one it was never given. No
// workspace_context_proposal column stores it (there is no created_by
// column) and no foreign key references it; it exists only to satisfy
// database.AccessContext.Validate and RLS's tenant check. It is never an
// audit event's actor (S2-MODEL-CONTEXT-DESIGN.md's "context_proposal_
// created (actor SYSTEM)" audit event is emitted by the lead's wiring
// around this call — see this package's doc comment in proposer.go).
const systemPrincipalID = "sys_ctxproposer"

// listCap bounds every unpaginated read (List, and ListPage/Reject/Get's own
// internal reads) defensively: PROPOSED is already bounded by
// maxOpenProposalsPerWorkspace, but ACCEPTED/REJECTED/WITHDRAWN accumulate
// without a product-specified bound, and workspacecontext.ProposalService.
// List (A0, frozen) takes no limit/cursor at all.
const listCap = 500

// Store implements workspacecontext.RunObserver and
// workspacecontext.ProposalService (card A0, internal/workspacecontext/
// interfaces.go) against migration 000113. See proposer.go's package doc
// for what it depends on and the two seams (VersionMinter, RunExcerptReader)
// the lead must wire.
type Store struct {
	db       *database.Store
	reader   workspacecontext.Reader
	minter   VersionMinter
	excerpts RunExcerptReader
}

// NewStore builds a Store. db is required for every method. reader and
// minter are required only by Accept (which fails closed with CodeInternal
// if either is nil); excerpts is used only by ListPage/GetWithExamples, and
// a nil RunExcerptReader simply resolves zero examples rather than failing.
// A partially wired Store (e.g. before the lead's card-A/card-B adapters
// exist) is therefore still safe to construct and use for ObserveRun/List/
// Get/Reject.
func NewStore(db *database.Store, reader workspacecontext.Reader, minter VersionMinter, excerpts RunExcerptReader) *Store {
	return &Store{db: db, reader: reader, minter: minter, excerpts: excerpts}
}

func toDBAccess(access workspacecontext.Access) database.AccessContext {
	return database.AccessContext{
		OrganizationID: access.OrganizationID,
		PrincipalID:    access.PrincipalID,
		RequestID:      access.RequestID,
	}
}

// ObserveRun implements workspacecontext.RunObserver. Per that interface's
// contract, it must not block, retry into, or fail the run it reports on;
// its caller (card B) is expected to invoke it after the run response has
// already been returned and to route any error it returns only to a metric,
// never back to the user. A soft-cap skip (the 200-open or 20-evidence
// bound) is not an error: it returns nil.
func (store *Store) ObserveRun(ctx context.Context, event workspacecontext.RunEvent) error {
	if err := validateRunEvent(event); err != nil {
		return err
	}

	detection := Detect(event)
	access := database.AccessContext{
		OrganizationID: event.OrganizationID, PrincipalID: systemPrincipalID, RequestID: event.QuestionRunID,
	}

	return store.db.Write(ctx, access, func(ctx context.Context, tx database.Transaction) error {
		recorded := 0
		for _, candidate := range detection.Candidates {
			if recorded >= maxProposalsPerRun {
				break
			}
			proposalID, err := store.recordCandidate(ctx, tx, event, candidate)
			if err != nil {
				return err
			}
			if proposalID != "" {
				recorded++
			}
		}
		for _, token := range detection.NewTermTokens {
			if recorded >= maxProposalsPerRun {
				break
			}
			promote, err := store.recordSighting(ctx, tx, event, token)
			if err != nil {
				return err
			}
			if !promote {
				continue
			}
			proposalID, err := store.recordCandidate(ctx, tx, event, Candidate{
				Kind: workspacecontext.ProposalKindNewTerm, CandidateTerm: token,
			})
			if err != nil {
				return err
			}
			if proposalID != "" {
				recorded++
			}
		}
		return nil
	})
}

func validateRunEvent(event workspacecontext.RunEvent) error {
	if event.OrganizationID == "" || event.WorkspaceID == "" || event.QuestionRunID == "" {
		return newError(CodeInternal, errors.New("proposer: RunEvent is missing a required identifier"))
	}
	return nil
}

// recordSighting implements NEW_TERM's cross-run half: "queued after at
// least two distinct runs". It returns whether token has now been seen in
// at least two distinct runs (promote), regardless of whether this call
// itself crossed that threshold.
//
// It calls app.workspace_context_term_sighting_record (migration 000113)
// rather than reading/writing the table directly: ObserveRun runs as the
// system principal (systemPrincipalID), which is never a workspace member,
// so it cannot pass migration 000113's own OWNER/MANAGER-only RLS read
// policy on the sibling workspace_context_proposal table. This bookkeeping
// table's only reader is this method, but the SECURITY DEFINER function
// keeps every "record a detection" write on the same trusted, RLS-
// independent path as recordCandidate below.
func (store *Store) recordSighting(ctx context.Context, tx database.Transaction, event workspacecontext.RunEvent, token string) (bool, error) {
	key := foldToken(token)
	var promote bool
	if err := tx.ScanRow(ctx, `
		SELECT app.workspace_context_term_sighting_record($1, $2, $3, $4)
	`, []any{event.OrganizationID, event.WorkspaceID, key, event.QuestionRunID}, &promote); err != nil {
		return false, newError(CodeInternal, err)
	}
	return promote, nil
}

// recordCandidate dedup-bumps an existing PROPOSED proposal matching
// candidate's fold key, or creates one (subject to
// maxOpenProposalsPerWorkspace), then records evidence for event (subject to
// maxEvidencePerProposal). It returns "" (no error) when the open-proposal
// cap silently skipped creation — S2-MODEL-CONTEXT-DESIGN.md's "beyond that,
// only counters grow" is a product outcome, not a failure.
//
// It calls app.workspace_context_proposal_record (migration 000113), a
// SECURITY DEFINER function, instead of selecting/inserting/updating the
// table directly. ObserveRun's system principal (systemPrincipalID) is
// never a workspace member and migration 000113's RLS SELECT/UPDATE
// policies on workspace_context_proposal are OWNER/MANAGER-only (by
// design, for the REST list/decide surface — see that migration's own
// comments): a plain SELECT ... FOR UPDATE dedup lookup or UPDATE
// occurrences bump from this system-authored path would silently see zero
// rows under RLS even though the row exists, corrupting dedup. The function
// bypasses RLS as its owner and re-derives the only check that actually
// applies here (the caller's own tenant), which is exactly the pattern this
// codebase already uses for every other trusted, non-member-scoped write
// (e.g. app.conversation_purge_request_enqueue, app.metric_definition_*).
func (store *Store) recordCandidate(ctx context.Context, tx database.Transaction, event workspacecontext.RunEvent, candidate Candidate) (string, error) {
	key := foldToken(candidate.CandidateTerm)
	newID, idErr := ids.New(proposalIDPrefix)
	if idErr != nil {
		return "", newError(CodeInternal, idErr)
	}

	var recordedID *string
	if err := tx.ScanRow(ctx, `
		SELECT app.workspace_context_proposal_record($1, $2, $3, $4, $5, $6, $7, $8, $9)
	`, []any{
		event.OrganizationID, event.WorkspaceID, newID, string(candidate.Kind),
		candidate.CandidateTerm, key, nullIfEmpty(candidate.TargetTermID),
		nullIfEmpty(candidate.SuggestedText), DetectorVersion,
	}, &recordedID); err != nil {
		return "", newError(CodeInternal, err)
	}
	if recordedID == nil {
		return "", nil
	}
	if evErr := store.addEvidence(ctx, tx, event, *recordedID, candidate.Kind); evErr != nil {
		return "", evErr
	}
	return *recordedID, nil
}

// addEvidence records one evidence row for proposalID, subject to
// maxEvidencePerProposal, via app.workspace_context_proposal_evidence_record
// (migration 000113) for the same RLS-bypass reason as recordCandidate: the
// evidence table's own SELECT policy is OWNER/MANAGER-only, and this
// system-authored write must still count existing rows itself to enforce
// the cap. A run with no conversation/turn binding (a legacy or non-
// conversational run; question_run.conversation_id is nullable) contributes
// only to occurrences, never to evidence: an evidence row's own CHECK
// constraints require valid, non-empty ids.
func (store *Store) addEvidence(ctx context.Context, tx database.Transaction, event workspacecontext.RunEvent, proposalID string, kind workspacecontext.ProposalKind) error {
	if event.ConversationID == "" || event.TurnID == "" {
		return nil
	}
	if _, err := tx.Exec(ctx, `
		SELECT app.workspace_context_proposal_evidence_record($1, $2, $3, $4, $5, $6, $7)
	`, event.OrganizationID, event.WorkspaceID, proposalID, event.QuestionRunID, event.ConversationID, event.TurnID, string(kind)); err != nil {
		return newError(CodeInternal, err)
	}
	return nil
}

func nullIfEmpty(value string) any {
	if value == "" {
		return nil
	}
	return value
}

// List implements workspacecontext.ProposalService. It returns every
// matching row (newest first, capped at listCap) with no examples resolved
// — see ListPage for the REST/tool-parity surface that resolves them.
func (store *Store) List(ctx context.Context, access workspacecontext.Access, workspaceID string, status workspacecontext.ProposalStatus) ([]workspacecontext.Proposal, error) {
	proposals, _, err := store.listRows(ctx, access, workspaceID, status, listCap, "")
	return proposals, err
}

// ListPage is this package's own richer listing (beyond the A0
// ProposalService.List, which takes no limit/cursor and returns no
// examples): S2-CONTRACT.md's `GET .../proposals?status=&limit=&cursor=`
// needs both. It requires excerpts (NewStore) to resolve Examples; with a
// nil RunExcerptReader every ListedProposal simply has zero examples.
func (store *Store) ListPage(ctx context.Context, access workspacecontext.Access, workspaceID string, status workspacecontext.ProposalStatus, limit int, cursor string) ([]ListedProposal, string, error) {
	proposals, next, err := store.listRows(ctx, access, workspaceID, status, limit, cursor)
	if err != nil {
		return nil, "", err
	}
	listed := make([]ListedProposal, len(proposals))
	for i, proposal := range proposals {
		examples, hidden, exErr := store.resolveExamples(ctx, access, workspaceID, proposal.ID)
		if exErr != nil {
			return nil, "", exErr
		}
		listed[i] = ListedProposal{Proposal: proposal, Examples: examples, HiddenExamples: hidden}
	}
	return listed, next, nil
}

func (store *Store) listRows(ctx context.Context, access workspacecontext.Access, workspaceID string, status workspacecontext.ProposalStatus, limit int, cursor string) ([]workspacecontext.Proposal, string, error) {
	if !status.Valid() {
		return nil, "", newError(CodeInternal, fmt.Errorf("proposer: invalid status %q", status))
	}
	if limit <= 0 || limit > listCap {
		limit = listCap
	}

	var afterCreated time.Time
	var afterID string
	if cursor != "" {
		var err error
		afterCreated, afterID, err = decodeCursor(cursor)
		if err != nil {
			return nil, "", newError(CodeInternal, err)
		}
	}

	var rows []workspacecontext.Proposal
	err := store.db.Read(ctx, toDBAccess(access), func(ctx context.Context, tx database.Transaction) error {
		query := proposalSelectColumns + `
			  FROM public.workspace_context_proposal
			 WHERE organization_id = $1 AND workspace_id = $2 AND status = $3`
		args := []any{access.OrganizationID, workspaceID, string(status)}
		if cursor != "" {
			query += " AND (created_at, id) < ($4, $5)"
			args = append(args, afterCreated, afterID)
		}
		query += " ORDER BY created_at DESC, id DESC LIMIT $" + strconv.Itoa(len(args)+1)
		args = append(args, limit+1)

		result, queryErr := tx.Query(ctx, query, args...)
		if queryErr != nil {
			return newError(CodeInternal, queryErr)
		}
		defer result.Close()
		for result.Next() {
			proposal, scanErr := scanProposal(result)
			if scanErr != nil {
				return newError(CodeInternal, scanErr)
			}
			rows = append(rows, proposal)
		}
		if err := result.Err(); err != nil {
			return newError(CodeInternal, err)
		}
		return nil
	})
	if err != nil {
		return nil, "", err
	}

	var next string
	if len(rows) > limit {
		last := rows[limit-1]
		next = encodeCursor(last.CreatedAt, last.ID)
		rows = rows[:limit]
	}
	return rows, next, nil
}

// Get implements workspacecontext.ProposalService.
func (store *Store) Get(ctx context.Context, access workspacecontext.Access, workspaceID, proposalID string) (workspacecontext.Proposal, error) {
	var proposal workspacecontext.Proposal
	err := store.db.Read(ctx, toDBAccess(access), func(ctx context.Context, tx database.Transaction) error {
		var scanErr error
		proposal, scanErr = store.getLocked(ctx, tx, access.OrganizationID, workspaceID, proposalID)
		return scanErr
	})
	if err != nil {
		return workspacecontext.Proposal{}, err
	}
	return proposal, nil
}

// GetWithExamples is ListPage's single-proposal counterpart, for `GET
// .../proposals/{proposal_id}`.
func (store *Store) GetWithExamples(ctx context.Context, access workspacecontext.Access, workspaceID, proposalID string) (ListedProposal, error) {
	proposal, err := store.Get(ctx, access, workspaceID, proposalID)
	if err != nil {
		return ListedProposal{}, err
	}
	examples, hidden, err := store.resolveExamples(ctx, access, workspaceID, proposalID)
	if err != nil {
		return ListedProposal{}, err
	}
	return ListedProposal{Proposal: proposal, Examples: examples, HiddenExamples: hidden}, nil
}

func (store *Store) getLocked(ctx context.Context, tx database.Transaction, organizationID, workspaceID, proposalID string) (workspacecontext.Proposal, error) {
	query := proposalSelectColumns + `
		  FROM public.workspace_context_proposal
		 WHERE organization_id = $1 AND workspace_id = $2 AND id = $3`
	row := tx.QueryRow(ctx, query, organizationID, workspaceID, proposalID)
	proposal, err := scanProposal(row)
	if database.IsNotFound(err) {
		return workspacecontext.Proposal{}, newError(CodeNotFound, err)
	}
	if err != nil {
		return workspacecontext.Proposal{}, newError(CodeInternal, err)
	}
	return proposal, nil
}

// Reject implements workspacecontext.ProposalService.
func (store *Store) Reject(ctx context.Context, access workspacecontext.Access, workspaceID, proposalID string) (workspacecontext.Proposal, error) {
	var proposal workspacecontext.Proposal
	err := store.db.Write(ctx, toDBAccess(access), func(ctx context.Context, tx database.Transaction) error {
		tag, execErr := tx.Exec(ctx, `
			UPDATE public.workspace_context_proposal
			   SET status = 'REJECTED', decided_by = $1, decided_at = transaction_timestamp()
			 WHERE organization_id = $2 AND workspace_id = $3 AND id = $4 AND status = 'PROPOSED'
		`, access.PrincipalID, access.OrganizationID, workspaceID, proposalID)
		if execErr != nil {
			return newError(CodeInternal, execErr)
		}
		if tag.RowsAffected() == 0 {
			return store.notProposedOrNotFound(ctx, tx, access.OrganizationID, workspaceID, proposalID)
		}
		var scanErr error
		proposal, scanErr = store.getLocked(ctx, tx, access.OrganizationID, workspaceID, proposalID)
		return scanErr
	})
	if err != nil {
		return workspacecontext.Proposal{}, err
	}
	return proposal, nil
}

// notProposedOrNotFound distinguishes "no such row visible to this caller"
// (CodeNotFound; RLS already denies the read the same way it denies the
// write) from "the row exists but is no longer PROPOSED" (CodeNotProposed),
// after a conditional UPDATE affected zero rows.
func (store *Store) notProposedOrNotFound(ctx context.Context, tx database.Transaction, organizationID, workspaceID, proposalID string) error {
	var status string
	err := tx.ScanRow(ctx, `
		SELECT status FROM public.workspace_context_proposal
		 WHERE organization_id = $1 AND workspace_id = $2 AND id = $3
	`, []any{organizationID, workspaceID, proposalID}, &status)
	if database.IsNotFound(err) {
		return newError(CodeNotFound, err)
	}
	if err != nil {
		return newError(CodeInternal, err)
	}
	return newError(CodeNotProposed, nil)
}

// Accept implements workspacecontext.ProposalService. It requires both a
// Reader (to read the current Document; NewStore) and a VersionMinter
// (NewStore) — see seams.go for the exact atomicity contract the minter
// must uphold.
func (store *Store) Accept(ctx context.Context, access workspacecontext.Access, workspaceID, proposalID, ifMatchHash string, edits workspacecontext.ProposalEdits) (workspacecontext.Version, error) {
	if store.reader == nil || store.minter == nil {
		return workspacecontext.Version{}, newError(CodeInternal, errors.New("proposer: Accept requires a Reader and a VersionMinter"))
	}

	proposal, err := store.Get(ctx, access, workspaceID, proposalID)
	if err != nil {
		return workspacecontext.Version{}, err
	}
	if proposal.Status != workspacecontext.ProposalStatusProposed {
		return workspacecontext.Version{}, newError(CodeNotProposed, nil)
	}

	current, err := store.reader.Current(ctx, access, workspaceID)
	if err != nil {
		return workspacecontext.Version{}, newError(CodeInternal, err)
	}
	if current.ContentHash != ifMatchHash {
		return workspacecontext.Version{}, newError(CodeIfMatchStale, nil)
	}

	edited, err := applyProposal(current.Document, proposal, edits)
	if err != nil {
		return workspacecontext.Version{}, err
	}

	decidedBy := access.PrincipalID
	organizationID := access.OrganizationID
	version, err := store.minter.MintAcceptedVersion(ctx, access, workspaceID, ifMatchHash, edited, proposalID,
		func(ctx context.Context, tx database.Transaction, mintedVersion int64) error {
			tag, execErr := tx.Exec(ctx, `
				UPDATE public.workspace_context_proposal
				   SET status = 'ACCEPTED', decided_by = $1, decided_at = transaction_timestamp(), decided_version = $2
				 WHERE organization_id = $3 AND workspace_id = $4 AND id = $5 AND status = 'PROPOSED'
			`, decidedBy, mintedVersion, organizationID, workspaceID, proposalID)
			if execErr != nil {
				return newError(CodeInternal, execErr)
			}
			if tag.RowsAffected() == 0 {
				return newError(CodeNotProposed, nil)
			}
			return nil
		},
	)
	if err != nil {
		return workspacecontext.Version{}, err
	}
	return version, nil
}

func (store *Store) resolveExamples(ctx context.Context, access workspacecontext.Access, workspaceID, proposalID string) ([]Example, int, error) {
	if store.excerpts == nil {
		return nil, 0, nil
	}

	var runIDs []string
	err := store.db.Read(ctx, toDBAccess(access), func(ctx context.Context, tx database.Transaction) error {
		result, queryErr := tx.Query(ctx, `
			SELECT DISTINCT question_run_id FROM public.workspace_context_proposal_evidence
			 WHERE organization_id = $1 AND workspace_id = $2 AND proposal_id = $3
			 ORDER BY question_run_id
		`, access.OrganizationID, workspaceID, proposalID)
		if queryErr != nil {
			return newError(CodeInternal, queryErr)
		}
		defer result.Close()
		for result.Next() {
			var id string
			if scanErr := result.Scan(&id); scanErr != nil {
				return newError(CodeInternal, scanErr)
			}
			runIDs = append(runIDs, id)
		}
		if err := result.Err(); err != nil {
			return newError(CodeInternal, err)
		}
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	if len(runIDs) == 0 {
		return nil, 0, nil
	}

	excerpts, err := store.excerpts.GetBatch(ctx, access, runIDs)
	if err != nil {
		return nil, 0, newError(CodeInternal, err)
	}

	examples := make([]Example, 0, len(excerpts))
	for _, excerpt := range excerpts {
		text := excerpt.QuestionExcerpt
		runes := []rune(text)
		if len(runes) > maxExcerptRunes {
			text = string(runes[:maxExcerptRunes])
		}
		examples = append(examples, Example{ConversationID: excerpt.ConversationID, QuestionExcerpt: text})
	}
	hidden := len(runIDs) - len(excerpts)
	if hidden < 0 {
		hidden = 0
	}
	return examples, hidden, nil
}

const proposalSelectColumns = `
	SELECT id, kind, candidate_term, target_term_id, suggested_text, status,
	       occurrences, detector_version, created_at, decided_by, decided_at, decided_version`

// rowScanner is satisfied by both pgx.Row (QueryRow) and pgx.Rows (Query),
// so scanProposal serves both Get (single row) and listRows (many rows)
// without depending on the pgx driver type directly.
type rowScanner interface {
	Scan(destinations ...any) error
}

func scanProposal(row rowScanner) (workspacecontext.Proposal, error) {
	var (
		id, kind, detectorVersion string
		candidateTerm             *string
		targetTermID              *string
		suggestedText             *string
		status                    string
		occurrences               int
		createdAt                 time.Time
		decidedBy                 *string
		decidedAt                 *time.Time
		decidedVersion            *int64
	)
	if err := row.Scan(
		&id, &kind, &candidateTerm, &targetTermID, &suggestedText, &status,
		&occurrences, &detectorVersion, &createdAt, &decidedBy, &decidedAt, &decidedVersion,
	); err != nil {
		return workspacecontext.Proposal{}, err
	}

	proposal := workspacecontext.Proposal{
		ID: id, Kind: workspacecontext.ProposalKind(kind), Status: workspacecontext.ProposalStatus(status),
		Occurrences: occurrences, DetectorVersion: detectorVersion, CreatedAt: createdAt,
	}
	if candidateTerm != nil {
		proposal.CandidateTerm = *candidateTerm
	}
	if targetTermID != nil {
		proposal.TargetTermID = *targetTermID
	}
	if suggestedText != nil {
		proposal.SuggestedText = *suggestedText
	}
	if decidedBy != nil {
		proposal.DecidedBy = *decidedBy
	}
	if decidedAt != nil {
		proposal.DecidedAt = *decidedAt
	}
	if decidedVersion != nil {
		proposal.DecidedVersion = *decidedVersion
	}
	return proposal, nil
}

// encodeCursor/decodeCursor implement listRows' opaque keyset cursor over
// (created_at, id) — the same pair its ORDER BY/WHERE use — as an
// unpadded-base64 "<rfc3339nano>|<id>" string. It is meaningful only to this
// package: S2-CONTRACT.md's `cursor` is documented as opaque.
func encodeCursor(createdAt time.Time, id string) string {
	raw := createdAt.UTC().Format(time.RFC3339Nano) + "|" + id
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func decodeCursor(cursor string) (time.Time, string, error) {
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return time.Time{}, "", fmt.Errorf("proposer: invalid cursor: %w", err)
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 || parts[1] == "" {
		return time.Time{}, "", fmt.Errorf("proposer: malformed cursor")
	}
	createdAt, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return time.Time{}, "", fmt.Errorf("proposer: invalid cursor timestamp: %w", err)
	}
	return createdAt, parts[1], nil
}
