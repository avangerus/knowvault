package repository

// P10a: authorized member-candidate lookup.
//
// GET /api/v1/workspaces/{workspace_id}/member-candidates?q=<text> reads real
// ACTIVE USER principal records of the caller's own organization and returns a
// bounded, deterministic candidate list (principal_id + display_name) so the
// member UI can add members by display name instead of guessing principal ids.
//
// Only a caller who may manage this workspace's members (an effective OWNER or
// MANAGER of an ACTIVE workspace — the same OperationWorkspaceManage gate the
// AddMember mutation already uses) may search. A MEMBER/VIEWER/AUDITOR caller,
// a revoked/inactive actor, an inactive organization, or a revoked or archived
// workspace all resolve to the same content-free CodeNotFound with no
// existence or role oracle. The search never mutates membership and never
// returns credentials, email, external identity links, inactive/service/group
// principals or principals of any other tenant.

import (
	"context"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/policy"
	"knowvault.local/verified-workspace/internal/workspace"
)

// memberCandidateLimit is the only page boundary the candidate surface offers.
// The transport route accepts no paging parameter, so the server constant is
// the cap and reading one row beyond it turns the boundary into truthful
// truncation data.
const memberCandidateLimit = 20

// memberCandidateQueryMinRunes / memberCandidateQueryMaxRunes bound the search
// term after trim, in Unicode code points. A term outside this range is
// REQUEST_INVALID before any tenant read.
const (
	memberCandidateQueryMinRunes = 2
	memberCandidateQueryMaxRunes = 100
)

// MemberCandidate is one searchable active USER principal of the caller's own
// organization. It carries no credentials, email, external identity link or
// membership role — only the two display surfaces the member picker needs.
type MemberCandidate struct {
	PrincipalID   string
	DisplayName   string
	AlreadyMember bool
}

// MemberCandidateResult is the bounded search page. Truncated is true only
// when more matching candidates existed beyond the returned limit.
type MemberCandidateResult struct {
	Candidates []MemberCandidate
	Truncated  bool
}

// MemberCandidates resolves the caller's manage authorization for the target
// workspace and returns up to memberCandidateLimit current ACTIVE USER
// principals of the caller's own organization whose id or display name
// contains the literal query (case-insensitive, LIKE metacharacters escaped so
// the term is a literal, never a pattern). Current members are included so the
// UI can disable duplicate adds via AlreadyMember. Deterministic ordering and
// truthful truncation keep the picker stable and bounded.
func (store *Store) MemberCandidates(ctx context.Context, access database.AccessContext, workspaceID, query string) (MemberCandidateResult, error) {
	if store == nil || store.database == nil || access.Validate() != nil || !validID(workspaceID) || !validMemberCandidateQuery(query) {
		return MemberCandidateResult{}, &Error{code: CodeRequestInvalid}
	}
	result := MemberCandidateResult{Candidates: []MemberCandidate{}}
	denied := false
	err := store.database.Read(ctx, access, func(transactionContext context.Context, transaction database.Transaction) error {
		subject, organization, found, actorErr := currentActor(transactionContext, transaction, access, false)
		if actorErr != nil {
			return actorErr
		}
		if !found || organization.Status != policy.OrganizationActive {
			denied = true
			return nil
		}
		target, exists, targetErr := loadJournalTarget(transactionContext, transaction, access.OrganizationID, workspaceID)
		if targetErr != nil {
			return targetErr
		}
		if !exists {
			denied = true
			return nil
		}
		probe := workspace.Snapshot{OrganizationID: target.OrganizationID, ID: target.ID, Status: target.Status, Members: target.Members}
		decision := policy.EvaluateWorkspace(policy.Request{
			Operation: policy.OperationWorkspaceManage, Subject: subject,
			Workspace:  policy.Workspace{OrganizationID: target.OrganizationID, ID: target.ID, Status: policy.WorkspaceStatus(target.Status)},
			Membership: currentMembership(probe, access.PrincipalID),
		})
		if !decision.Allowed {
			denied = true
			return nil
		}

		pattern := "%" + escapeLikePattern(strings.TrimSpace(query)) + "%"
		rows, queryErr := transaction.Query(transactionContext, `
			SELECT principal.id, principal.display_name,
			       EXISTS (
			           SELECT 1 FROM public.workspace_member AS member
			           WHERE member.organization_id = principal.organization_id
			             AND member.workspace_id = $2
			             AND member.principal_id = principal.id
			             AND member.removed_at IS NULL
			       ) AS already_member
			FROM public.principal AS principal
			WHERE principal.organization_id = $1
			  AND principal.type = 'USER'
			  AND principal.status = 'ACTIVE'
			  AND (principal.id ILIKE $3 OR principal.display_name ILIKE $3)
			ORDER BY principal.id
			LIMIT $4
		`, access.OrganizationID, target.ID, pattern, memberCandidateLimit+1)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var candidate MemberCandidate
			if scanErr := rows.Scan(&candidate.PrincipalID, &candidate.DisplayName, &candidate.AlreadyMember); scanErr != nil {
				return scanErr
			}
			result.Candidates = append(result.Candidates, candidate)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return rowsErr
		}
		if len(result.Candidates) > memberCandidateLimit {
			result.Candidates = result.Candidates[:memberCandidateLimit]
			result.Truncated = true
		}
		return nil
	})
	if err != nil {
		if CodeOf(err) == CodePersistence {
			return MemberCandidateResult{}, err
		}
		return MemberCandidateResult{}, &Error{code: CodePersistence, cause: err}
	}
	if denied {
		return MemberCandidateResult{}, &Error{code: CodeNotFound}
	}
	return result, nil
}

// validMemberCandidateQuery accepts a literal search term whose trimmed length
// is 2..100 Unicode characters. The boundary is evaluated after trimming, so
// surrounding whitespace never lets a too-short term through nor counts toward
// the upper bound.
func validMemberCandidateQuery(query string) bool {
	trimmed := strings.TrimSpace(query)
	if trimmed == "" {
		return false
	}
	runes := utf8.RuneCountInString(trimmed)
	return runes >= memberCandidateQueryMinRunes && runes <= memberCandidateQueryMaxRunes
}

// escapeLikePattern escapes PostgreSQL LIKE metacharacters so the caller's term
// is matched literally (a percent or underscore in the term cannot widen the
// match). The backslash must be escaped first because it is LIKE's default
// escape character.
func escapeLikePattern(value string) string {
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `%`, `\%`)
	escaped = strings.ReplaceAll(escaped, `_`, `\_`)
	return escaped
}
