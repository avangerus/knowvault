package proposer

import "errors"

// ErrorCode is content-free and safe for HTTP/MCP mapping, logs and audit
// metadata, mirroring workspacecontext.ErrorCode and database.ErrorCode's
// own convention.
type ErrorCode string

const (
	// CodeNotFound covers both "no such proposal" and "the caller cannot
	// currently see it" (RLS already returns no row for either): the lead's
	// REST mapping should treat both as 404, exactly as S2-CONTRACT.md's
	// "Proposals (OWNER and MANAGER only; others get 404)" requires.
	CodeNotFound ErrorCode = "WORKSPACE_CONTEXT_PROPOSAL_NOT_FOUND"
	// CodeNotProposed is returned by Accept/Reject when the proposal is no
	// longer PROPOSED (already decided, or withdrawn by a purge).
	CodeNotProposed ErrorCode = "WORKSPACE_CONTEXT_PROPOSAL_NOT_PROPOSED"
	// CodeIfMatchStale mirrors the model-context PUT/restore contract: the
	// caller's If-Match hash no longer matches the workspace's current
	// context version. The lead's REST mapping should return 412.
	CodeIfMatchStale ErrorCode = "WORKSPACE_CONTEXT_PROPOSAL_IF_MATCH_STALE"
	// CodeTargetTermMissing is returned by Accept when a SYNONYM or
	// DEFINITION_CORRECTION proposal's target_term_id no longer exists in
	// the workspace's current glossary (it was deleted by an edit made
	// after the proposal was created).
	CodeTargetTermMissing ErrorCode = "WORKSPACE_CONTEXT_PROPOSAL_TARGET_TERM_MISSING"
	// CodeInternal covers every other failure. Its cause is never exposed to
	// an untrusted caller.
	CodeInternal ErrorCode = "WORKSPACE_CONTEXT_PROPOSAL_INTERNAL"
)

// Error preserves a stable, content-free code.
type Error struct {
	code  ErrorCode
	cause error
}

func (err *Error) Error() string { return string(err.code) }
func (err *Error) Unwrap() error { return err.cause }

// CodeOf maps any error to a safe, stable proposer code.
func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeInternal
}

func newError(code ErrorCode, cause error) error { return &Error{code: code, cause: cause} }
