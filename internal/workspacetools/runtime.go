package workspacetools

import (
	"context"
	"encoding/json"
	"errors"

	"knowvault.local/verified-workspace/internal/platform/database"
)

var (
	ErrUnavailable  = errors.New("workspace tools unavailable")
	ErrScopeChanged = errors.New("workspace tools scope changed")
	ErrArguments    = errors.New("invalid workspace tool arguments")
	// ErrSourceBusy reports that a workspace source's shared load limit is fully
	// taken, so a readiness check was refused instead of opening another
	// connection to that database (card D-18 result 3). The question route reads
	// it as "the database is busy right now", never as "the database cannot be
	// read".
	ErrSourceBusy = errors.New("workspace source busy")
)

// Scope is supplied by the question authority, never by model-generated args.
// Revision binds a tool turn to the run's captured authorization provenance.
type Scope struct {
	Access      database.AccessContext
	WorkspaceID string
	Revision    int64
}

type Definition struct {
	Name        string
	Description string
	Schema      json.RawMessage
}

type Result struct {
	Text       string          `json:"text"`
	Structured json.RawMessage `json:"structured,omitempty"`
	IsError    bool            `json:"is_error"`
}

// Runtime is the transport-neutral bridge to the registered implementations.
// Each invocation retains the same admission, authorization and outcome audit
// as MCP/REST. It cannot dispatch an administrative or recursive question tool.
type Runtime interface {
	Catalog(context.Context, Scope) ([]Definition, error)
	Invoke(context.Context, Scope, string, json.RawMessage) (Result, error)
}
