// This file is S2 card C's (MCP/tool-parity) chat-side extension point for
// the workspace_context knowledge tool (ADR-0098,
// S2-MODEL-CONTEXT-DESIGN.md "MCP", S2-CONTRACT.md "Tool parity"/"MCP").
//
// knowvault_workspace_context needs no chat-specific dispatch code here: like
// every other internal/workspacetools registry entry, the chat's tool loop
// reaches it through the workspacetools.Runtime it already holds
// (Service.tools, wired by EnableToolLoop in tool_loop.go, card B) --
// production wires that Runtime to internal/platform/workspaceapi's Handler,
// whose Invoke (that package's own tool_runtime.go) dispatches by registry
// Kind through the identical mcpKnowledgeToolCall core the MCP transport
// uses. A canonical name resolved through one shared
// internal/workspacetools.Registry entry cannot drift between MCP, REST tool
// parity and the chat tool runtime by construction, so a second
// implementation is deliberately not added in this package.
//
// What is chat-package-shaped, and does not require touching tool_loop.go or
// service.go (both card B's), is a content-free audit sink for a
// workspace-context read reached any of those three ways.
// S2-MODEL-CONTEXT-DESIGN.md "Audit (content-free)" names
// workspace.model_context_read, but that action does not exist yet in
// internal/audit (card A adds it) and this card must not edit store/audit.
// WorkspaceContextReadAuditHook is therefore a nil-safe, clearly-named
// extension point: composition (composition/runtime.go) installs it once the
// action exists, typically with a closure that calls audit.Record with
// ActionWorkspaceModelContextRead, ResourceType WORKSPACE_MODEL_CONTEXT and
// no document content. internal/platform/workspaceapi calls
// ObserveWorkspaceContextRead after every successful read in its shared
// workspaceContextToolResult core (tools_rest.go), which MCP, REST tool
// parity and (transitively, through Handler.Invoke) the chat tool runtime
// all dispatch through, so one installed hook covers all three surfaces
// identically and a read is never audited twice.
package question

import (
	"context"

	"knowvault.local/verified-workspace/internal/platform/database"
)

// WorkspaceContextReadTrace is what one knowvault_workspace_context /
// tools/workspace-context read hands to WorkspaceContextReadAuditHook. It
// carries no document text: only the workspace read and the pinned version
// workspacecontext.Reader.Current resolved.
type WorkspaceContextReadTrace struct {
	WorkspaceID string
	Version     int64
}

// workspaceContextReadAuditHook is nil until SetWorkspaceContextReadAuditHook
// installs one; ObserveWorkspaceContextRead is then a safe no-op, exactly
// like every other optional capability in this product staying content-free
// SERVICE_UNAVAILABLE (or, here, silently unaudited) until composition wires
// it.
var workspaceContextReadAuditHook func(ctx context.Context, access database.AccessContext, trace WorkspaceContextReadTrace)

// SetWorkspaceContextReadAuditHook installs the content-free audit sink for
// every knowvault_workspace_context / tools/workspace-context read, across
// MCP, REST tool parity and the chat tool runtime alike. See the package
// file doc for the intended composition wiring. Passing nil restores the
// no-op default.
func SetWorkspaceContextReadAuditHook(hook func(ctx context.Context, access database.AccessContext, trace WorkspaceContextReadTrace)) {
	workspaceContextReadAuditHook = hook
}

// ObserveWorkspaceContextRead reports one successful workspace-context read
// to the installed audit hook, if any. It never blocks or fails the read
// that reports it: a nil hook is a no-op, and the hook itself is expected to
// be as cheap and reliable as any other audit emission (it runs inline,
// unlike the deterministic proposer's own best-effort RunObserver).
func ObserveWorkspaceContextRead(ctx context.Context, access database.AccessContext, workspaceID string, version int64) {
	if workspaceContextReadAuditHook == nil {
		return
	}
	workspaceContextReadAuditHook(ctx, access, WorkspaceContextReadTrace{WorkspaceID: workspaceID, Version: version})
}
