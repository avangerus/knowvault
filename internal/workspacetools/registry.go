// Package workspacetools is the single registry of the workspace knowledge tool
// set of R3a-1, plus ADR-0098's workspace model context tool. It is the
// product's canonical contract for the tool names, compatibility aliases,
// service-principal exposure and tools/list mount gating of knowvault_search,
// knowvault_read, knowvault_list_objects, knowvault_related, knowvault_grep,
// knowvault_sources, knowvault_refresh, knowvault_workspace_context and,
// per ADR-0097, knowvault_source_schema and knowvault_source_sql.
//
// The registry is deliberately transport-free: it carries identifiers and
// dispatch kinds, never an HTTP handler, so the MCP adapter and the REST parity
// routes both resolve the same tool through the same table and neither surface
// can drift from the other on an advertised name, an alias or a denial.
//
// The tool set is KnowVault's own (owner decision 12.09.2026): the table below
// contains no wiki-rag tool name, so no former name is advertised or dispatched.
package workspacetools

// Kind identifies the one implementation that serves a knowledge tool. The
// adapter maps a kind onto the shared workspace implementation; two tool names
// (a canonical name and a compatibility alias) that carry the same kind reach
// the byte-identical core.
type Kind string

const (
	KindSearch      Kind = "search"
	KindRead        Kind = "read"
	KindListObjects Kind = "list_objects"
	KindRelated     Kind = "related"
	KindGrep        Kind = "grep"
	KindSources     Kind = "sources"
	KindRefresh     Kind = "refresh"
	// KindWorkspaceContext is ADR-0098's workspace model context tool
	// (knowvault_workspace_context): the workspace's explicit description,
	// answer rules, glossary and enabled-source notes, rendered as context
	// only -- never evidence, and never a change to the tool catalog, a
	// grant of another tool, a write or access.
	KindWorkspaceContext Kind = "workspace_context"
	// KindSourceSchema is ADR-0097's read-only source schema tool
	// (knowvault_source_schema): the tables, columns, types, primary keys and
	// row estimates of one PostgreSQL source enabled in the caller's
	// workspace, plus the source/table/column notes of the workspace model
	// context. It reads stored projections and discovery metadata only; it
	// never opens the source database, never runs SQL and never exposes a
	// column excluded at registration.
	KindSourceSchema Kind = "source_schema"
	// KindSourceSQL is ADR-0097's agent-authored read-only SQL tool
	// (knowvault_source_sql): one SELECT/WITH statement written by the agent
	// against one PostgreSQL source enabled in the caller's workspace. It runs
	// with the source's own query credential in a read-only transaction, under
	// the shared governed-execution limits, and the planner's own relations
	// are walked against the source's registered scope. It is the only
	// workspace knowledge tool that executes SQL, and it does so through the
	// one governedquery execution path; no other package gains that
	// capability.
	KindSourceSQL Kind = "source_sql"
)

// Capability names the optional mounted evidence capability a dynamic tool needs
// before it may be mounted on tools/list. A tool with an empty capability is
// part of the always-present catalogue.
type Capability string

const (
	CapabilitySearch  Capability = "search"
	CapabilityRelated Capability = "related"
	CapabilityGrep    Capability = "grep"
)

// Tool is one entry of the workspace knowledge tool set.
type Tool struct {
	// Kind is the shared implementation this entry resolves to.
	Kind Kind
	// Name is the canonical advertised tools/list name.
	Name string
	// RESTPath is the tools/{segment} subpath of the workspace REST parity of
	// this entry (GET/POST /workspaces/{workspace_id}/tools/{RESTPath}). It is
	// deliberately distinct from Name: the REST surface and the MCP surface are
	// two addressings of the one registry entry, so resolving either form lands
	// on the same Tool and thus the same Kind.
	RESTPath string
	// Aliases are the dispatch-only former names. They resolve through Lookup to
	// the same entry, are never advertised, and reach the identical core.
	Aliases []string
	// Service reports whether a SERVICE (external agent) principal may invoke the
	// tool. Every R3a-1 knowledge tool is service-visible; an administrative tool
	// is not registered here at all.
	Service bool
	// Capability, when non-empty, makes the tool a dynamic addition to tools/list
	// gated on the mounted evidence capability of that name.
	Capability Capability
}

// Registry is an immutable lookup table built once from the canonical set. It is
// read-only after construction, so tools/list and tools/call cannot be mutated
// into "shown but refused" or "hidden but callable".
type Registry struct {
	ordered []Tool
	byName  map[string]Tool
	byREST  map[string]Tool
}

// New builds a registry from the given tools. A canonical name and every alias
// resolve to the same entry; the REST subpath resolves to that same entry.
func New(tools []Tool) *Registry {
	registry := &Registry{
		ordered: append([]Tool(nil), tools...),
		byName:  make(map[string]Tool, len(tools)*2),
		byREST:  make(map[string]Tool, len(tools)),
	}
	for _, tool := range tools {
		if tool.Name != "" {
			registry.byName[tool.Name] = tool
		}
		if tool.RESTPath != "" {
			registry.byREST[tool.RESTPath] = tool
		}
		for _, alias := range tool.Aliases {
			if alias != "" {
				registry.byName[alias] = tool
			}
		}
	}
	return registry
}

// LookupREST resolves a tools/{segment} REST subpath to its entry, so the REST
// parity surface and the MCP surface cannot drift on which implementation,
// name or kind a tool resolves to. An unknown segment reports false, so the
// caller keeps its existing content-free NOT_FOUND for a segment no knowledge
// tool owns.
func (registry *Registry) LookupREST(segment string) (Tool, bool) {
	if registry == nil {
		return Tool{}, false
	}
	tool, ok := registry.byREST[segment]
	return tool, ok
}

// Lookup resolves a canonical name or a compatibility alias to its entry. An
// unknown name reports false so the caller can keep its existing content-free
// refusal for a name no knowledge tool owns.
func (registry *Registry) Lookup(name string) (Tool, bool) {
	if registry == nil {
		return Tool{}, false
	}
	tool, ok := registry.byName[name]
	return tool, ok
}

// Knowledge reports whether name is any registered knowledge tool, canonical or
// alias.
func (registry *Registry) Knowledge(name string) bool {
	_, ok := registry.Lookup(name)
	return ok
}

// ServiceKnowledge reports whether name is a registered knowledge tool that a
// SERVICE principal may invoke.
func (registry *Registry) ServiceKnowledge(name string) bool {
	tool, ok := registry.Lookup(name)
	return ok && tool.Service
}

// Tools returns the ordered canonical tool set (canonical names only).
func (registry *Registry) Tools() []Tool {
	if registry == nil {
		return nil
	}
	return append([]Tool(nil), registry.ordered...)
}

// Dynamic returns the ordered subset of tools that tools/list adds only when the
// matching optional evidence capability is mounted, in registration order.
func (registry *Registry) Dynamic() []Tool {
	if registry == nil {
		return nil
	}
	dynamic := make([]Tool, 0, len(registry.ordered))
	for _, tool := range registry.ordered {
		if tool.Capability != "" {
			dynamic = append(dynamic, tool)
		}
	}
	return dynamic
}

// Len returns the number of registered canonical tools.
func (registry *Registry) Len() int {
	if registry == nil {
		return 0
	}
	return len(registry.ordered)
}

// knowledgeTools is the one canonical R3a-1 workspace knowledge tool set. The
// canonical advertised names and the dispatch-only compatibility names (former
// advertised names kept callable for pinned clients) live here, so the MCP
// adapter and the REST parity surface resolve the same table.
var knowledgeTools = New([]Tool{
	{Kind: KindSearch, Name: "knowvault_search", RESTPath: "search", Service: true, Capability: CapabilitySearch},
	{Kind: KindRead, Name: "knowvault_read", RESTPath: "read", Aliases: []string{"knowvault_evidence_read"}, Service: true},
	{Kind: KindListObjects, Name: "knowvault_list_objects", RESTPath: "list-objects", Aliases: []string{"knowvault_workspace_list"}, Service: true},
	{Kind: KindRelated, Name: "knowvault_related", RESTPath: "related", Service: true, Capability: CapabilityRelated},
	{Kind: KindGrep, Name: "knowvault_grep", RESTPath: "grep", Service: true, Capability: CapabilityGrep},
	{Kind: KindSources, Name: "knowvault_sources", RESTPath: "sources", Aliases: []string{"knowvault_sources_list"}, Service: true},
	{Kind: KindRefresh, Name: "knowvault_refresh", RESTPath: "refresh", Service: true},
	{Kind: KindWorkspaceContext, Name: "knowvault_workspace_context", RESTPath: "workspace-context", Service: true},
	{Kind: KindSourceSchema, Name: "knowvault_source_schema", RESTPath: "source-schema", Service: true},
	{Kind: KindSourceSQL, Name: "knowvault_source_sql", RESTPath: "source-sql", Service: true},
})

// KnowledgeTools returns the canonical R3a-1 workspace knowledge tool registry.
func KnowledgeTools() *Registry {
	return knowledgeTools
}
