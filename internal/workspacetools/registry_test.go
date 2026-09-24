package workspacetools

import "testing"

func TestKnowledgeToolSetRegistersCanonicalNames(t *testing.T) {
	registry := KnowledgeTools()
	want := []struct {
		name       string
		restPath   string
		kind       Kind
		capability Capability
		aliases    []string
	}{
		{name: "knowvault_search", restPath: "search", kind: KindSearch, capability: CapabilitySearch},
		{name: "knowvault_read", restPath: "read", kind: KindRead, aliases: []string{"knowvault_evidence_read"}},
		{name: "knowvault_list_objects", restPath: "list-objects", kind: KindListObjects, aliases: []string{"knowvault_workspace_list"}},
		{name: "knowvault_related", restPath: "related", kind: KindRelated, capability: CapabilityRelated},
		{name: "knowvault_grep", restPath: "grep", kind: KindGrep, capability: CapabilityGrep},
		{name: "knowvault_sources", restPath: "sources", kind: KindSources, aliases: []string{"knowvault_sources_list"}},
		{name: "knowvault_refresh", restPath: "refresh", kind: KindRefresh},
		{name: "knowvault_workspace_context", restPath: "workspace-context", kind: KindWorkspaceContext},
		{name: "knowvault_source_schema", restPath: "source-schema", kind: KindSourceSchema},
	}
	if registry.Len() != len(want) {
		t.Fatalf("registry has %d tools, want %d", registry.Len(), len(want))
	}
	for index, expected := range want {
		tool := registry.Tools()[index]
		if tool.Name != expected.name || tool.Kind != expected.kind || tool.Capability != expected.capability {
			t.Fatalf("tool %d = %+v, want name=%s kind=%s capability=%s", index, tool, expected.name, expected.kind, expected.capability)
		}
		if tool.RESTPath != expected.restPath {
			t.Fatalf("tool %s RESTPath = %q, want %q", tool.Name, tool.RESTPath, expected.restPath)
		}
		// The MCP name and the REST subpath must resolve to the one entry.
		restResolved, ok := registry.LookupREST(expected.restPath)
		if !ok || restResolved.Kind != expected.kind || restResolved.Name != expected.name {
			t.Fatalf("REST tools/%s resolved to %+v (ok=%v), want %s", expected.restPath, restResolved, ok, expected.name)
		}
		if !tool.Service {
			t.Fatalf("tool %s is not service-visible", tool.Name)
		}
		if len(tool.Aliases) != len(expected.aliases) {
			t.Fatalf("tool %s aliases = %v, want %v", tool.Name, tool.Aliases, expected.aliases)
		}
		for aliasIndex, alias := range expected.aliases {
			if tool.Aliases[aliasIndex] != alias {
				t.Fatalf("tool %s alias %d = %s, want %s", tool.Name, aliasIndex, tool.Aliases[aliasIndex], alias)
			}
			resolved, ok := registry.Lookup(alias)
			if !ok || resolved.Kind != expected.kind || resolved.Name != expected.name {
				t.Fatalf("alias %s resolved to %+v (ok=%v), want %s", alias, resolved, ok, expected.name)
			}
			if !registry.ServiceKnowledge(alias) {
				t.Fatalf("alias %s is not service-visible", alias)
			}
		}
	}
}

func TestKnowledgeToolRegistryRejectsUnknownNames(t *testing.T) {
	registry := KnowledgeTools()
	if _, ok := registry.Lookup("knowvault_question"); ok {
		t.Fatal("knowvault_question is not part of the R3a-1 knowledge registry")
	}
	if registry.Knowledge("knowvault_evidence_get") {
		t.Fatal("knowvault_evidence_get is not part of the R3a-1 knowledge registry")
	}
	if registry.Knowledge("knowvault_metric_definitions_list") {
		t.Fatal("an administrative tool must not be a knowledge tool")
	}
	if registry.ServiceKnowledge("knowvault_source_sync") {
		t.Fatal("an administrative tool must not be service-visible")
	}
	if _, ok := registry.LookupREST("wiki_search"); ok {
		t.Fatal("a wiki-rag name must not be a REST subpath")
	}
	if _, ok := registry.LookupREST("knowvault_search"); ok {
		t.Fatal("a canonical MCP name is not a REST subpath")
	}
}

func TestKnowledgeToolDynamicSubsetIsCapabilityGated(t *testing.T) {
	dynamic := KnowledgeTools().Dynamic()
	if len(dynamic) != 3 {
		t.Fatalf("dynamic subset has %d tools, want 3", len(dynamic))
	}
	for index, kind := range []Kind{KindSearch, KindRelated, KindGrep} {
		if dynamic[index].Kind != kind {
			t.Fatalf("dynamic[%d] = %s, want %s", index, dynamic[index].Kind, kind)
		}
	}
}
