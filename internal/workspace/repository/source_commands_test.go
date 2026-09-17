package repository

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/workspace"
)

func TestSourceCommandHashesUseV2AndBindRemoveLineage(t *testing.T) {
	t.Parallel()

	request := sourceRemoveFixture()
	actual, err := removeSourceCommandHash(request)
	if err != nil {
		t.Fatalf("remove source hash: %v", err)
	}
	payload := sourceCommandPayload{
		WorkspaceID: request.WorkspaceID, ExpectedWorkspaceRevision: request.ExpectedWorkspaceRevision,
		ExpectedConfigurationHash: request.ExpectedConfigurationHash, SourceScopeID: request.SourceScopeID,
		SourceScopeRevision: request.SourceScopeRevision, ScopeConfigHash: request.ScopeConfigHash,
		AccessMode: string(request.AccessMode), WorkspaceSourceID: request.WorkspaceSourceID,
	}
	v2, err := canonicalCommandHashWithVersion("workspace-command-v2", operationSourceRemove, payload)
	if err != nil || actual != v2 {
		t.Fatalf("source command did not use exact v2 envelope: actual=%q want=%q err=%v", actual, v2, err)
	}
	v1, err := canonicalCommandHashWithVersion("workspace-command-v1", operationSourceRemove, payload)
	if err != nil || actual == v1 {
		t.Fatal("source command silently reused the gate-v1 envelope")
	}

	changed := request
	changed.WorkspaceSourceID = "binding_01ARZ3NDEKTSV4RRFFQ69G5FAW"
	changedHash, err := removeSourceCommandHash(changed)
	if err != nil || changedHash == actual {
		t.Fatal("remove hash did not bind the client-visible stable binding ID")
	}
	add := AddSourceRequest{
		WorkspaceID: request.WorkspaceID, ExpectedWorkspaceRevision: request.ExpectedWorkspaceRevision,
		ExpectedConfigurationHash: request.ExpectedConfigurationHash, SourceScopeID: request.SourceScopeID,
		SourceScopeRevision: request.SourceScopeRevision, ScopeConfigHash: request.ScopeConfigHash, AccessMode: request.AccessMode,
	}
	addHash, err := addSourceCommandHash(add)
	if err != nil || addHash == actual {
		t.Fatal("typed add/remove operations shared a canonical command identity")
	}
}

func TestAddingSourceV2DoesNotChangeWorkspaceV1Hash(t *testing.T) {
	t.Parallel()

	actual, err := createCommandHash(CreateRequest{Name: "Alpha", RetentionPolicyID: "ret_default"})
	const expected = "sha256:22864adf07e0d4b91f883b0c2abf092c7ffed6fd2f043acb6ab9859a7b4a9e79"
	if err != nil || actual != expected {
		t.Fatalf("workspace-command-v1 golden drifted: actual=%q err=%v", actual, err)
	}
}

func TestSourceGateV2IntentRequiresEveryExactField(t *testing.T) {
	t.Parallel()

	request := sourceRemoveFixture()
	source := sourceCommandIntent{
		ExpectedWorkspaceRevision: request.ExpectedWorkspaceRevision,
		ExpectedConfigurationHash: request.ExpectedConfigurationHash,
		WorkspaceSourceID:         request.WorkspaceSourceID, SourceScopeID: request.SourceScopeID,
		SourceScopeRevision: request.SourceScopeRevision, ScopeConfigHash: request.ScopeConfigHash,
		AccessMode: request.AccessMode,
	}
	intent := commandIntent{
		Operation: operationSourceRemove, WorkspaceID: request.WorkspaceID,
		ResourceType: audit.ResourceWorkspaceSource, ResourceID: request.WorkspaceSourceID, Source: &source,
	}
	operation, resourceType := string(operationSourceRemove), string(audit.ResourceWorkspaceSource)
	workspaceID, resourceID := request.WorkspaceID, request.WorkspaceSourceID
	projection := sourceReceiptFixture(source)
	if !intent.matches(2, operation, &workspaceID, nil, nil, &resourceType, &resourceID, projection) {
		t.Fatal("exact gate-v2 source intent did not match")
	}
	if intent.matches(1, operation, &workspaceID, nil, nil, &resourceType, &resourceID, projection) {
		t.Fatal("source intent accepted gate-v1 receipt")
	}

	mutations := []struct {
		name   string
		mutate func(*sourceCommandReceiptProjection)
	}{
		{"workspace revision", func(value *sourceCommandReceiptProjection) { *value.ExpectedWorkspaceRevision++ }},
		{"workspace hash", func(value *sourceCommandReceiptProjection) { *value.ExpectedConfigurationHash = hashOf("c") }},
		{"binding", func(value *sourceCommandReceiptProjection) {
			*value.WorkspaceSourceID = "binding_01ARZ3NDEKTSV4RRFFQ69G5FAW"
		}},
		{"scope", func(value *sourceCommandReceiptProjection) { *value.SourceScopeID = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAW" }},
		{"scope revision", func(value *sourceCommandReceiptProjection) { *value.SourceScopeRevision++ }},
		{"scope hash", func(value *sourceCommandReceiptProjection) { *value.ScopeConfigHash = hashOf("d") }},
		{"access mode", func(value *sourceCommandReceiptProjection) { *value.AccessMode = string(SourceAccessWorkspaceManaged) }},
	}
	for _, testCase := range mutations {
		t.Run(testCase.name, func(t *testing.T) {
			changed := sourceReceiptFixture(source)
			testCase.mutate(&changed)
			if intent.matches(2, operation, &workspaceID, nil, nil, &resourceType, &resourceID, changed) {
				t.Fatalf("source intent accepted changed %s", testCase.name)
			}
		})
	}
}

func TestStableWorkspaceSourceIDIsScopeStableAndClosed(t *testing.T) {
	t.Parallel()

	first := stableWorkspaceSourceID("org_alpha", "ws_alpha", "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if first != stableWorkspaceSourceID("org_alpha", "ws_alpha", "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV") ||
		!validStage2SourceID(first, "binding_") {
		t.Fatalf("unstable or non-closed binding ID: %q", first)
	}
	if first == stableWorkspaceSourceID("org_alpha", "ws_beta", "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV") ||
		first == stableWorkspaceSourceID("org_alpha", "ws_alpha", "scope_01ARZ3NDEKTSV4RRFFQ69G5FAW") ||
		first == stableWorkspaceSourceID("org_beta", "ws_alpha", "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV") {
		t.Fatal("binding lineage was not tenant/workspace/scope scoped")
	}
	for _, invalid := range []string{
		"binding_81ARZ3NDEKTSV4RRFFQ69G5FAV", // overflow symbol
		"binding_01ARZ3NDEKTSV4RRFFQ69G5FAI", // excluded I
		"binding_01arz3ndektsv4rrffq69g5fav", // lowercase alias
		"binding_short",
	} {
		if validStage2SourceID(invalid, "binding_") {
			t.Fatalf("accepted non-canonical binding ID %q", invalid)
		}
	}
}

func TestSourceProjectionAddDisableAndReenableReusesLineage(t *testing.T) {
	t.Parallel()

	request := sourceMutationFixture(true)
	current := sourceCommandWorkspaceFixture()
	next, sources, createLineage, err := nextSourceProjection(current, nil, request)
	if err != nil || !createLineage || len(sources) != 1 || !sources[0].Enabled || sources[0].WorkspaceSourceID != request.WorkspaceSourceID {
		t.Fatalf("initial add next=%#v sources=%#v create=%v err=%v", next, sources, createLineage, err)
	}

	disable := request
	disable.Enabled = false
	disable.ExpectedWorkspaceRevision = next.Revision
	disable.ExpectedConfigurationHash, _ = workspace.ConfigurationHash(next)
	disabled, disabledSources, createLineage, err := nextSourceProjection(next, sources, disable)
	if err != nil || createLineage || len(disabledSources) != 1 || disabledSources[0].Enabled || disabledSources[0].WorkspaceSourceID != request.WorkspaceSourceID {
		t.Fatalf("disable sources=%#v create=%v err=%v", disabledSources, createLineage, err)
	}

	// A new Add command has a new idempotency key, but the stable binding is
	// scope-derived rather than key-derived and therefore reuses the lineage.
	reenable := request
	reenable.IdempotencyKey = "a-different-idempotency-key"
	reenable.ExpectedWorkspaceRevision = disabled.Revision
	reenable.ExpectedConfigurationHash, _ = workspace.ConfigurationHash(disabled)
	reenabled, reenabledSources, createLineage, err := nextSourceProjection(disabled, disabledSources, reenable)
	if err != nil || createLineage || len(reenabledSources) != 1 || !reenabledSources[0].Enabled ||
		reenabledSources[0].WorkspaceSourceID != request.WorkspaceSourceID || reenabled.Revision != current.Revision+3 {
		t.Fatalf("re-enable sources=%#v create=%v err=%v", reenabledSources, createLineage, err)
	}
}

func TestSourceProjectionRejectsAlreadyStateAndTupleSubstitution(t *testing.T) {
	t.Parallel()

	request := sourceMutationFixture(true)
	current := sourceCommandWorkspaceFixture()
	next, sources, _, err := nextSourceProjection(current, nil, request)
	if err != nil {
		t.Fatalf("fixture add: %v", err)
	}
	request.ExpectedWorkspaceRevision = next.Revision
	request.ExpectedConfigurationHash, _ = workspace.ConfigurationHash(next)
	if _, _, _, err := nextSourceProjection(next, sources, request); CodeOf(err) != CodeRevisionConflict {
		t.Fatalf("already enabled code=%q err=%v", CodeOf(err), err)
	}

	for name, mutate := range map[string]func(*sourceMutationRequest){
		"binding":        func(value *sourceMutationRequest) { value.WorkspaceSourceID = "binding_01ARZ3NDEKTSV4RRFFQ69G5FAW" },
		"scope revision": func(value *sourceMutationRequest) { value.SourceScopeRevision++ },
		"scope hash":     func(value *sourceMutationRequest) { value.ScopeConfigHash = hashOf("f") },
		"access mode":    func(value *sourceMutationRequest) { value.AccessMode = SourceAccessWorkspaceManaged },
	} {
		t.Run(name, func(t *testing.T) {
			remove := request
			remove.Enabled = false
			mutate(&remove)
			if _, _, _, err := nextSourceProjection(next, sources, remove); err == nil {
				t.Fatalf("accepted %s substitution", name)
			}
		})
	}
}

func TestSourceRequestValidationIsClosed(t *testing.T) {
	t.Parallel()

	request := sourceMutationFixture(true)
	if !validSourceRequest(request.WorkspaceID, request.ExpectedWorkspaceRevision, request.ExpectedConfigurationHash,
		request.SourceScopeID, request.SourceScopeRevision, request.ScopeConfigHash, request.AccessMode) {
		t.Fatal("valid exact source request rejected")
	}
	for name, valid := range map[string]bool{
		"zero workspace revision": validSourceRequest(request.WorkspaceID, 0, request.ExpectedConfigurationHash, request.SourceScopeID, request.SourceScopeRevision, request.ScopeConfigHash, request.AccessMode),
		"unsafe scope revision":   validSourceRequest(request.WorkspaceID, request.ExpectedWorkspaceRevision, request.ExpectedConfigurationHash, request.SourceScopeID, maxSafeInteger+1, request.ScopeConfigHash, request.AccessMode),
		"scope alias":             validSourceRequest(request.WorkspaceID, request.ExpectedWorkspaceRevision, request.ExpectedConfigurationHash, "scope_01arz3ndektsv4rrffq69g5fav", request.SourceScopeRevision, request.ScopeConfigHash, request.AccessMode),
		"unknown access":          validSourceRequest(request.WorkspaceID, request.ExpectedWorkspaceRevision, request.ExpectedConfigurationHash, request.SourceScopeID, request.SourceScopeRevision, request.ScopeConfigHash, "UNKNOWN"),
	} {
		if valid {
			t.Fatalf("accepted invalid %s", name)
		}
	}
}

func TestSourceAuthorizationTerminalHidesMissingWorkspace(t *testing.T) {
	t.Parallel()

	status, code, workspaceID := sourceAuthorizationTerminal(nil)
	if status != receiptNotFound || code != CodeNotFound || workspaceID != nil {
		t.Fatalf("hidden workspace terminal=(%q,%q,%v)", status, code, workspaceID)
	}
	visibleID := "ws_alpha"
	status, code, workspaceID = sourceAuthorizationTerminal(&visibleID)
	if status != receiptDenied || code != CodeDenied || workspaceID == nil || *workspaceID != visibleID {
		t.Fatalf("visible denied terminal=(%q,%q,%v)", status, code, workspaceID)
	}
}

func sourceReceiptFixture(source sourceCommandIntent) sourceCommandReceiptProjection {
	accessMode := string(source.AccessMode)
	return sourceCommandReceiptProjection{
		ExpectedWorkspaceRevision: &source.ExpectedWorkspaceRevision,
		ExpectedConfigurationHash: &source.ExpectedConfigurationHash,
		WorkspaceSourceID:         &source.WorkspaceSourceID, SourceScopeID: &source.SourceScopeID,
		SourceScopeRevision: &source.SourceScopeRevision, ScopeConfigHash: &source.ScopeConfigHash,
		AccessMode: &accessMode,
	}
}

func sourceRemoveFixture() RemoveSourceRequest {
	return RemoveSourceRequest{
		WorkspaceID: "ws_alpha", ExpectedWorkspaceRevision: 3, ExpectedConfigurationHash: hashOf("a"),
		WorkspaceSourceID: "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		SourceScopeID:     "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV", SourceScopeRevision: 2,
		ScopeConfigHash: hashOf("b"), AccessMode: SourceAccessSourceEnforced,
	}
}

func sourceMutationFixture(enabled bool) sourceMutationRequest {
	scopeID := "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	return sourceMutationRequest{
		WorkspaceID: "ws_alpha", ExpectedWorkspaceRevision: 1, ExpectedConfigurationHash: hashOf("a"),
		WorkspaceSourceID: stableWorkspaceSourceID("org_alpha", "ws_alpha", scopeID),
		SourceScopeID:     scopeID, SourceScopeRevision: 2, ScopeConfigHash: hashOf("b"),
		AccessMode: SourceAccessSourceEnforced, Enabled: enabled,
	}
}

func sourceCommandWorkspaceFixture() workspace.Snapshot {
	return workspace.Snapshot{
		OrganizationID: "org_alpha", ID: "ws_alpha", Revision: 1, Name: "Alpha", Status: workspace.StatusActive,
		OwnerPrincipalID: "usr_alice", Members: []workspace.Member{{PrincipalID: "usr_alice", Role: workspace.RoleOwner}},
	}
}

func hashOf(value string) string { return "sha256:" + strings.Repeat(value, 64) }
