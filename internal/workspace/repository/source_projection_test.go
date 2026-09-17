package repository

import (
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/workspace"
)

func TestSourceProjectionRequiresExactCanonicalBindingSet(t *testing.T) {
	t.Parallel()

	configurationHash := "sha256:" + strings.Repeat("a", 64)
	scopeHash := "sha256:" + strings.Repeat("b", 64)
	snapshot := sourceProjectionFixtureSnapshot(scopeHash)
	projection := sourceProjectionFixture(configurationHash, scopeHash)
	if !sourceProjectionMatchesSnapshot(projection, snapshot, configurationHash) {
		t.Fatal("exact relational projection did not match canonical source bindings")
	}

	for name, mutate := range map[string]func([]revisionSourceProjection) []revisionSourceProjection{
		"missing": func(rows []revisionSourceProjection) []revisionSourceProjection { return nil },
		"extra": func(rows []revisionSourceProjection) []revisionSourceProjection {
			return append(rows, revisionSourceProjection{
				WorkspaceConfigurationHash: configurationHash, WorkspaceSourceID: "binding_extra",
				SourceScopeID: "scope_extra", SourceScopeRevision: 1, ScopeConfigHash: scopeHash,
				AccessMode: "SOURCE_ENFORCED", Enabled: true,
			})
		},
		"configuration hash": func(rows []revisionSourceProjection) []revisionSourceProjection {
			rows[0].WorkspaceConfigurationHash = "sha256:" + strings.Repeat("c", 64)
			return rows
		},
		"binding ID": func(rows []revisionSourceProjection) []revisionSourceProjection {
			rows[0].WorkspaceSourceID = ""
			return rows
		},
		"scope ID": func(rows []revisionSourceProjection) []revisionSourceProjection {
			rows[0].SourceScopeID = "scope_other"
			return rows
		},
		"scope revision": func(rows []revisionSourceProjection) []revisionSourceProjection {
			rows[0].SourceScopeRevision++
			return rows
		},
		"scope hash": func(rows []revisionSourceProjection) []revisionSourceProjection {
			rows[0].ScopeConfigHash = "sha256:" + strings.Repeat("d", 64)
			return rows
		},
		"access mode": func(rows []revisionSourceProjection) []revisionSourceProjection {
			rows[0].AccessMode = "UNKNOWN"
			return rows
		},
		"enabled": func(rows []revisionSourceProjection) []revisionSourceProjection {
			rows[0].Enabled = false
			return rows
		},
	} {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			rows := mutate(append([]revisionSourceProjection(nil), projection...))
			if sourceProjectionMatchesSnapshot(rows, snapshot, configurationHash) {
				t.Fatalf("projection accepted mismatched %s", name)
			}
		})
	}
}

func TestEveryOrdinaryWorkspaceRevisionCarriesExactSourceProjection(t *testing.T) {
	t.Parallel()

	oldConfigurationHash := "sha256:" + strings.Repeat("a", 64)
	scopeHash := "sha256:" + strings.Repeat("b", 64)
	current := sourceProjectionFixtureSnapshot(scopeHash)
	projection := sourceProjectionFixture(oldConfigurationHash, scopeHash)

	mutations := []struct {
		name   string
		change func(workspace.Snapshot) (workspace.Snapshot, error)
	}{
		{"metadata", func(value workspace.Snapshot) (workspace.Snapshot, error) {
			return workspace.NextMetadata(value, "Renamed", "changed", "ret_default")
		}},
		{"member add", func(value workspace.Snapshot) (workspace.Snapshot, error) {
			return workspace.NextWithMember(value, workspace.Member{PrincipalID: "usr_carol", Role: workspace.RoleViewer})
		}},
		{"member role", func(value workspace.Snapshot) (workspace.Snapshot, error) {
			return workspace.NextWithMemberRole(value, "usr_bob", workspace.RoleViewer)
		}},
		{"ownership", func(value workspace.Snapshot) (workspace.Snapshot, error) {
			return workspace.NextOwnershipTransferred(value, "usr_bob")
		}},
		{"member remove", func(value workspace.Snapshot) (workspace.Snapshot, error) {
			return workspace.NextWithoutMember(value, "usr_bob")
		}},
		{"archive", workspace.NextArchived},
	}

	for _, testCase := range mutations {
		t.Run(testCase.name, func(t *testing.T) {
			next, err := testCase.change(current)
			if err != nil {
				t.Fatalf("create next revision: %v", err)
			}
			nextHash, err := workspace.ConfigurationHash(next)
			if err != nil {
				t.Fatalf("hash next revision: %v", err)
			}
			carried, valid := carrySourceProjection(projection, next, nextHash)
			if !valid || len(carried) != 1 {
				t.Fatalf("ordinary mutation did not carry projection: %#v", carried)
			}
			if carried[0].WorkspaceConfigurationHash != nextHash || carried[0].WorkspaceSourceID != projection[0].WorkspaceSourceID ||
				carried[0].AccessMode != projection[0].AccessMode || carried[0].SourceScopeID != projection[0].SourceScopeID ||
				carried[0].SourceScopeRevision != projection[0].SourceScopeRevision || carried[0].ScopeConfigHash != projection[0].ScopeConfigHash ||
				carried[0].Enabled != projection[0].Enabled {
				t.Fatalf("carried projection drifted: %#v", carried[0])
			}
			if !reflect.DeepEqual(projection, sourceProjectionFixture(oldConfigurationHash, scopeHash)) {
				t.Fatal("carry mutated the prior immutable projection")
			}
		})
	}
}

func sourceProjectionFixtureSnapshot(scopeHash string) workspace.Snapshot {
	return workspace.Snapshot{
		OrganizationID: "org_alpha", ID: "ws_alpha", Revision: 2, Name: "Alpha", Status: workspace.StatusActive,
		OwnerPrincipalID: "usr_alice",
		Members: []workspace.Member{
			{PrincipalID: "usr_alice", Role: workspace.RoleOwner},
			{PrincipalID: "usr_bob", Role: workspace.RoleManager},
		},
		SourceBindings: []workspace.SourceBinding{{
			SourceScopeID: "scope_alpha", SourceScopeRevision: 3, ScopeConfigHash: scopeHash, Enabled: true,
		}},
	}
}

func sourceProjectionFixture(configurationHash, scopeHash string) []revisionSourceProjection {
	return []revisionSourceProjection{{
		WorkspaceConfigurationHash: configurationHash,
		WorkspaceSourceID:          "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		SourceScopeID:              "scope_alpha",
		SourceScopeRevision:        3,
		ScopeConfigHash:            scopeHash,
		AccessMode:                 "SOURCE_ENFORCED",
		Enabled:                    true,
	}}
}
