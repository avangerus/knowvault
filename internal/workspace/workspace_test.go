package workspace

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestNormalizeAndConfigurationHashAreCanonical(t *testing.T) {
	t.Parallel()

	first := Snapshot{
		OrganizationID: "org_alpha", ID: "ws_alpha", Revision: 7,
		Name: "Cafe\u0301", Description: "\u0421\u0432\u043e\u0434\u043a\u0430", Status: StatusActive,
		OwnerPrincipalID: "usr_alice", RetentionPolicyID: "ret_default",
		Members: []Member{{PrincipalID: "usr_bob", Role: RoleMember}, {PrincipalID: "usr_alice", Role: RoleOwner}},
	}
	second := first
	second.Name = "Café"
	second.Members = []Member{{PrincipalID: "usr_alice", Role: RoleOwner}, {PrincipalID: "usr_bob", Role: RoleMember}}
	first.SourceBindings = []SourceBinding{{SourceScopeID: "scope_docs", SourceScopeRevision: 2, ScopeConfigHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Enabled: true}, {SourceScopeID: "scope_mail", SourceScopeRevision: 1, ScopeConfigHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Enabled: false}}
	second.SourceBindings = []SourceBinding{{SourceScopeID: "scope_mail", SourceScopeRevision: 1, ScopeConfigHash: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Enabled: false}, {SourceScopeID: "scope_docs", SourceScopeRevision: 2, ScopeConfigHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Enabled: true}}

	normalized, err := Normalize(first)
	if err != nil {
		t.Fatalf("Normalize(first): %v", err)
	}
	if normalized.Name != "Café" || normalized.Members[0].PrincipalID != "usr_alice" || normalized.Members[1].PrincipalID != "usr_bob" || normalized.SourceBindings[0].SourceScopeID != "scope_docs" || normalized.SourceBindings[1].SourceScopeID != "scope_mail" {
		t.Fatalf("normalized snapshot = %#v", normalized)
	}
	firstHash, err := ConfigurationHash(first)
	if err != nil {
		t.Fatalf("ConfigurationHash(first): %v", err)
	}
	secondHash, err := ConfigurationHash(second)
	if err != nil {
		t.Fatalf("ConfigurationHash(second): %v", err)
	}
	if firstHash != secondHash || len(firstHash) != len("sha256:")+64 {
		t.Fatalf("canonical hashes differ or malformed: %q / %q", firstHash, secondHash)
	}
	if !IsConfigurationHash(firstHash) || IsConfigurationHash(strings.ToUpper(firstHash)) || IsConfigurationHash("sha256:short") {
		t.Fatal("configuration hash validator accepted an alias or rejected the canonical hash")
	}
	if first.Members[0].PrincipalID != "usr_bob" {
		t.Fatal("Normalize retained or mutated caller-owned members")
	}
}

func TestCanonicalSnapshotRoundTripUsesExactJCSArtifact(t *testing.T) {
	t.Parallel()

	snapshot := Snapshot{
		OrganizationID: "org_alpha", ID: "ws_alpha", Revision: 7,
		Name: "Cafe\u0301", Description: "\u0421\u0432\u043e\u0434\u043a\u0430", Status: StatusActive,
		OwnerPrincipalID: "usr_alice", RetentionPolicyID: "ret_default",
		Members:        []Member{{PrincipalID: "usr_bob", Role: RoleMember}, {PrincipalID: "usr_alice", Role: RoleOwner}},
		SourceBindings: []SourceBinding{{SourceScopeID: "scope_docs", SourceScopeRevision: 2, ScopeConfigHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Enabled: true}},
	}
	canonical, err := CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatalf("CanonicalSnapshot: %v", err)
	}
	parsed, err := ParseCanonicalSnapshot(canonical)
	if err != nil {
		t.Fatalf("ParseCanonicalSnapshot: %v", err)
	}
	want, err := Normalize(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, want) || parsed.Name != "Café" {
		t.Fatalf("parsed snapshot = %#v, want %#v", parsed, want)
	}
	reencoded, err := CanonicalSnapshot(parsed)
	if err != nil || !bytes.Equal(canonical, reencoded) {
		t.Fatalf("re-encoded artifact changed: %q / %q / %v", canonical, reencoded, err)
	}
	firstHash, err := ConfigurationHash(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	secondHash, err := ConfigurationHash(parsed)
	if err != nil || firstHash != secondHash {
		t.Fatalf("round-trip hashes = %q / %q, err=%v", firstHash, secondHash, err)
	}
}

func TestMemberDisplayNameIsLiveProjectionOutsideConfigurationHash(t *testing.T) {
	t.Parallel()

	base := Snapshot{
		OrganizationID: "org_alpha", ID: "ws_alpha", Revision: 1, Name: "Alpha", Status: StatusActive,
		OwnerPrincipalID: "usr_alice", Members: []Member{{PrincipalID: "usr_alice", Role: RoleOwner, DisplayName: "Alice"}},
		SourceBindings: []SourceBinding{},
	}
	renamed := base
	renamed.Members = []Member{{PrincipalID: "usr_alice", Role: RoleOwner, DisplayName: "\u0410\u043b\u0438\u0441\u0430"}}

	baseHash, err := ConfigurationHash(base)
	if err != nil {
		t.Fatalf("ConfigurationHash(base): %v", err)
	}
	renamedHash, err := ConfigurationHash(renamed)
	if err != nil {
		t.Fatalf("ConfigurationHash(renamed): %v", err)
	}
	if baseHash != renamedHash {
		t.Fatalf("display-name change changed configuration hash: %q / %q", baseHash, renamedHash)
	}

	canonical, err := CanonicalSnapshot(base)
	if err != nil {
		t.Fatalf("CanonicalSnapshot(base): %v", err)
	}
	if bytes.Contains(canonical, []byte(`"display_name"`)) {
		t.Fatalf("canonical workspace configuration persisted live member display name: %s", canonical)
	}
}

func TestParseCanonicalSnapshotRejectsSubstitutedOrNonStrictJSON(t *testing.T) {
	t.Parallel()

	snapshot := Snapshot{
		OrganizationID: "org_alpha", ID: "ws_alpha", Revision: 1, Name: "Alpha", Status: StatusActive,
		OwnerPrincipalID: "usr_alice", Members: []Member{{PrincipalID: "usr_alice", Role: RoleOwner}}, SourceBindings: []SourceBinding{},
	}
	canonical, err := CanonicalSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	duplicate := bytes.Replace(canonical,
		[]byte(`"schema_version":"workspace-configuration-v1"`),
		[]byte(`"schema_version":"workspace-configuration-v1","schema_version":"workspace-configuration-v1"`), 1)
	unknown := bytes.Replace(canonical,
		[]byte(`{"description"`), []byte(`{"unknown":true,"description"`), 1)
	nonCanonicalWhitespace := append(append([]byte(nil), canonical...), '\n')
	trailingValue := append(append([]byte(nil), canonical...), []byte(`true`)...)

	for name, value := range map[string][]byte{
		"duplicate member":       duplicate,
		"unknown member":         unknown,
		"tampered noncanonical":  nonCanonicalWhitespace,
		"trailing second value":  trailingValue,
		"wrong schema":           bytes.Replace(canonical, []byte(configurationSchemaVersion), []byte(`workspace-configuration-v2`), 1),
		"unsafe I-JSON revision": bytes.Replace(canonical, []byte(`"revision":1`), []byte(`"revision":9007199254740992`), 1),
	} {
		name, value := name, value
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, parseErr := ParseCanonicalSnapshot(value); CodeOf(parseErr) != CodeInvalidSnapshot {
				t.Fatalf("ParseCanonicalSnapshot(%s) code=%q err=%v", name, CodeOf(parseErr), parseErr)
			}
		})
	}
}

func TestNormalizeRejectsAmbiguousOrUnsafeWorkspaceConfiguration(t *testing.T) {
	t.Parallel()

	valid := Snapshot{
		OrganizationID: "org_alpha", ID: "ws_alpha", Revision: 1, Name: "Alpha", Status: StatusActive,
		OwnerPrincipalID: "usr_alice", Members: []Member{{PrincipalID: "usr_alice", Role: RoleOwner}},
	}
	tests := map[string]func(*Snapshot){
		"no owner": func(snapshot *Snapshot) { snapshot.Members[0].Role = RoleMember },
		"two owners": func(snapshot *Snapshot) {
			snapshot.Members = append(snapshot.Members, Member{PrincipalID: "usr_bob", Role: RoleOwner})
		},
		"owner mismatch":              func(snapshot *Snapshot) { snapshot.OwnerPrincipalID = "usr_bob" },
		"duplicate member":            func(snapshot *Snapshot) { snapshot.Members = append(snapshot.Members, valid.Members[0]) },
		"unknown role":                func(snapshot *Snapshot) { snapshot.Members[0].Role = "ADMIN" },
		"control in description":      func(snapshot *Snapshot) { snapshot.Description = "bad\u0000value" },
		"whitespace padded name":      func(snapshot *Snapshot) { snapshot.Name = " Alpha" },
		"nonpositive revision":        func(snapshot *Snapshot) { snapshot.Revision = 0 },
		"invalid retention reference": func(snapshot *Snapshot) { snapshot.RetentionPolicyID = "ret policy" },
		"invalid source binding": func(snapshot *Snapshot) {
			snapshot.SourceBindings = []SourceBinding{{SourceScopeID: "scope_docs", SourceScopeRevision: 1, ScopeConfigHash: "sha256:not-a-hash", Enabled: true}}
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			snapshot := valid
			snapshot.Members = append([]Member(nil), valid.Members...)
			mutate(&snapshot)
			if _, err := Normalize(snapshot); CodeOf(err) != CodeInvalidSnapshot {
				t.Fatalf("Normalize error code = %q, want %q", CodeOf(err), CodeInvalidSnapshot)
			}
		})
	}
}

func TestNextRevisionMutationsPreserveImmutableConfigurationRules(t *testing.T) {
	t.Parallel()

	current := Snapshot{
		OrganizationID: "org_alpha", ID: "ws_alpha", Revision: 4, Name: "Alpha", Status: StatusActive,
		OwnerPrincipalID: "usr_alice", Members: []Member{{PrincipalID: "usr_alice", Role: RoleOwner}}, SourceBindings: []SourceBinding{},
	}
	updated, err := NextMetadata(current, "Alpha 2", "\u041e\u0431\u043d\u043e\u0432\u043b\u0435\u043d\u043e", "ret_default")
	if err != nil || updated.Revision != 5 || updated.Name != "Alpha 2" || current.Name != "Alpha" {
		t.Fatalf("NextMetadata=%#v err=%v", updated, err)
	}
	withMember, err := NextWithMember(updated, Member{PrincipalID: "usr_bob", Role: RoleViewer})
	if err != nil || withMember.Revision != 6 || len(withMember.Members) != 2 || withMember.Members[1].PrincipalID != "usr_bob" {
		t.Fatalf("NextWithMember=%#v err=%v", withMember, err)
	}
	archived, err := NextArchived(withMember)
	if err != nil || archived.Revision != 7 || archived.Status != StatusArchived {
		t.Fatalf("NextArchived=%#v err=%v", archived, err)
	}
	if _, err := NextWithMember(current, Member{PrincipalID: "usr_bob", Role: RoleOwner}); CodeOf(err) != CodeInvalidSnapshot {
		t.Fatalf("owner transfer shortcut code=%q err=%v", CodeOf(err), err)
	}
	changed, err := NextWithMemberRole(withMember, "usr_bob", RoleMember)
	if err != nil || changed.Revision != 7 || changed.Members[1].Role != RoleMember {
		t.Fatalf("NextWithMemberRole=%#v err=%v", changed, err)
	}
	transferred, err := NextOwnershipTransferred(changed, "usr_bob")
	if err != nil || transferred.Revision != 8 || transferred.OwnerPrincipalID != "usr_bob" || transferred.Members[0].Role != RoleManager || transferred.Members[1].Role != RoleOwner {
		t.Fatalf("NextOwnershipTransferred=%#v err=%v", transferred, err)
	}
	withoutAlice, err := NextWithoutMember(transferred, "usr_alice")
	if err != nil || withoutAlice.Revision != 9 || len(withoutAlice.Members) != 1 || withoutAlice.Members[0].PrincipalID != "usr_bob" {
		t.Fatalf("NextWithoutMember=%#v err=%v", withoutAlice, err)
	}
	for name, operation := range map[string]func() error{
		"remove owner":              func() error { _, err := NextWithoutMember(transferred, "usr_bob"); return err },
		"change owner role":         func() error { _, err := NextWithMemberRole(transferred, "usr_bob", RoleViewer); return err },
		"transfer to absent member": func() error { _, err := NextOwnershipTransferred(transferred, "usr_carol"); return err },
	} {
		if err := operation(); CodeOf(err) != CodeInvalidSnapshot {
			t.Fatalf("%s code=%q err=%v", name, CodeOf(err), err)
		}
	}
}

func TestNextSourceBindingEnabledAddsOrReenablesOnlyExactBinding(t *testing.T) {
	t.Parallel()

	const hashA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const hashB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	current := Snapshot{
		OrganizationID: "org_alpha", ID: "ws_alpha", Revision: 8, Name: "Alpha", Description: "Stable metadata", Status: StatusActive,
		OwnerPrincipalID: "usr_alice", RetentionPolicyID: "ret_default",
		Members:        []Member{{PrincipalID: "usr_bob", Role: RoleMember}, {PrincipalID: "usr_alice", Role: RoleOwner}},
		SourceBindings: []SourceBinding{{SourceScopeID: "scope_zeta", SourceScopeRevision: 4, ScopeConfigHash: hashB, Enabled: false}},
	}

	added, err := NextSourceBindingEnabled(current, SourceBinding{
		SourceScopeID: "scope_alpha", SourceScopeRevision: 2, ScopeConfigHash: hashA, Enabled: true,
	})
	if err != nil {
		t.Fatalf("NextSourceBindingEnabled(add): %v", err)
	}
	if added.Revision != 9 || added.Name != current.Name || added.Description != current.Description ||
		added.RetentionPolicyID != current.RetentionPolicyID || !reflect.DeepEqual(added.Members, []Member{{PrincipalID: "usr_alice", Role: RoleOwner}, {PrincipalID: "usr_bob", Role: RoleMember}}) ||
		len(added.SourceBindings) != 2 || added.SourceBindings[0].SourceScopeID != "scope_alpha" || !added.SourceBindings[0].Enabled ||
		added.SourceBindings[1].SourceScopeID != "scope_zeta" || added.SourceBindings[1].Enabled {
		t.Fatalf("added snapshot = %#v", added)
	}
	if current.Revision != 8 || len(current.SourceBindings) != 1 || current.SourceBindings[0].Enabled {
		t.Fatalf("caller-owned current mutated: %#v", current)
	}

	reenabled, err := NextSourceBindingEnabled(added, SourceBinding{
		SourceScopeID: "scope_zeta", SourceScopeRevision: 4, ScopeConfigHash: hashB, Enabled: true,
	})
	if err != nil || reenabled.Revision != 10 || !reenabled.SourceBindings[1].Enabled {
		t.Fatalf("NextSourceBindingEnabled(re-enable)=%#v err=%v", reenabled, err)
	}
	if added.SourceBindings[1].Enabled {
		t.Fatal("re-enable mutated the previous snapshot")
	}

	for name, binding := range map[string]SourceBinding{
		"already enabled":       {SourceScopeID: "scope_alpha", SourceScopeRevision: 2, ScopeConfigHash: hashA, Enabled: true},
		"revision substitution": {SourceScopeID: "scope_zeta", SourceScopeRevision: 5, ScopeConfigHash: hashB, Enabled: true},
		"hash substitution":     {SourceScopeID: "scope_zeta", SourceScopeRevision: 4, ScopeConfigHash: hashA, Enabled: true},
		"wrong desired state":   {SourceScopeID: "scope_new", SourceScopeRevision: 1, ScopeConfigHash: hashA, Enabled: false},
		"unsafe revision":       {SourceScopeID: "scope_new", SourceScopeRevision: maxIJSONInteger + 1, ScopeConfigHash: hashA, Enabled: true},
	} {
		name, binding := name, binding
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, operationErr := NextSourceBindingEnabled(added, binding); CodeOf(operationErr) != CodeInvalidSnapshot {
				t.Fatalf("code=%q err=%v", CodeOf(operationErr), operationErr)
			}
		})
	}
}

func TestNextSourceBindingDisabledRetainsOnlyExactBinding(t *testing.T) {
	t.Parallel()

	const hashA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const hashB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	current := Snapshot{
		OrganizationID: "org_alpha", ID: "ws_alpha", Revision: 11, Name: "Alpha", Status: StatusActive,
		OwnerPrincipalID: "usr_alice", Members: []Member{{PrincipalID: "usr_alice", Role: RoleOwner}, {PrincipalID: "usr_bob", Role: RoleViewer}},
		SourceBindings: []SourceBinding{
			{SourceScopeID: "scope_alpha", SourceScopeRevision: 2, ScopeConfigHash: hashA, Enabled: true},
			{SourceScopeID: "scope_zeta", SourceScopeRevision: 4, ScopeConfigHash: hashB, Enabled: true},
		},
	}

	disabled, err := NextSourceBindingDisabled(current, SourceBinding{
		SourceScopeID: "scope_alpha", SourceScopeRevision: 2, ScopeConfigHash: hashA, Enabled: false,
	})
	if err != nil || disabled.Revision != 12 || len(disabled.SourceBindings) != 2 || disabled.SourceBindings[0].Enabled || !disabled.SourceBindings[1].Enabled ||
		disabled.Name != current.Name || !reflect.DeepEqual(disabled.Members, current.Members) {
		t.Fatalf("NextSourceBindingDisabled=%#v err=%v", disabled, err)
	}
	if !current.SourceBindings[0].Enabled {
		t.Fatal("disable mutated the previous snapshot")
	}

	for name, binding := range map[string]SourceBinding{
		"absent":                {SourceScopeID: "scope_missing", SourceScopeRevision: 2, ScopeConfigHash: hashA, Enabled: false},
		"already disabled":      {SourceScopeID: "scope_alpha", SourceScopeRevision: 2, ScopeConfigHash: hashA, Enabled: false},
		"revision substitution": {SourceScopeID: "scope_zeta", SourceScopeRevision: 5, ScopeConfigHash: hashB, Enabled: false},
		"hash substitution":     {SourceScopeID: "scope_zeta", SourceScopeRevision: 4, ScopeConfigHash: hashA, Enabled: false},
		"wrong desired state":   {SourceScopeID: "scope_zeta", SourceScopeRevision: 4, ScopeConfigHash: hashB, Enabled: true},
	} {
		name, binding := name, binding
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, operationErr := NextSourceBindingDisabled(disabled, binding); CodeOf(operationErr) != CodeInvalidSnapshot {
				t.Fatalf("code=%q err=%v", CodeOf(operationErr), operationErr)
			}
		})
	}

	current.Revision = maxIJSONInteger
	if _, err := NextSourceBindingDisabled(current, SourceBinding{
		SourceScopeID: "scope_alpha", SourceScopeRevision: 2, ScopeConfigHash: hashA, Enabled: false,
	}); CodeOf(err) != CodeInvalidSnapshot {
		t.Fatalf("maximum revision code=%q err=%v", CodeOf(err), err)
	}
}
