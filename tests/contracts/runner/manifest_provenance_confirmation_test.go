package contracts

import "testing"

func confirmationGrantFixture(t *testing.T, id string, revision int, validFrom, validUntil string) map[string]any {
	t.Helper()
	grant := map[string]any{
		"schema_version": "workspace-source-confirmation-grant-v1", "grant_id": id, "revision": float64(revision),
		"organization_id": "org_alpha", "workspace_id": "ws_alpha", "principal_id": "user_admin", "permission": "workspace.source.confirm",
		"valid_from": validFrom, "valid_until": validUntil, "policy_revision": "policy-0007", "granted_by": "user_security_admin", "granted_at": "2026-07-13T23:55:00Z",
	}
	hash, err := hashCanonical(confirmationActorGrantHashInput(grant))
	if err != nil {
		t.Fatalf("hash confirmation grant: %v", err)
	}
	grant["grant_hash"] = hash
	return grant
}

func confirmationFixture(grant map[string]any, confirmedAt string) map[string]any {
	return map[string]any{
		"confirmation_id": "wmc_projects_3", "confirmation_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"confirmed_by": "user_admin", "confirmed_at": confirmedAt, "policy_revision": "policy-0007",
		"confirmation_actor_grant_id": grant["grant_id"], "confirmation_actor_grant_revision": grant["revision"], "confirmation_actor_grant_hash": grant["grant_hash"],
	}
}

func confirmationManifestFixture() map[string]any {
	return map[string]any{"organization_id": "org_alpha", "workspace_id": "ws_alpha", "workspace_revision": float64(7)}
}

func confirmationRetrievalContext(grants ...map[string]any) map[string]any {
	items := make([]any, 0, len(grants))
	for _, grant := range grants {
		items = append(items, grant)
	}
	return map[string]any{
		"confirmation_actor_grants":                  items,
		"confirmation_actor_grant_revocations":       []any{},
		"workspace_managed_confirmation_revocations": []any{},
	}
}

func fullConfirmationFixture(t *testing.T, grant map[string]any, confirmationID, bindingID string) (map[string]any, map[string]any) {
	t.Helper()
	warningHash, err := hashCanonical(workspaceManagedWarningContract())
	if err != nil {
		t.Fatal(err)
	}
	confirmation := map[string]any{
		"schema_version": "workspace-managed-confirmation-v1", "confirmation_id": confirmationID,
		"organization_id": "org_alpha", "workspace_id": "ws_alpha", "workspace_revision": float64(7),
		"workspace_configuration_hash": "sha256:7777777777777777777777777777777777777777777777777777777777777777", "workspace_source_id": bindingID,
		"source_scope_id": "scope_projects", "source_scope_revision": float64(3), "scope_config_hash": "sha256:c2f04f0025efc3d6a652e2e75b74539d3f33b90e3f5ffea7aff3be97d1a99570",
		"access_mode": "WORKSPACE_MANAGED", "confirmation_actor_grant_id": grant["grant_id"], "confirmation_actor_grant_revision": grant["revision"], "confirmation_actor_grant_hash": grant["grant_hash"],
		"warning_version": "workspace-managed-risk-v1", "warning_contract_hash": warningHash, "acknowledgement_code": "WORKSPACE_MEMBERS_MAY_READ_WITHOUT_SOURCE_NATIVE_ACL",
		"confirmed_by": grant["principal_id"], "confirmed_at": "2026-07-14T12:00:00Z", "policy_revision": "policy-0007",
	}
	confirmationHash, err := hashCanonical(workspaceManagedConfirmationHashInput(confirmation))
	if err != nil {
		t.Fatal(err)
	}
	confirmation["confirmation_hash"] = confirmationHash
	context := confirmationRetrievalContext(grant)
	context["live_workspace_revision"] = map[string]any{
		"organization_id": "org_alpha", "workspace_id": "ws_alpha", "workspace_revision": float64(7), "status": "ACTIVE",
		"workspace_configuration_hash": confirmation["workspace_configuration_hash"],
		"bindings": []any{map[string]any{
			"organization_id": "org_alpha", "workspace_source_id": bindingID, "source_scope_id": "scope_projects", "source_scope_revision": float64(3),
			"scope_config_hash": confirmation["scope_config_hash"], "access_mode": "WORKSPACE_MANAGED", "workspace_managed_confirmation_id": confirmationID, "enabled": true,
		}},
	}
	return confirmation, context
}

func TestConfirmationActorGrantExactIdentityAuthorizes(t *testing.T) {
	grant := confirmationGrantFixture(t, "grant_admin", 7, "2026-07-14T00:00:00Z", "2026-07-15T00:00:00Z")
	context := confirmationRetrievalContext(grant)
	manifest := confirmationManifestFixture()
	if err := validateConfirmationActorGrantInventory(manifest, context); err != nil {
		t.Fatalf("valid grant inventory rejected: %v", err)
	}
	if !confirmationActorAuthorized(manifest, context, confirmationFixture(grant, "2026-07-14T12:00:00Z")) {
		t.Fatal("exact immutable actor grant did not authorize confirmation")
	}
}

func TestConfirmationActorGrantHashCoversCanonicalBody(t *testing.T) {
	grant := confirmationGrantFixture(t, "grant_admin", 7, "2026-07-14T00:00:00Z", "2026-07-15T00:00:00Z")
	grant["valid_until"] = "2026-07-16T00:00:00Z"
	if err := validateConfirmationActorGrantInventory(confirmationManifestFixture(), confirmationRetrievalContext(grant)); err == nil {
		t.Fatal("grant body substitution with stale hash was accepted")
	}
}

func TestConfirmationActorGrantReferenceCannotSubstituteRenewal(t *testing.T) {
	first := confirmationGrantFixture(t, "grant_admin", 7, "2026-07-14T00:00:00Z", "2026-07-14T12:30:00Z")
	renewal := confirmationGrantFixture(t, "grant_admin", 8, "2026-07-14T12:30:00Z", "2026-07-15T00:00:00Z")
	context := confirmationRetrievalContext(first, renewal)
	manifest := confirmationManifestFixture()
	if err := validateConfirmationActorGrantInventory(manifest, context); err != nil {
		t.Fatalf("distinct immutable grant revisions rejected: %v", err)
	}
	confirmation := confirmationFixture(first, "2026-07-14T12:00:00Z")
	confirmation["confirmation_actor_grant_revision"] = renewal["revision"]
	confirmation["confirmation_actor_grant_hash"] = renewal["grant_hash"]
	if confirmationActorAuthorized(manifest, context, confirmation) {
		t.Fatal("renewal with the same grant id substituted for the exact referenced revision")
	}
}

func TestConfirmationActorGrantRevocationIsExactKillSwitch(t *testing.T) {
	grantA := confirmationGrantFixture(t, "grant_admin_a", 1, "2026-07-14T00:00:00Z", "2026-07-15T00:00:00Z")
	grantB := confirmationGrantFixture(t, "grant_admin_b", 1, "2026-07-14T00:00:00Z", "2026-07-15T00:00:00Z")
	context := confirmationRetrievalContext(grantA, grantB)
	revocation := map[string]any{
		"schema_version": "workspace-source-confirmation-grant-revocation-v1", "revocation_id": "revoke_a", "organization_id": "org_alpha",
		"grant_id": grantA["grant_id"], "grant_revision": grantA["revision"], "grant_hash": grantA["grant_hash"],
		"revoked_by": "user_security_admin", "revoked_at": "2026-07-14T12:30:00Z", "reason_code": "AUTHORITY_REVOKED", "policy_revision": "policy-0007",
	}
	revocationHash, err := hashCanonical(confirmationActorGrantRevocationHashInput(revocation))
	if err != nil {
		t.Fatal(err)
	}
	revocation["revocation_hash"] = revocationHash
	context["confirmation_actor_grant_revocations"] = []any{revocation}
	manifest := confirmationManifestFixture()
	if err := validateConfirmationActorGrantInventory(manifest, context); err != nil {
		t.Fatalf("valid revocation inventory rejected: %v", err)
	}
	if confirmationActorAuthorized(manifest, context, confirmationFixture(grantA, "2026-07-14T12:00:00Z")) {
		t.Fatal("revoked grant still authorized confirmation")
	}
	if !confirmationActorAuthorized(manifest, context, confirmationFixture(grantB, "2026-07-14T12:00:00Z")) {
		t.Fatal("revoking grant A affected unrelated grant B")
	}
}

func TestConfirmationActorGrantIntervalIsHalfOpen(t *testing.T) {
	grant := confirmationGrantFixture(t, "grant_admin", 1, "2026-07-14T12:00:00Z", "2026-07-14T13:00:00Z")
	context := confirmationRetrievalContext(grant)
	manifest := confirmationManifestFixture()
	if !confirmationActorAuthorized(manifest, context, confirmationFixture(grant, "2026-07-14T12:00:00Z")) {
		t.Fatal("valid_from boundary must be inclusive")
	}
	if confirmationActorAuthorized(manifest, context, confirmationFixture(grant, "2026-07-14T13:00:00Z")) {
		t.Fatal("valid_until boundary must be exclusive")
	}
}

func TestWorkspaceManagedConfirmationExactTupleAndHash(t *testing.T) {
	grant := confirmationGrantFixture(t, "grant_admin", 1, "2026-07-14T00:00:00Z", "2026-07-15T00:00:00Z")
	manifest := confirmationManifestFixture()
	for name, mutate := range map[string]func(map[string]any){
		"confirmation hash": func(confirmation map[string]any) {
			confirmation["confirmation_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		"binding": func(confirmation map[string]any) { confirmation["workspace_source_id"] = "binding_substituted" },
		"workspace config": func(confirmation map[string]any) {
			confirmation["workspace_configuration_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
		"warning contract": func(confirmation map[string]any) {
			confirmation["warning_contract_hash"] = "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
		},
	} {
		t.Run(name, func(t *testing.T) {
			confirmation, context := fullConfirmationFixture(t, grant, "wmc_projects_3", "binding_projects")
			mutate(confirmation)
			if validateWorkspaceManagedConfirmation(manifest, context, confirmation) {
				t.Fatal("substituted confirmation tuple was accepted")
			}
		})
	}
}

func TestWorkspaceManagedConfirmationRejectsAmbiguousLiveTuple(t *testing.T) {
	grantA := confirmationGrantFixture(t, "grant_admin_a", 1, "2026-07-14T00:00:00Z", "2026-07-15T00:00:00Z")
	grantB := confirmationGrantFixture(t, "grant_admin_b", 1, "2026-07-14T00:00:00Z", "2026-07-15T00:00:00Z")
	first, context := fullConfirmationFixture(t, grantA, "wmc_projects_3", "binding_projects")
	second, _ := fullConfirmationFixture(t, grantB, "wmc_projects_other", "binding_projects")
	context["confirmation_actor_grants"] = []any{grantA, grantB}
	context["live_workspace_managed_confirmations"] = []any{first, second}
	context["live_object_scope_memberships"] = []any{}
	context["live_policy_decisions"] = []any{}
	context["live_acl_snapshots"] = []any{}
	context["live_source_acl_pointers"] = []any{}
	if _, _, _, _, _, err := trustedRetrievalRecords(confirmationManifestFixture(), context); err == nil {
		t.Fatal("two live confirmations for one exact binding tuple were accepted")
	}
}

func TestAuthorityTimestampV1RejectsFractionalSeconds(t *testing.T) {
	if _, err := parseAuthorityTimestampV1("2026-07-14T12:00:00.123Z"); err == nil {
		t.Fatal("fractional seconds timestamp was accepted")
	}
}

func TestAuthorityTimestampV1RejectsOffset(t *testing.T) {
	if _, err := parseAuthorityTimestampV1("2026-07-14T12:00:00+00:00"); err == nil {
		t.Fatal("timezone offset timestamp was accepted")
	}
}

func TestAuthorityTimestampV1RejectsMissingSeconds(t *testing.T) {
	if _, err := parseAuthorityTimestampV1("2026-07-14T12:00Z"); err == nil {
		t.Fatal("timestamp missing seconds was accepted")
	}
}

func TestAuthorityTimestampV1RejectsInvalidLeapSecond(t *testing.T) {
	if _, err := parseAuthorityTimestampV1("2026-07-14T23:59:60Z"); err == nil {
		t.Fatal("leap second timestamp was accepted")
	}
}

func TestConfirmationActorGrantRejectsGrantedAtAfterValidFrom(t *testing.T) {
	grant := confirmationGrantFixture(t, "grant_admin", 1, "2026-07-14T00:00:00Z", "2026-07-15T00:00:00Z")
	grant["granted_at"] = "2026-07-14T00:00:01Z"
	hash, err := hashCanonical(confirmationActorGrantHashInput(grant))
	if err != nil {
		t.Fatal(err)
	}
	grant["grant_hash"] = hash
	context := confirmationRetrievalContext(grant)
	manifest := confirmationManifestFixture()
	if err := validateConfirmationActorGrantInventory(manifest, context); err == nil {
		t.Fatal("grant with granted_at after valid_from was accepted")
	}
}

func TestConfirmationActorAuthorizedRejectsConfirmedAtBeforeValidFrom(t *testing.T) {
	grant := confirmationGrantFixture(t, "grant_admin", 1, "2026-07-14T12:00:00Z", "2026-07-14T13:00:00Z")
	context := confirmationRetrievalContext(grant)
	manifest := confirmationManifestFixture()
	if confirmationActorAuthorized(manifest, context, confirmationFixture(grant, "2026-07-14T11:59:59Z")) {
		t.Fatal("confirmation before valid_from was authorized")
	}
}

func TestConfirmationActorGrantRevocationRejectsRevokedBeforeGrantedAt(t *testing.T) {
	grant := confirmationGrantFixture(t, "grant_admin", 1, "2026-07-14T00:00:00Z", "2026-07-15T00:00:00Z")
	context := confirmationRetrievalContext(grant)
	revocation := map[string]any{
		"schema_version": "workspace-source-confirmation-grant-revocation-v1", "revocation_id": "revoke_early", "organization_id": "org_alpha",
		"grant_id": grant["grant_id"], "grant_revision": grant["revision"], "grant_hash": grant["grant_hash"],
		"revoked_by": "user_security_admin", "revoked_at": "2026-07-13T23:00:00Z", "reason_code": "AUTHORITY_REVOKED", "policy_revision": "policy-0007",
	}
	revocationHash, err := hashCanonical(confirmationActorGrantRevocationHashInput(revocation))
	if err != nil {
		t.Fatal(err)
	}
	revocation["revocation_hash"] = revocationHash
	context["confirmation_actor_grant_revocations"] = []any{revocation}
	manifest := confirmationManifestFixture()
	if err := validateConfirmationActorGrantInventory(manifest, context); err == nil {
		t.Fatal("grant revocation before granted_at was accepted")
	}
}

func TestWorkspaceManagedConfirmationRevocationRejectsRevokedBeforeConfirmedAt(t *testing.T) {
	grant := confirmationGrantFixture(t, "grant_admin", 1, "2026-07-14T00:00:00Z", "2026-07-15T00:00:00Z")
	confirmation, context := fullConfirmationFixture(t, grant, "wmc_early", "binding_early")
	context["live_workspace_managed_confirmations"] = []any{confirmation}
	revocation := map[string]any{
		"schema_version": "workspace-managed-confirmation-revocation-v1", "revocation_id": "revoke_early", "organization_id": "org_alpha",
		"confirmation_id": confirmation["confirmation_id"], "confirmation_hash": confirmation["confirmation_hash"],
		"revoked_by": "user_security_admin", "revoked_at": "2026-07-14T11:00:00Z", "reason_code": "ACCESS_REVOKED", "policy_revision": "policy-0007",
	}
	revocationHash, err := hashCanonical(workspaceManagedConfirmationRevocationHashInput(revocation))
	if err != nil {
		t.Fatal(err)
	}
	revocation["revocation_hash"] = revocationHash
	context["workspace_managed_confirmation_revocations"] = []any{revocation}
	manifest := confirmationManifestFixture()
	if err := validateConfirmationActorGrantInventory(manifest, context); err == nil {
		t.Fatal("confirmation revocation before confirmed_at was accepted")
	}
}

func TestConfirmationActorGrantRevocationRejectsDuplicateParent(t *testing.T) {
	grant := confirmationGrantFixture(t, "grant_admin", 1, "2026-07-14T00:00:00Z", "2026-07-15T00:00:00Z")
	context := confirmationRetrievalContext(grant)
	makeRevocation := func(t *testing.T, id string) map[string]any {
		t.Helper()
		revocation := map[string]any{
			"schema_version": "workspace-source-confirmation-grant-revocation-v1", "revocation_id": id, "organization_id": "org_alpha",
			"grant_id": grant["grant_id"], "grant_revision": grant["revision"], "grant_hash": grant["grant_hash"],
			"revoked_by": "user_security_admin", "revoked_at": "2026-07-14T12:30:00Z", "reason_code": "AUTHORITY_REVOKED", "policy_revision": "policy-0007",
		}
		hash, err := hashCanonical(confirmationActorGrantRevocationHashInput(revocation))
		if err != nil {
			t.Fatal(err)
		}
		revocation["revocation_hash"] = hash
		return revocation
	}
	context["confirmation_actor_grant_revocations"] = []any{makeRevocation(t, "revoke_a"), makeRevocation(t, "revoke_b")}
	manifest := confirmationManifestFixture()
	if err := validateConfirmationActorGrantInventory(manifest, context); err == nil {
		t.Fatal("two grant revocations with distinct IDs for the same exact parent were accepted")
	}
}

func TestWorkspaceManagedConfirmationRevocationRejectsDuplicateParent(t *testing.T) {
	grant := confirmationGrantFixture(t, "grant_admin", 1, "2026-07-14T00:00:00Z", "2026-07-15T00:00:00Z")
	confirmation, context := fullConfirmationFixture(t, grant, "wmc_dup", "binding_dup")
	context["live_workspace_managed_confirmations"] = []any{confirmation}
	makeRevocation := func(t *testing.T, id string) map[string]any {
		t.Helper()
		revocation := map[string]any{
			"schema_version": "workspace-managed-confirmation-revocation-v1", "revocation_id": id, "organization_id": "org_alpha",
			"confirmation_id": confirmation["confirmation_id"], "confirmation_hash": confirmation["confirmation_hash"],
			"revoked_by": "user_security_admin", "revoked_at": "2026-07-14T12:30:00Z", "reason_code": "ACCESS_REVOKED", "policy_revision": "policy-0007",
		}
		hash, err := hashCanonical(workspaceManagedConfirmationRevocationHashInput(revocation))
		if err != nil {
			t.Fatal(err)
		}
		revocation["revocation_hash"] = hash
		return revocation
	}
	context["workspace_managed_confirmation_revocations"] = []any{makeRevocation(t, "revoke_x"), makeRevocation(t, "revoke_y")}
	manifest := confirmationManifestFixture()
	if err := validateConfirmationActorGrantInventory(manifest, context); err == nil {
		t.Fatal("two confirmation revocations with distinct IDs for the same exact parent were accepted")
	}
}

func TestWorkspaceManagedConfirmationRevocationDoesNotAffectSibling(t *testing.T) {
	grant := confirmationGrantFixture(t, "grant_admin", 1, "2026-07-14T00:00:00Z", "2026-07-15T00:00:00Z")
	confirmationA, context := fullConfirmationFixture(t, grant, "wmc_a", "binding_a")
	confirmationB, _ := fullConfirmationFixture(t, grant, "wmc_b", "binding_b")
	revocation := map[string]any{
		"schema_version": "workspace-managed-confirmation-revocation-v1", "revocation_id": "revoke_a", "organization_id": "org_alpha",
		"confirmation_id": confirmationA["confirmation_id"], "confirmation_hash": confirmationA["confirmation_hash"],
		"revoked_by": "user_security_admin", "revoked_at": "2026-07-14T12:30:00Z", "reason_code": "ACCESS_REVOKED", "policy_revision": "policy-0007",
	}
	revocationHash, err := hashCanonical(workspaceManagedConfirmationRevocationHashInput(revocation))
	if err != nil {
		t.Fatal(err)
	}
	revocation["revocation_hash"] = revocationHash
	context["workspace_managed_confirmation_revocations"] = []any{revocation}
	if !workspaceManagedConfirmationIsRevoked(context, confirmationA) {
		t.Fatal("exact confirmation revocation did not apply")
	}
	if workspaceManagedConfirmationIsRevoked(context, confirmationB) {
		t.Fatal("revoking confirmation A affected confirmation B")
	}
}
