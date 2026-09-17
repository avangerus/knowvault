package repository

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// The production canonicalizer must emit byte-for-byte the frozen golden JCS
// vectors. This test decodes each vector's request into the typed payload the
// runtime marshals and proves authorityRequestHash reproduces both the exact
// canonical bytes and the exact request hash. A drifted field name, a dropped
// field or a wrong integer type would change the bytes and fail here.

type authorityGoldenVector struct {
	ID        string `json:"id"`
	Operation string `json:"operation"`
	Input     struct {
		Request json.RawMessage `json:"request"`
	} `json:"input"`
	CanonicalJCS string `json:"canonical_jcs"`
	RequestHash  string `json:"request_hash"`
}

type authorityGoldenFile struct {
	Vectors []authorityGoldenVector `json:"vectors"`
}

func loadAuthorityGoldenVectors(t *testing.T) []authorityGoldenVector {
	t.Helper()
	path := filepath.Join("..", "..", "..", "tests", "contracts", "fixtures", "golden", "workspace-managed-authority-command-jcs.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden vectors: %v", err)
	}
	var file authorityGoldenFile
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("decode golden vectors: %v", err)
	}
	if len(file.Vectors) != 4 {
		t.Fatalf("golden vectors = %d, want 4", len(file.Vectors))
	}
	return file.Vectors
}

func TestAuthorityRequestHashMatchesGoldenVectors(t *testing.T) {
	t.Parallel()
	for _, vector := range loadAuthorityGoldenVectors(t) {
		t.Run(vector.ID, func(t *testing.T) {
			var operation authorityOperation
			var payload any
			switch vector.Operation {
			case string(operationConfirmationGrantIssue):
				operation = operationConfirmationGrantIssue
				var request grantIssueRequestPayload
				decodeAuthorityRequest(t, vector.Input.Request, &request)
				payload = request
			case string(operationConfirmationGrantRevoke):
				operation = operationConfirmationGrantRevoke
				var request grantRevokeRequestPayload
				decodeAuthorityRequest(t, vector.Input.Request, &request)
				payload = request
			case string(operationManagedConfirm):
				operation = operationManagedConfirm
				var request managedConfirmRequestPayload
				decodeAuthorityRequest(t, vector.Input.Request, &request)
				payload = request
			case string(operationManagedConfirmRevoke):
				operation = operationManagedConfirmRevoke
				var request managedConfirmRevokeRequestPayload
				decodeAuthorityRequest(t, vector.Input.Request, &request)
				payload = request
			default:
				t.Fatalf("unknown operation %q", vector.Operation)
			}
			bytes, hash, err := authorityRequestHash(operation, payload)
			if err != nil {
				t.Fatalf("hash request: %v", err)
			}
			if string(bytes) != vector.CanonicalJCS {
				t.Fatalf("canonical bytes mismatch\n got: %s\nwant: %s", string(bytes), vector.CanonicalJCS)
			}
			if hash != vector.RequestHash {
				t.Fatalf("request hash = %s, want %s", hash, vector.RequestHash)
			}
		})
	}
}

func decodeAuthorityRequest(t *testing.T, raw json.RawMessage, target any) {
	t.Helper()
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("decode request into typed payload: %v", err)
	}
}

// The valid request builders below carry every field the schema requires, so a
// per-field mutation isolates exactly one validation rule.
func validIssueRequest() IssueGrantRequest {
	return IssueGrantRequest{
		IdempotencyKey: authorityTestIdempotencyKey, OrganizationID: "org_acme", WorkspaceID: "ws_alpha",
		ExpectedWorkspaceRevision:          7,
		ExpectedWorkspaceConfigurationHash: authorityTestHash,
		TargetPrincipalID:                  "user_maria", TTLSeconds: 3600, ExpectedPolicyRevision: "policy-r7",
	}
}

func validRevokeGrantRequest() RevokeGrantRequest {
	return RevokeGrantRequest{
		IdempotencyKey: authorityTestIdempotencyKey, OrganizationID: "org_acme", WorkspaceID: "ws_alpha",
		GrantID: "grant_alpha", GrantRevision: 1, GrantHash: authorityTestHash, ExpectedPolicyRevision: "policy-r7",
	}
}

func validConfirmRequest() ConfirmRequest {
	return ConfirmRequest{
		IdempotencyKey: authorityTestIdempotencyKey, OrganizationID: "org_acme", WorkspaceID: "ws_alpha",
		WorkspaceRevision: 7, WorkspaceConfigurationHash: authorityTestHash,
		WorkspaceSourceID: "binding_0A1B2C3D4E5F6G7H8J9K0M1N2P", SourceScopeID: "scope_folder_alpha",
		SourceScopeRevision: 3, ScopeConfigHash: authorityTestHash, AccessMode: authorityAccessModeManaged,
		ConfirmationActorGrantID: "grant_alpha", ConfirmationActorGrantRevision: 1, ConfirmationActorGrantHash: authorityTestHash,
		WarningVersion: authorityWarningVersion, WarningContractHash: authorityTestHash,
		AcknowledgementCode: authorityAcknowledgementCode, ExpectedPolicyRevision: "policy-r7",
	}
}

func validRevokeConfirmationRequest() RevokeConfirmationRequest {
	return RevokeConfirmationRequest{
		IdempotencyKey: authorityTestIdempotencyKey, OrganizationID: "org_acme", WorkspaceID: "ws_alpha",
		ConfirmationID: "confirmation_alpha", ConfirmationHash: authorityTestHash, ExpectedPolicyRevision: "policy-r7",
	}
}

const authorityTestHash = "sha256:1c9f2b4d1c9f2b4d1c9f2b4d1c9f2b4d1c9f2b4d1c9f2b4d1c9f2b4d1c9f2b4d"

// authorityTestIdempotencyKey is the base64url of 32 bytes, the only shape
// idempotencyKeyHash accepts.
const authorityTestIdempotencyKey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func TestAuthorityRequestValidationAcceptsEveryValidRequest(t *testing.T) {
	t.Parallel()
	if _, ok := validIssueRequest().validate(); !ok {
		t.Fatal("valid issue request rejected")
	}
	if _, ok := validRevokeGrantRequest().validate(); !ok {
		t.Fatal("valid grant-revoke request rejected")
	}
	if _, ok := validConfirmRequest().validate(); !ok {
		t.Fatal("valid confirm request rejected")
	}
	if _, ok := validRevokeConfirmationRequest().validate(); !ok {
		t.Fatal("valid confirm-revoke request rejected")
	}
}

func TestAuthorityIssueValidationRejectsFacets(t *testing.T) {
	t.Parallel()
	mutations := map[string]func(*IssueGrantRequest){
		"empty organization":       func(r *IssueGrantRequest) { r.OrganizationID = "" },
		"whitespace workspace":     func(r *IssueGrantRequest) { r.WorkspaceID = " ws_alpha" },
		"zero revision":            func(r *IssueGrantRequest) { r.ExpectedWorkspaceRevision = 0 },
		"unsafe revision":          func(r *IssueGrantRequest) { r.ExpectedWorkspaceRevision = maxSafeInteger + 1 },
		"config hash not a hash":   func(r *IssueGrantRequest) { r.ExpectedWorkspaceConfigurationHash = "deadbeef" },
		"ttl below minimum":        func(r *IssueGrantRequest) { r.TTLSeconds = 59 },
		"ttl above maximum":        func(r *IssueGrantRequest) { r.TTLSeconds = 86401 },
		"numeric policy revision":  func(r *IssueGrantRequest) { r.ExpectedPolicyRevision = "12345" },
		"policy revision as hash":  func(r *IssueGrantRequest) { r.ExpectedPolicyRevision = authorityTestHash },
		"target with control byte": func(r *IssueGrantRequest) { r.TargetPrincipalID = "user\x01maria" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			request := validIssueRequest()
			mutate(&request)
			if _, ok := request.validate(); ok {
				t.Fatalf("invalid issue request accepted: %s", name)
			}
		})
	}
}

func TestAuthorityConfirmValidationRejectsClosedConstants(t *testing.T) {
	t.Parallel()
	mutations := map[string]func(*ConfirmRequest){
		"foreign access mode":        func(r *ConfirmRequest) { r.AccessMode = "SOURCE_ENFORCED" },
		"foreign warning version":    func(r *ConfirmRequest) { r.WarningVersion = "workspace-managed-risk-v2" },
		"foreign acknowledgement":    func(r *ConfirmRequest) { r.AcknowledgementCode = "SOMETHING_ELSE" },
		"binding without prefix":     func(r *ConfirmRequest) { r.WorkspaceSourceID = "scope_folder_alpha" },
		"binding first char above 7": func(r *ConfirmRequest) { r.WorkspaceSourceID = "binding_8A1B2C3D4E5F6G7H8J9K0M1N2P" },
		"warning hash not a hash":    func(r *ConfirmRequest) { r.WarningContractHash = "not-a-hash" },
		"grant hash not a hash":      func(r *ConfirmRequest) { r.ConfirmationActorGrantHash = "0xdeadbeef" },
		"zero source scope revision": func(r *ConfirmRequest) { r.SourceScopeRevision = 0 },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			request := validConfirmRequest()
			mutate(&request)
			if _, ok := request.validate(); ok {
				t.Fatalf("invalid confirm request accepted: %s", name)
			}
		})
	}
}
