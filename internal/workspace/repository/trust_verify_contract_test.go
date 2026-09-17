package repository

// Contract test for ADR-0087 §2 review blocker B4 (review-opus-s2-4-5.md):
// proves the production request, result and canonical-document types this
// package actually marshals have exactly the field set the three
// architecture/contracts/source-connection-trust-verify*.schema.json
// schemas declare -- no undeclared implementation field, no schema field the
// implementation never populates. It marshals the real production types
// (connectionTrustVerifyRequestDocument, VerifyConnectionTrustResult,
// connectionTrustVerifyDocument) rather than a duplicated shape, so the two
// can never silently drift apart.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// repoRootForContracts locates the repository root the same way
// tests/contracts/runner's repoRoot() does (walking up to the first
// directory containing architecture/contracts), so this in-package test can
// read the schemas without a new dependency or a hardcoded relative depth.
func repoRootForContracts(t *testing.T) string {
	t.Helper()
	if root := os.Getenv("REPO_ROOT"); root != "" {
		return root
	}
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "architecture", "contracts")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("repository root not found (no architecture/contracts ancestor)")
		}
		dir = parent
	}
}

type jsonSchemaShape struct {
	AdditionalProperties *bool                      `json:"additionalProperties"`
	Required             []string                   `json:"required"`
	Properties           map[string]json.RawMessage `json:"properties"`
}

func loadSchemaShape(t *testing.T, relativeToContracts string) jsonSchemaShape {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRootForContracts(t), "architecture", "contracts", relativeToContracts))
	if err != nil {
		t.Fatalf("read schema %s: %v", relativeToContracts, err)
	}
	var shape jsonSchemaShape
	if err := json.Unmarshal(raw, &shape); err != nil {
		t.Fatalf("parse schema %s: %v", relativeToContracts, err)
	}
	if shape.AdditionalProperties == nil || *shape.AdditionalProperties {
		t.Fatalf("%s does not declare a closed object (additionalProperties: false)", relativeToContracts)
	}
	return shape
}

// implementationFieldSet marshals a real production value (never a
// hand-duplicated map) and returns its top-level JSON key set.
func implementationFieldSet(t *testing.T, value any) map[string]bool {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal %#v: %v", value, err)
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal %#v: %v", value, err)
	}
	fields := make(map[string]bool, len(generic))
	for key := range generic {
		fields[key] = true
	}
	return fields
}

// assertExactFieldSetMatchesSchema fails if the implementation's populated
// field set and the schema's declared property set are not exactly equal:
// every schema property must be one the implementation actually populates
// (dead schema field), and every implementation field must be declared in
// the schema (undeclared drift). Every property in these three schemas is
// also required -- none is optional -- so "declared" and "required" are the
// same set here; a future genuinely optional field would need its own
// carve-out, not a silent pass here.
func assertExactFieldSetMatchesSchema(t *testing.T, label string, shape jsonSchemaShape, fields map[string]bool) {
	t.Helper()
	for name := range fields {
		if _, declared := shape.Properties[name]; !declared {
			t.Errorf("%s: implementation field %q is not declared in the schema properties", label, name)
		}
	}
	required := make(map[string]bool, len(shape.Required))
	for _, name := range shape.Required {
		required[name] = true
	}
	for name := range shape.Properties {
		if !required[name] {
			t.Errorf("%s: schema property %q is declared but not required -- this contract has no optional fields, so review the schema", label, name)
			continue
		}
		if !fields[name] {
			t.Errorf("%s: schema-required field %q is never populated by the implementation", label, name)
		}
	}
}

func TestSourceConnectionTrustVerifyRequestMatchesContractSchema(t *testing.T) {
	shape := loadSchemaShape(t, "source-connection-trust-verify-request.schema.json")
	document := connectionTrustVerifyRequestDocument{
		SchemaVersion: connectionTrustVerifyRequestSchema, Operation: "VERIFY_TRUST",
		ConnectionID: "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV", AttestedConnectorIdentity: "folder-connector-1",
		AttestedBy: "security-team", AttestedAt: time.Now().UTC().Format(time.RFC3339),
	}
	assertExactFieldSetMatchesSchema(t, "request", shape, implementationFieldSet(t, document))
}

func TestSourceConnectionTrustVerifyResultMatchesContractSchema(t *testing.T) {
	shape := loadSchemaShape(t, "source-connection-trust-verify-result.schema.json")
	result := VerifyConnectionTrustResult{
		ResultID:   "wctv_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		ResultHash: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
	}
	assertExactFieldSetMatchesSchema(t, "result", shape, implementationFieldSet(t, result))
}

func TestSourceConnectionTrustVerifyDocumentMatchesContractSchema(t *testing.T) {
	shape := loadSchemaShape(t, "source-connection-trust-verify.schema.json")
	document := connectionTrustVerifyDocument{
		SchemaVersion: connectionTrustVerifyDocumentSchema, VerificationID: "wctv_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		OrganizationID: "org_authority_ops", ConnectionID: "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		AttestedConnectorIdentity: "folder-connector-1", AttestedBy: "security-team",
		AttestedAt: time.Now().UTC().Format(time.RFC3339), VerifiedBy: "usr_reg_connector_admin",
		VerifiedAt: time.Now().UTC().Format(time.RFC3339),
	}
	assertExactFieldSetMatchesSchema(t, "canonical document", shape, implementationFieldSet(t, document))
}
