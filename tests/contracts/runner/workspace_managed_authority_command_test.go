package contracts

import (
	"encoding/hex"
	"testing"
)

// workspaceManagedAuthorityValidFixturesFromRegistry derives the one
// canonical valid fixture per operation directly from fixture-cases.json —
// the registry is the only source of truth for the fixture inventory (see
// TestWorkspaceManagedAuthorityCommandFixtureInventoryMatchesRegistry in
// contract_test.go), so this helper never hardcodes a second fixture list.
func workspaceManagedAuthorityValidFixturesFromRegistry(t *testing.T) map[string]string {
	t.Helper()
	registryData := loadRegistry(t)
	result := map[string]string{}
	for _, testCase := range registryData.Cases {
		if testCase.Contract != "workspace-managed-authority-command" {
			continue
		}
		if testCase.ExpectedSchemaValid == nil || !*testCase.ExpectedSchemaValid {
			continue
		}
		envelope, _, err := loadObject(testCase.Fixture)
		if err != nil {
			t.Fatal(err)
		}
		operation := stringValue(envelope["operation"])
		if existing, ok := result[operation]; ok {
			t.Fatalf("operation %s has multiple valid fixtures: %s and %s", operation, existing, testCase.Fixture)
		}
		result[operation] = testCase.Fixture
	}
	for operation := range workspaceManagedAuthorityRequestFields {
		if _, ok := result[operation]; !ok {
			t.Fatalf("registry has no valid fixture for operation %s", operation)
		}
	}
	return result
}

func TestWorkspaceManagedAuthorityCommandGoldenVectors(t *testing.T) {
	validFixtures := workspaceManagedAuthorityValidFixturesFromRegistry(t)
	golden, _, err := loadObject("fixtures/golden/workspace-managed-authority-command-jcs.json")
	if err != nil {
		t.Fatal(err)
	}
	if stringValue(golden["vector_version"]) != workspaceManagedAuthorityCommandSchemaVersion {
		t.Fatalf("unexpected vector_version %q", stringValue(golden["vector_version"]))
	}
	vectors := array(golden["vectors"])
	if len(vectors) != len(workspaceManagedAuthorityRequestFields) {
		t.Fatalf("expected exactly %d golden vectors, found %d", len(workspaceManagedAuthorityRequestFields), len(vectors))
	}
	seen := map[string]bool{}
	for _, rawVector := range vectors {
		vector := object(rawVector)
		operation := stringValue(vector["operation"])
		if seen[operation] {
			t.Fatalf("duplicate golden vector for %s", operation)
		}
		seen[operation] = true
		input := object(vector["input"])
		if stringValue(input["operation"]) != operation {
			t.Fatalf("golden input operation mismatch for %s", operation)
		}
		if err := validateWorkspaceManagedAuthorityCommand(input); err != nil {
			t.Fatalf("golden input for %s rejected: %v", operation, err)
		}
		canonical, err := canonicalValue(input)
		if err != nil {
			t.Fatal(err)
		}
		if string(canonical) != stringValue(vector["canonical_jcs"]) ||
			hex.EncodeToString(canonical) != stringValue(vector["canonical_utf8_hex"]) ||
			sha256String(canonical) != stringValue(vector["request_hash"]) {
			t.Fatalf("golden JCS mismatch for %s", operation)
		}
		fixture, ok := validFixtures[operation]
		if !ok {
			t.Fatalf("golden vector for unknown operation %s", operation)
		}
		_, fixtureCanonical, err := loadObject(fixture)
		if err != nil {
			t.Fatal(err)
		}
		if string(fixtureCanonical) != string(canonical) {
			t.Fatalf("valid fixture and golden input diverged for %s", operation)
		}
	}
	for operation := range validFixtures {
		if !seen[operation] {
			t.Fatalf("missing golden vector for %s", operation)
		}
	}
}

func TestWorkspaceManagedAuthorityCommandRequestHashBindsEveryField(t *testing.T) {
	validFixtures := workspaceManagedAuthorityValidFixturesFromRegistry(t)
	for operation, fixture := range validFixtures {
		envelope, canonical, err := loadObject(fixture)
		if err != nil {
			t.Fatal(err)
		}
		baseHash := sha256String(canonical)
		request := object(envelope["request"])
		for field := range request {
			mutated := cloneObject(envelope)
			mutatedRequest := object(mutated["request"])
			switch value := mutatedRequest[field].(type) {
			case string:
				mutatedRequest[field] = value + "x"
			case float64:
				mutatedRequest[field] = value + 1
			default:
				t.Fatalf("%s: unexpected fixture field type for %s", operation, field)
			}
			mutatedCanonical, err := canonicalValue(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if sha256String(mutatedCanonical) == baseHash {
				t.Fatalf("%s: request field %s does not change the request hash", operation, field)
			}
		}
		for otherOperation := range workspaceManagedAuthorityRequestFields {
			if otherOperation == operation {
				continue
			}
			mutated := cloneObject(envelope)
			mutated["operation"] = otherOperation
			mutatedCanonical, err := canonicalValue(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if sha256String(mutatedCanonical) == baseHash {
				t.Fatalf("operation can be swapped from %s to %s without changing the request hash", operation, otherOperation)
			}
		}
		mutated := cloneObject(envelope)
		mutated["schema_version"] = "workspace-command-v2"
		mutatedCanonical, err := canonicalValue(mutated)
		if err != nil {
			t.Fatal(err)
		}
		if sha256String(mutatedCanonical) == baseHash {
			t.Fatalf("%s: schema_version does not change the request hash", operation)
		}
	}
}

func TestWorkspaceManagedAuthorityCommandCanonicalizationDeterminism(t *testing.T) {
	golden, _, err := loadObject("fixtures/golden/workspace-managed-authority-command-jcs.json")
	if err != nil {
		t.Fatal(err)
	}
	var canonical string
	for _, rawVector := range array(golden["vectors"]) {
		vector := object(rawVector)
		if stringValue(vector["operation"]) == operationConfirmationGrantIssue {
			canonical = stringValue(vector["canonical_jcs"])
		}
	}
	if canonical == "" {
		t.Fatal("missing grant-issue golden vector")
	}
	// Same semantics, different encoding: permuted key order, a \u-escaped
	// ASCII letter inside the operation, and an exponent-form safe integer.
	// The raw bytes are not the golden canonical bytes, but canonicalization
	// must map them onto exactly the golden bytes.
	variant := `{"request":{"workspace_id":"ws_alpha","ttl_seconds":3.6e3,"target_principal_id":"user_maria",` +
		`"organization_id":"org_acme","expected_workspace_revision":7,` +
		`"expected_workspace_configuration_hash":"sha256:1c9f2b4d1c9f2b4d1c9f2b4d1c9f2b4d1c9f2b4d1c9f2b4d1c9f2b4d1c9f2b4d",` +
		`"expected_policy_revision":"policy-r7"},` +
		`"schema_version":"workspace-managed-authority-command-v1",` +
		`"operation":"WORKSPACE_CONFIRMATION_GRANT_\u0049SSUE"}`
	if variant == canonical {
		t.Fatal("variant encoding must differ from the golden canonical bytes")
	}
	canonicalized, err := strictCanonical([]byte(variant))
	if err != nil {
		t.Fatal(err)
	}
	if string(canonicalized) != canonical {
		t.Fatalf("canonicalization is not deterministic:\n%s\n%s", canonicalized, canonical)
	}
}
