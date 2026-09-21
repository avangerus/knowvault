package analytic

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/tzrules"
)

func TestDecodeDatasetProfileJSONRoundTripsCanonicalProfile(t *testing.T) {
	spec := validDatasetProfileSpec(t)
	semanticInput := spec.Semantics.Values()
	semanticInput.Fields[0].Aliases = []string{"Total amount"}
	spec.Semantics = mustProfileSemantics(t, semanticInput)
	raw, expectedHash := canonicalProfileForTest(t, spec)

	profile, err := DecodeDatasetProfileJSON(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !profile.Valid() || profile.Hash() != expectedHash {
		t.Fatalf("decoded profile valid=%v hash=%q, want %q", profile.Valid(), profile.Hash(), expectedHash)
	}
	again, err := DecodeDatasetProfileJSON(append([]byte(nil), raw...))
	if err != nil || again.Hash() != profile.Hash() {
		t.Fatalf("deterministic decode hash=%q err=%v, want %q", again.Hash(), err, profile.Hash())
	}

	fields := profile.Fields()
	semantics := profile.Semantics().Values()
	grain := profile.Grain().Values()
	fields[0] = FieldSpec{}
	semantics.Fields[0].Aliases[0] = "mutated"
	grain.KeyFields[0] = "mutated"
	if !profile.Valid() || profile.Hash() != expectedHash || reflect.DeepEqual(profile.Fields(), fields) ||
		profile.Semantics().Values().Fields[0].Aliases[0] != "Total amount" {
		t.Fatal("decoded profile exposed caller-owned nested values")
	}
}

func TestDecodeDatasetProfileJSONRejectsMalformedEnvelope(t *testing.T) {
	raw, _ := canonicalProfileForTest(t, validDatasetProfileSpec(t))
	cases := map[string][]byte{
		"empty":          nil,
		"top null":       []byte(`null`),
		"trailing value": append(append([]byte(nil), raw...), []byte(` {}`)...),
		"unknown top": replaceDatasetProfileJSON(t, raw,
			`"schema_version":`, `"profile_hash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schema_version":`),
		"unknown nested": replaceDatasetProfileJSON(t, raw,
			`"source_scope_id":"gm"`, `"source_scope_id":"gm","endpoint":"postgres://forbidden"`),
		"duplicate top": replaceDatasetProfileJSON(t, raw,
			`"schema_version":`, `"schema_version":"knowvault-dataset-profile-v2","schema_version":`),
		"duplicate nested": replaceDatasetProfileJSON(t, raw,
			`"source_scope_id":"gm"`, `"source_scope_id":"gm","source_scope_id":"other"`),
		"null object": replaceDatasetProfileJSON(t, raw,
			`"key":{"dataset_id":"operations","version":1}`, `"key":null`),
		"null array": replaceDatasetProfileJSON(t, raw,
			`"allowed_ops":[]`, `"allowed_ops":null`),
		"missing required scalar": replaceDatasetProfileJSON(t, raw,
			`"output_allowed":true,`, ``),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) { assertInvalidDatasetProfileJSON(t, candidate) })
	}

	exactLimit := append(append([]byte(nil), raw...), bytes.Repeat([]byte{' '}, maxDatasetProfileJSONBytes-len(raw))...)
	profile, err := DecodeDatasetProfileJSON(exactLimit)
	if err != nil || !profile.Valid() {
		t.Fatalf("valid profile at exact size limit rejected: valid=%v err=%v", profile.Valid(), err)
	}
	assertInvalidDatasetProfileJSON(t, append(exactLimit, ' '))
}

func TestDecodeDatasetProfileJSONRejectsInvalidPhysicalLogicalAndBusinessSemantics(t *testing.T) {
	raw, _ := canonicalProfileForTest(t, validDatasetProfileSpec(t))
	cases := map[string][]byte{
		"invalid physical enum": replaceDatasetProfileJSON(t, raw,
			`"physical_type":"PG_TEXT"`, `"physical_type":"PG_JSONB"`),
		"physical logical mismatch": replaceDatasetProfileJSON(t, raw,
			`"logical_type":"TEXT"`, `"logical_type":"INT"`),
		"invalid logical enum": replaceDatasetProfileJSON(t, raw,
			`"logical_type":"TEXT"`, `"logical_type":"OBJECT"`),
		"semantic structural mismatch": replaceDatasetProfileJSON(t, raw,
			`"token":"amount"`, `"token":"other"`),
		"invalid coverage": replaceDatasetProfileJSON(t, raw,
			`"coverage":"UNKNOWN"`, `"coverage":"COMPLETE"`),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) { assertInvalidDatasetProfileJSON(t, candidate) })
	}
}

func TestDecodeDatasetProfileJSONBindsTimezoneRulesBundleDigest(t *testing.T) {
	raw, _ := canonicalProfileForTest(t, validDatasetProfileSpec(t))
	member := `"timezone_rules_bundle_sha256":"` + tzrules.BundleSHA256 + `"`
	if !bytes.Contains(raw, []byte(member)) {
		t.Fatalf("canonical time object lacks pinned timezone rules digest: %s", raw)
	}
	cases := map[string][]byte{
		"missing digest": replaceDatasetProfileJSON(t, raw, ","+member, ``),
		"altered digest": replaceDatasetProfileJSON(t, raw, member,
			`"timezone_rules_bundle_sha256":"sha256:0000000000000000000000000000000000000000000000000000000000000000"`),
		"digest outside time": replaceDatasetProfileJSON(t, raw,
			`"schema_version":`, member+`,"schema_version":`),
		"duplicate digest": replaceDatasetProfileJSON(t, raw, member, member+`,`+member),
	}
	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) { assertInvalidDatasetProfileJSON(t, candidate) })
	}
}

func replaceDatasetProfileJSON(t *testing.T, raw []byte, old, replacement string) []byte {
	t.Helper()
	if !bytes.Contains(raw, []byte(old)) {
		t.Fatalf("fixture does not contain %q", old)
	}
	return bytes.Replace(append([]byte(nil), raw...), []byte(old), []byte(replacement), 1)
}

func assertInvalidDatasetProfileJSON(t *testing.T, raw []byte) {
	t.Helper()
	profile, err := DecodeDatasetProfileJSON(raw)
	if err == nil || profile.Valid() || CodeOf(err) != CodeInvalidRequest ||
		err.Error() != string(CodeInvalidRequest) || errors.Unwrap(err) != nil {
		t.Fatalf("invalid JSON accepted or leaked detail: valid=%v err=%#v", profile.Valid(), err)
	}
}
