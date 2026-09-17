package evidence

import (
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
)

func TestSourceExternalPathDecodesIngestIdentity(t *testing.T) {
	for encoded, expected := range map[string]string{
		`{"connection_id":"conn_a","kind":"FILE","relative_path":"project/requirements.txt"}`: "project/requirements.txt",
		`{"connection_id":"conn_a","kind":"GIT","external_id":"src/main.go"}`:                 "src/main.go",
		"src/legacy.go": "src/legacy.go",
	} {
		actual, err := sourceExternalPath(encoded)
		if err != nil || actual != expected {
			t.Fatalf("path=%q error=%v, want %q", actual, err, expected)
		}
	}
	for _, invalid := range []string{
		"", "{broken", `{"kind":"FILE","relative_path":"x"}`,
		`{"connection_id":"c","kind":"FILE","external_id":"x"}`,
		`{"connection_id":"c","kind":"FILE","relative_path":"x","external_id":"y"}`,
		`{"connection_id":"c","kind":"FILE","relative_path":"x","relative_path":"y"}`,
	} {
		if _, err := sourceExternalPath(invalid); err == nil {
			t.Fatalf("malformed source identity accepted: %s", invalid)
		}
	}
}

func TestSourcePostgreSQLQueryDisplayUsesOnlyOpaqueCatalogDigest(t *testing.T) {
	value, err := canon.CanonicalJSON(map[string]any{
		"kind":                  "POSTGRESQL_QUERY_IDENTITY",
		"projection_lineage_id": "waste-daily",
		"identity_values": []any{map[string]any{
			"ordinal":          1,
			"type_fingerprint": "oid:2950",
			"logical_type":     "UUID",
			"value_tag":        "UUID",
			"value":            "550e8400-e29b-41d4-a716-446655440010",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	opaqueID := "hmac-sha256:k1:" + strings.Repeat("a", 64)
	actual, err := sourcePostgreSQLQueryDisplay(string(value), opaqueID)
	if err != nil {
		t.Fatalf("valid PostgreSQL identity rejected: %v", err)
	}
	want := "postgresql-query/waste-daily/" + opaqueID
	if actual != want {
		t.Fatalf("display=%q, want %q", actual, want)
	}
	if strings.Contains(actual, "550e8400") {
		t.Fatal("row identity value was exposed in the display")
	}
}

func TestSourcePostgreSQLQueryDisplayAllowsEmbeddedJSONNullIdentity(t *testing.T) {
	value, err := canon.CanonicalJSON(struct {
		Kind      string                        `json:"kind"`
		LineageID string                        `json:"projection_lineage_id"`
		Identity  []postgresqlQueryIdentityTest `json:"identity_values"`
	}{
		Kind: "POSTGRESQL_QUERY_IDENTITY", LineageID: "waste-daily",
		Identity: []postgresqlQueryIdentityTest{{
			Ordinal: 1, TypeFingerprint: "oid:3802", LogicalType: "JSONB", ValueTag: "JSONB", Value: nil,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	digest := "hmac-sha256:k1:" + strings.Repeat("c", 64)
	if display, err := sourcePostgreSQLQueryDisplay(string(value), digest); err != nil || display == "" {
		t.Fatalf("embedded JSON null identity rejected: display=%q err=%v", display, err)
	}
}

type postgresqlQueryIdentityTest struct {
	Ordinal         int    `json:"ordinal"`
	TypeFingerprint string `json:"type_fingerprint"`
	LogicalType     string `json:"logical_type"`
	ValueTag        string `json:"value_tag"`
	Value           any    `json:"value"`
}

func TestSourcePostgreSQLQueryDisplayFailsClosedForForeignOrMalformedIdentity(t *testing.T) {
	validValue := `{"identity_values":[{"logical_type":"UUID","ordinal":1,"type_fingerprint":"oid:2950","value":"550e8400-e29b-41d4-a716-446655440010","value_tag":"UUID"}],"kind":"POSTGRESQL_QUERY_IDENTITY","projection_lineage_id":"waste-daily"}`
	opaqueID := "hmac-sha256:k1:" + strings.Repeat("b", 64)
	for _, test := range []struct {
		name   string
		value  string
		digest string
	}{
		{name: "foreign kind", value: strings.Replace(validValue, "POSTGRESQL_QUERY_IDENTITY", "GIT", 1), digest: opaqueID},
		{name: "unknown member", value: strings.Replace(validValue, `"kind":"POSTGRESQL_QUERY_IDENTITY"`, `"extra":true,"kind":"POSTGRESQL_QUERY_IDENTITY"`, 1), digest: opaqueID},
		{name: "leading whitespace", value: " " + validValue, digest: opaqueID},
		{name: "null identity", value: strings.Replace(validValue, `"value":"550e8400-e29b-41d4-a716-446655440010"`, `"value":null`, 1), digest: opaqueID},
		{name: "invalid opaque digest", value: validValue, digest: "hmac-sha256:k1:short"},
		{name: "unsafe lineage", value: strings.Replace(validValue, "waste-daily", "waste/daily", 1), digest: opaqueID},
	} {
		t.Run(test.name, func(t *testing.T) {
			if actual, err := sourcePostgreSQLQueryDisplay(test.value, test.digest); err == nil || actual != "" {
				t.Fatalf("malformed identity accepted: display=%q err=%v", actual, err)
			}
		})
	}
}

func TestPostgreSQLQueryCanonicalLocatorBindsCatalogIdentity(t *testing.T) {
	connectionID := "conn_01J00000000000000000000000"
	lineageID := "waste-daily"
	digest := "hmac-sha256:k1:" + strings.Repeat("a", 64)
	locator, err := canon.CanonicalJSON(struct {
		ConnectionID   string `json:"connection_id"`
		Kind           string `json:"kind"`
		LineageID      string `json:"projection_lineage_id"`
		Revision       int64  `json:"projection_revision"`
		IdentityDigest string `json:"entity_identity_digest"`
	}{connectionID, "POSTGRESQL_QUERY_ROW", lineageID, 7, digest})
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePostgreSQLQueryCanonicalLocator(string(locator), connectionID, lineageID, digest); err != nil {
		t.Fatalf("valid locator rejected: %v", err)
	}

	for name, want := range map[string]struct {
		connection string
		lineage    string
		digest     string
	}{
		"foreign connection": {connection: "conn_foreign", lineage: lineageID, digest: digest},
		"foreign lineage":    {connection: connectionID, lineage: "other-lineage", digest: digest},
		"swapped row digest": {connection: connectionID, lineage: lineageID, digest: "hmac-sha256:k1:" + strings.Repeat("b", 64)},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validatePostgreSQLQueryCanonicalLocator(string(locator), want.connection, want.lineage, want.digest); err == nil {
				t.Fatal("locator accepted with a foreign catalog binding")
			}
		})
	}

	for name, value := range map[string]string{
		"foreign kind":   strings.Replace(string(locator), `"POSTGRESQL_QUERY_ROW"`, `"FILE"`, 1),
		"unknown member": strings.Replace(string(locator), `"kind":"POSTGRESQL_QUERY_ROW"`, `"extra":true,"kind":"POSTGRESQL_QUERY_ROW"`, 1),
		"noncanonical":   " " + string(locator),
	} {
		t.Run(name, func(t *testing.T) {
			if err := validatePostgreSQLQueryCanonicalLocator(value, connectionID, lineageID, digest); err == nil {
				t.Fatal("malformed locator accepted")
			}
		})
	}
}
