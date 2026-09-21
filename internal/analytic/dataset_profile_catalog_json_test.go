package analytic

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// catalogMountEntryForTest describes one mount entry so a test can control its
// state and its exact embedded trusted profile bytes.
type catalogMountEntryForTest struct {
	state   string
	profile []byte
}

// datasetProfileCatalogMountJSONForTest renders the server-owned mount document
// with the literal schema version from the contract, so a drift in the
// implementation constant fails the acceptance fixtures.
func datasetProfileCatalogMountJSONForTest(t *testing.T, catalogID string, revision int64, entries ...catalogMountEntryForTest) []byte {
	t.Helper()
	document := bytes.Buffer{}
	document.WriteString(`{"schema_version":"knowvault-dataset-profile-catalog-mount-v1","catalog_id":`)
	fmt.Fprintf(&document, `%q,"revision":%d,"entries":[`, catalogID, revision)
	for index, entry := range entries {
		if index > 0 {
			document.WriteByte(',')
		}
		fmt.Fprintf(&document, `{"state":%q,"profile":`, entry.state)
		document.Write(entry.profile)
		document.WriteByte('}')
	}
	document.WriteString(`]}`)
	return document.Bytes()
}

// datasetProfileCatalogMountJSONWithEntriesForTest wraps a hand-written entries
// array in an otherwise valid mount envelope.
func datasetProfileCatalogMountJSONWithEntriesForTest(entries string) []byte {
	return []byte(`{"schema_version":"knowvault-dataset-profile-catalog-mount-v1","catalog_id":"catalog.operations","revision":7,"entries":[` + entries + `]}`)
}

// catalogMountProfileForTest seals one trusted profile and returns both its
// canonical wire object and the profile value that object must decode into.
func catalogMountProfileForTest(t *testing.T, datasetID string, version int64, coverage CoveragePolicy) ([]byte, DatasetProfile) {
	t.Helper()
	spec := validDatasetProfileSpec(t)
	key, err := NewProfileKey(datasetID, version)
	if err != nil {
		t.Fatal(err)
	}
	spec.Key = key
	spec.Coverage = coverage
	raw, canonicalHash := canonicalProfileForTest(t, spec)
	profile, err := NewDatasetProfile(spec)
	if err != nil {
		t.Fatal(err)
	}
	if !profile.Valid() || profile.Hash() != canonicalHash {
		t.Fatal("profile fixture disagrees with its own canonical wire bytes")
	}
	return raw, profile
}

func TestDecodeDatasetProfileCatalogJSONSealsTrustedEntries(t *testing.T) {
	alphaRaw, alpha := catalogMountProfileForTest(t, "alpha", 1, CoverageUnknown)
	betaRaw, beta := catalogMountProfileForTest(t, "beta", 1, CoverageSourceGuaranteed)
	wire := datasetProfileCatalogMountJSONForTest(t, "catalog.operations", 7,
		catalogMountEntryForTest{state: "RETIRED", profile: betaRaw},
		catalogMountEntryForTest{state: "ACTIVE", profile: alphaRaw},
	)

	catalog, err := DecodeDatasetProfileCatalogJSON(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !catalog.Valid() || catalog.ID() != "catalog.operations" || catalog.Revision() != 7 {
		t.Fatalf("decoded catalog invalid: valid=%v id=%q revision=%d", catalog.Valid(), catalog.ID(), catalog.Revision())
	}

	// The seal is recomputed from the trusted profiles, in canonical key order,
	// exactly as the constructor does for server-owned inputs.
	expected, err := NewDatasetProfileCatalog("catalog.operations", 7, []CatalogEntryInput{
		catalogEntry(alpha, ProfileActive),
		catalogEntry(beta, ProfileRetired),
	})
	if err != nil {
		t.Fatal(err)
	}
	if catalog.Hash() != expected.Hash() {
		t.Fatalf("catalog hash=%q want independently sealed %q", catalog.Hash(), expected.Hash())
	}

	entries := catalog.Entries()
	if len(entries) != 2 || entries[0].Profile.Key() != alpha.Key() || entries[0].State != ProfileActive ||
		entries[1].Profile.Key() != beta.Key() || entries[1].State != ProfileRetired {
		t.Fatalf("entries=%+v", entries)
	}

	// Wire order and repeated decodes must not change the deterministic seal.
	swapped, err := DecodeDatasetProfileCatalogJSON(datasetProfileCatalogMountJSONForTest(t, "catalog.operations", 7,
		catalogMountEntryForTest{state: "ACTIVE", profile: alphaRaw},
		catalogMountEntryForTest{state: "RETIRED", profile: betaRaw},
	))
	if err != nil || swapped.Hash() != catalog.Hash() {
		t.Fatalf("reordered wire hash=%q err=%v want=%q", swapped.Hash(), err, catalog.Hash())
	}
	again, err := DecodeDatasetProfileCatalogJSON(append([]byte(nil), wire...))
	if err != nil || again.Hash() != catalog.Hash() {
		t.Fatalf("deterministic decode hash=%q err=%v want=%q", again.Hash(), err, catalog.Hash())
	}

	// Exact active lookup requires both the profile key and the computed hash.
	resolved, found := catalog.ResolveActive(alpha.Key(), alpha.Hash())
	if !found || !resolved.Valid() || resolved.Hash() != alpha.Hash() {
		t.Fatalf("exact active lookup found=%v hash=%q", found, resolved.Hash())
	}
	if _, found := catalog.ResolveActive(beta.Key(), beta.Hash()); found {
		t.Fatal("retired entry resolved active")
	}
	if _, found := catalog.ResolveActive(alpha.Key(), beta.Hash()); found {
		t.Fatal("wrong computed profile hash resolved active")
	}
	unknown, err := NewProfileKey("alpha", 9)
	if err != nil {
		t.Fatal(err)
	}
	if _, found := catalog.ResolveActive(unknown, alpha.Hash()); found {
		t.Fatal("unknown version resolved active")
	}
}

func TestDecodeDatasetProfileCatalogJSONRejectsInvalidWire(t *testing.T) {
	activeRaw, active := catalogMountProfileForTest(t, "alpha", 1, CoverageUnknown)
	otherRaw, _ := catalogMountProfileForTest(t, "alpha", 1, CoverageSourceGuaranteed)
	retiredRaw, _ := catalogMountProfileForTest(t, "beta", 1, CoverageUnknown)
	valid := datasetProfileCatalogMountJSONForTest(t, "catalog.operations", 7,
		catalogMountEntryForTest{state: "ACTIVE", profile: activeRaw},
		catalogMountEntryForTest{state: "RETIRED", profile: retiredRaw},
	)
	single := datasetProfileCatalogMountJSONForTest(t, "catalog.operations", 7,
		catalogMountEntryForTest{state: "ACTIVE", profile: activeRaw},
	)
	sealed, _ := canonicalDatasetProfileCatalogForTest(t, mustDatasetProfileCatalogCanonicalTest(t,
		"catalog.operations", 7, []CatalogEntryInput{catalogEntry(active, ProfileActive)}))
	entry := func(body string) []byte { return datasetProfileCatalogMountJSONWithEntriesForTest(body) }

	cases := map[string][]byte{
		"empty":                nil,
		"blank":                []byte(`   `),
		"top null":             []byte(`null`),
		"top array":            []byte(`[]`),
		"top scalar":           []byte(`"catalog"`),
		"trailing value":       append(append([]byte(nil), valid...), []byte(` {}`)...),
		"sealed envelope":      sealed,
		"wrong schema":         replaceDatasetProfileCatalogJSON(t, valid, `"schema_version":"knowvault-dataset-profile-catalog-mount-v1"`, `"schema_version":"knowvault-dataset-profile-catalog-v1"`),
		"missing schema":       replaceDatasetProfileCatalogJSON(t, valid, `"schema_version":"knowvault-dataset-profile-catalog-mount-v1",`, ``),
		"null schema":          replaceDatasetProfileCatalogJSON(t, valid, `"schema_version":"knowvault-dataset-profile-catalog-mount-v1"`, `"schema_version":null`),
		"duplicate schema":     replaceDatasetProfileCatalogJSON(t, valid, `"schema_version":`, `"schema_version":"knowvault-dataset-profile-catalog-mount-v1","schema_version":`),
		"empty catalog id":     replaceDatasetProfileCatalogJSON(t, valid, `"catalog_id":"catalog.operations"`, `"catalog_id":""`),
		"null catalog id":      replaceDatasetProfileCatalogJSON(t, valid, `"catalog_id":"catalog.operations"`, `"catalog_id":null`),
		"missing catalog id":   replaceDatasetProfileCatalogJSON(t, valid, `"catalog_id":"catalog.operations",`, ``),
		"duplicate catalog id": replaceDatasetProfileCatalogJSON(t, valid, `"catalog_id":`, `"catalog_id":"catalog.operations","catalog_id":`),
		"zero revision":        replaceDatasetProfileCatalogJSON(t, valid, `"revision":7`, `"revision":0`),
		"negative revision":    replaceDatasetProfileCatalogJSON(t, valid, `"revision":7`, `"revision":-1`),
		"null revision":        replaceDatasetProfileCatalogJSON(t, valid, `"revision":7`, `"revision":null`),
		"string revision":      replaceDatasetProfileCatalogJSON(t, valid, `"revision":7`, `"revision":"7"`),
		"missing revision":     replaceDatasetProfileCatalogJSON(t, valid, `"revision":7,`, ``),
		"null entries":         []byte(`{"schema_version":"knowvault-dataset-profile-catalog-mount-v1","catalog_id":"catalog.operations","revision":7,"entries":null}`),
		"missing entries":      []byte(`{"schema_version":"knowvault-dataset-profile-catalog-mount-v1","catalog_id":"catalog.operations","revision":7}`),
		"entries not array":    []byte(`{"schema_version":"knowvault-dataset-profile-catalog-mount-v1","catalog_id":"catalog.operations","revision":7,"entries":{}}`),
		"empty entries":        datasetProfileCatalogMountJSONForTest(t, "catalog.operations", 7),
		"duplicate entries":    replaceDatasetProfileCatalogJSON(t, valid, `"entries":[`, `"entries":[],"entries":[`),

		"entry null":            entry(`null`),
		"entry not object":      entry(`[]`),
		"entry null state":      entry(`{"state":null,"profile":` + string(activeRaw) + `}`),
		"entry missing state":   entry(`{"profile":` + string(activeRaw) + `}`),
		"entry empty state":     entry(`{"state":"","profile":` + string(activeRaw) + `}`),
		"entry unknown state":   entry(`{"state":"PENDING","profile":` + string(activeRaw) + `}`),
		"entry duplicate state": entry(`{"state":"ACTIVE","state":"RETIRED","profile":` + string(activeRaw) + `}`),
		"entry null profile":    entry(`{"state":"ACTIVE","profile":null}`),
		"entry missing profile": entry(`{"state":"ACTIVE"}`),
		"entry duplicate profile": entry(`{"state":"ACTIVE","profile":` + string(activeRaw) +
			`,"profile":` + string(activeRaw) + `}`),
		"entry unknown profile hash": entry(`{"state":"ACTIVE","profile_hash":"sha256:` +
			strings.Repeat("b", 64) + `","profile":` + string(activeRaw) + `}`),
		"entry sql": entry(`{"state":"ACTIVE","sql":"SELECT 1","profile":` + string(activeRaw) + `}`),
		"duplicate entry": entry(`{"state":"ACTIVE","profile":` + string(activeRaw) +
			`},{"state":"ACTIVE","profile":` + string(activeRaw) + `}`),
		"duplicate profile key": entry(`{"state":"ACTIVE","profile":` + string(activeRaw) +
			`},{"state":"RETIRED","profile":` + string(otherRaw) + `}`),

		"profile unknown sql": replaceDatasetProfileCatalogJSON(t, single,
			`"mode":"LIVE"`, `"mode":"LIVE","sql":"SELECT 1"`),
		"profile unknown endpoint": replaceDatasetProfileCatalogJSON(t, single,
			`"source_scope_id":"gm"`, `"source_scope_id":"gm","endpoint":"postgres://forbidden.invalid:5432/gm"`),
		"profile unknown dsn": replaceDatasetProfileCatalogJSON(t, single,
			`"relation_name":"operations"`, `"relation_name":"operations","dsn_file":"dsn"`),
		"profile unknown credentials": replaceDatasetProfileCatalogJSON(t, single,
			`"connection_id":"primary"`, `"connection_id":"primary","credentials":{"password":"forbidden"}`),
		"profile unknown relation override": replaceDatasetProfileCatalogJSON(t, single,
			`"relation_name":"operations"`, `"relation_name":"operations","relation_name_override":"operations_other"`),
		"profile duplicate nested": replaceDatasetProfileCatalogJSON(t, single,
			`"source_scope_id":"gm"`, `"source_scope_id":"gm","source_scope_id":"other"`),
		"profile null object": replaceDatasetProfileCatalogJSON(t, single,
			`"key":{"dataset_id":"alpha","version":1}`, `"key":null`),
		"profile null array": replaceDatasetProfileCatalogJSON(t, single,
			`"allowed_ops":[]`, `"allowed_ops":null`),
		"profile missing scalar": replaceDatasetProfileCatalogJSON(t, single,
			`"output_allowed":true,`, ``),
		"profile invalid mode": replaceDatasetProfileCatalogJSON(t, single,
			`"mode":"LIVE"`, `"mode":"ADHOC"`),
		"profile invalid coverage": replaceDatasetProfileCatalogJSON(t, single,
			`"coverage":"UNKNOWN"`, `"coverage":"COMPLETE"`),
	}
	for name, member := range map[string]string{
		"catalog hash":      `"catalog_hash":"sha256:` + strings.Repeat("a", 64) + `"`,
		"profile hash":      `"profile_hash":"sha256:` + strings.Repeat("b", 64) + `"`,
		"sql":               `"sql":"SELECT 1"`,
		"endpoint":          `"endpoint":"postgres://forbidden.invalid:5432/gm"`,
		"dsn":               `"dsn":"host=forbidden"`,
		"credentials":       `"credentials":{"password":"forbidden"}`,
		"relation override": `"relation_name_override":"operations_other"`,
		"raw profile":       `"profile":{}`,
	} {
		cases["top unknown "+name] = replaceDatasetProfileCatalogJSON(t, valid,
			`"schema_version":"knowvault-dataset-profile-catalog-mount-v1"`,
			member+`,"schema_version":"knowvault-dataset-profile-catalog-mount-v1"`)
	}

	for name, candidate := range cases {
		t.Run(name, func(t *testing.T) { assertInvalidDatasetProfileCatalogJSON(t, candidate) })
	}
}

func TestDecodeDatasetProfileCatalogJSONDetachesNestedValues(t *testing.T) {
	alphaRaw, alpha := catalogMountProfileForTest(t, "alpha", 1, CoverageUnknown)
	wire := datasetProfileCatalogMountJSONForTest(t, "catalog.operations", 3,
		catalogMountEntryForTest{state: "ACTIVE", profile: alphaRaw},
	)
	catalog, err := DecodeDatasetProfileCatalogJSON(wire)
	if err != nil {
		t.Fatal(err)
	}
	expectedHash := catalog.Hash()

	// The sealed catalog must not be backed by the caller-owned wire buffer.
	for index := range wire {
		wire[index] = ' '
	}
	if !catalog.Valid() || catalog.Hash() != expectedHash {
		t.Fatal("sealed catalog depends on the caller-owned wire buffer")
	}

	entries := catalog.Entries()
	entries[0].State = ProfileRetired
	entries[0].Profile.fields[0] = FieldSpec{}
	entries[0].Profile.measures[0] = MeasureSpec{}
	entries[0].Profile.coverage = CoverageSourceGuaranteed

	resolved, found := catalog.ResolveActive(alpha.Key(), alpha.Hash())
	if !found {
		t.Fatal("exact active lookup failed after returned entries were mutated")
	}
	fields := resolved.Fields()
	semantics := resolved.Semantics().Values()
	grain := resolved.Grain().Values()
	fields[0] = FieldSpec{}
	semantics.Fields[0].Token = "mutated"
	grain.KeyFields[0] = "mutated"

	inspected, found := catalog.Inspect(alpha.Key())
	if !found {
		t.Fatal("inspect failed")
	}
	inspected.Profile.fields[0] = FieldSpec{}
	inspected.Profile.measures[0] = MeasureSpec{}

	again, found := catalog.ResolveActive(alpha.Key(), alpha.Hash())
	if !catalog.Valid() || catalog.Hash() != expectedHash || !found || !again.Valid() ||
		!reflect.DeepEqual(again.Fields(), alpha.Fields()) ||
		!reflect.DeepEqual(again.Semantics().Values(), alpha.Semantics().Values()) ||
		!reflect.DeepEqual(again.Grain().Values(), alpha.Grain().Values()) {
		t.Fatal("decoded catalog exposed caller-owned nested values")
	}
}

func TestDecodeDatasetProfileCatalogJSONAcceptsExactSizeLimit(t *testing.T) {
	alphaRaw, _ := catalogMountProfileForTest(t, "alpha", 1, CoverageUnknown)
	wire := datasetProfileCatalogMountJSONForTest(t, "catalog.operations", 7,
		catalogMountEntryForTest{state: "ACTIVE", profile: alphaRaw},
	)
	if len(wire) > maxDatasetProfileCatalogJSONBytes {
		t.Fatalf("fixture already exceeds the limit: %d", len(wire))
	}
	exact := append(append([]byte(nil), wire...),
		bytes.Repeat([]byte{' '}, maxDatasetProfileCatalogJSONBytes-len(wire))...)
	if len(exact) != maxDatasetProfileCatalogJSONBytes {
		t.Fatalf("exact fixture length=%d", len(exact))
	}
	catalog, err := DecodeDatasetProfileCatalogJSON(exact)
	if err != nil || !catalog.Valid() {
		t.Fatalf("valid JSON at exact size limit rejected: valid=%v err=%v", catalog.Valid(), err)
	}

	oversize := append(append([]byte(nil), exact...), ' ')
	if len(oversize) != maxDatasetProfileCatalogJSONBytes+1 {
		t.Fatalf("oversize fixture length=%d", len(oversize))
	}
	assertInvalidDatasetProfileCatalogJSON(t, oversize)
	assertInvalidDatasetProfileCatalogJSON(t, bytes.Repeat([]byte{' '}, maxDatasetProfileCatalogJSONBytes+1))
}

func replaceDatasetProfileCatalogJSON(t *testing.T, raw []byte, old, replacement string) []byte {
	t.Helper()
	if !bytes.Contains(raw, []byte(old)) {
		t.Fatalf("fixture does not contain %q", old)
	}
	return bytes.Replace(append([]byte(nil), raw...), []byte(old), []byte(replacement), 1)
}

func assertInvalidDatasetProfileCatalogJSON(t *testing.T, raw []byte) {
	t.Helper()
	catalog, err := DecodeDatasetProfileCatalogJSON(raw)
	if err == nil || catalog.Valid() || CodeOf(err) != CodeInvalidRequest ||
		err.Error() != string(CodeInvalidRequest) || errors.Unwrap(err) != nil {
		t.Fatalf("invalid JSON accepted or leaked detail: valid=%v err=%#v", catalog.Valid(), err)
	}
	if catalog.ID() != "" || catalog.Revision() != 0 || catalog.Hash() != "" || catalog.Entries() != nil {
		t.Fatal("invalid JSON returned partial catalog data")
	}
}
