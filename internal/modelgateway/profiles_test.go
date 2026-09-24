package modelgateway

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func testNamedProfileConfig(model string, external bool) LabAdapterConfig {
	config := LabAdapterConfig{
		SchemaVersion: LabAdapterSchemaVersion, Endpoint: "http://127.0.0.1:8088/v1", ModelID: model,
		ThinkingMode: ThinkingModeDisabled, InsecureLabMode: true, MaxOutputTokens: 2048, ToolLoop: testConverseProfile(),
	}
	if external {
		config.Endpoint = "https://provider.example/v1"
		config.APIKey = "unit-test-secret-never-expose"
		config.TrustRoots = x509.NewCertPool()
		config.ExternalRuntimeWorkspaceIDs = []string{"law"}
	}
	return config
}

func testProfileRegistry(t *testing.T) *ProfileRegistry {
	t.Helper()
	registry, err := NewProfileRegistry("local", []ProfileConfig{
		{ID: "local", Label: "Local model", Config: testNamedProfileConfig("local-model", false)},
		{ID: "cloud", Label: "Cloud model", Config: testNamedProfileConfig("cloud-model", true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = registry.Close() })
	return registry
}

func TestProfileRegistryFiltersWorkspaceAndNeverFallsBack(t *testing.T) {
	registry := testProfileRegistry(t)
	law := registry.List("law")
	if len(law) != 2 || law[0].ID != "local" || !law[0].IsDefault || law[0].Location != "INTERNAL" || law[1].Location != "EXTERNAL" || law[1].IsDefault {
		t.Fatalf("unexpected law catalog: %#v", law)
	}
	puit := registry.List("puit")
	if len(puit) != 1 || puit[0].ID != "local" || len(registry.List("")) != 0 {
		t.Fatalf("external profile leaked into a forbidden catalog: %#v", puit)
	}
	for _, test := range []struct{ workspace, id string }{{"puit", "cloud"}, {"law", "unknown"}, {"law", " local"}, {"", "local"}, {"law", strings.Repeat("x", 65)}} {
		if adapter, err := registry.Select(test.workspace, test.id); adapter != nil || CodeOf(err) != CodeProfile {
			t.Fatalf("invalid/forbidden selection fell back: %+v", test)
		}
	}
	adapter, err := registry.Select("puit", "")
	if err != nil || adapter != registry.Default() || adapter.ProviderName() != "local-model" {
		t.Fatalf("legacy default changed: %v", err)
	}
	law[0].Label = "changed by caller"
	if registry.List("law")[0].Label != "Local model" {
		t.Fatal("caller mutated shared catalog")
	}
	encoded, err := json.Marshal(registry.List("law"))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"provider.example", "unit-test-secret", "api_key", "trust", "workspace_ids", "config_directory"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("transport detail leaked: %s", secret)
		}
	}
}

type profileDenyTransport struct{ calls atomic.Int32 }

func (transport *profileDenyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	transport.calls.Add(1)
	return nil, errors.New("network must not be reached")
}

func TestProfileRegistryForbiddenWorkspaceCannotReachProvider(t *testing.T) {
	registry := testProfileRegistry(t)
	cloud, err := registry.Select("law", "cloud")
	if err != nil {
		t.Fatal(err)
	}
	transport := &profileDenyTransport{}
	cloud.http = &http.Client{Transport: transport}
	if selected, err := registry.Select("puit", "cloud"); selected != nil || err == nil {
		t.Fatal("forbidden selection accepted")
	}
	// Even an adapter retained by an allowed request cannot send another
	// workspace's messages through Converse.
	_, _, err = cloud.Converse(context.Background(), "puit", []Message{{Role: "system", Content: "rules"}, {Role: "user", Content: "private"}}, testConverseTools())
	if err == nil || transport.calls.Load() != 0 {
		t.Fatal("forbidden workspace content reached provider")
	}
}

func TestProfileRegistryCopiesConfigAndConcurrentSelection(t *testing.T) {
	cloudConfig := testNamedProfileConfig("cloud-model", true)
	registry, err := NewProfileRegistry("local", []ProfileConfig{
		{ID: "local", Label: "Local", Config: testNamedProfileConfig("local-model", false)},
		{ID: "cloud", Label: "Cloud", Config: cloudConfig},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	cloudConfig.ExternalRuntimeWorkspaceIDs[0] = "puit"
	cloudConfig.ToolLoop.MaxTurns = 1
	cloud, err := registry.Select("law", "cloud")
	if err != nil || cloud.config.TrustRoots == cloudConfig.TrustRoots {
		t.Fatal("registry retained caller-owned allow-list or trust pool")
	}
	profile, _ := cloud.ToolLoopProfile()
	if profile.MaxTurns != 8 {
		t.Fatal("registry retained caller-owned tool bounds")
	}
	var group sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for iteration := 0; iteration < 30; iteration++ {
				local, err := registry.Select("puit", "")
				if err != nil || local != registry.Default() || local.ProviderName() != "local-model" {
					t.Error("concurrent local selection changed")
				}
				selected, err := registry.Select("law", "cloud")
				if err != nil || selected != cloud || selected.ProviderName() != "cloud-model" {
					t.Error("concurrent cloud selection changed")
				}
				if selected, err := registry.Select("puit", "cloud"); selected != nil || err == nil {
					t.Error("concurrent selection widened external access")
				}
			}
		}()
	}
	group.Wait()
}

func TestProfileRegistryRejectsAmbiguousOrUnboundedMetadata(t *testing.T) {
	for _, test := range []struct{ name, id, label string }{
		{"empty-id", "", "Label"}, {"long-id", strings.Repeat("a", 65), "Label"}, {"path-id", "../cloud", "Label"},
		{"empty-label", "local", ""}, {"long-label", "local", strings.Repeat("a", 81)},
		{"control-label", "local", "hello\nworld"}, {"format-label", "local", "hello\u202eworld"}, {"html-label", "local", "<b>cloud</b>"},
	} {
		t.Run(test.name, func(t *testing.T) {
			registry, err := NewProfileRegistry("local", []ProfileConfig{{ID: test.id, Label: test.label, Config: testNamedProfileConfig("local-model", false)}})
			if err == nil {
				_ = registry.Close()
				t.Fatal("invalid profile metadata accepted")
			}
		})
	}
	for _, configs := range [][]ProfileConfig{
		{{ID: "local", Label: "One", Config: testNamedProfileConfig("m", false)}, {ID: "local", Label: "Two", Config: testNamedProfileConfig("m", false)}},
		{{ID: "missing-default", Label: "One", Config: testNamedProfileConfig("m", false)}},
	} {
		if registry, err := NewProfileRegistry("local", configs); err == nil {
			_ = registry.Close()
			t.Fatal("ambiguous catalog accepted")
		}
	}
}

// A workspace-scoped cloud profile may be the default next to local ones; it
// stays invisible to every workspace outside its allowlist.
func TestProfileRegistryAllowsWorkspaceScopedCloudDefault(t *testing.T) {
	registry, err := NewProfileRegistry("cloud", []ProfileConfig{
		{ID: "cloud", Label: "Cloud default", Config: testNamedProfileConfig("m", true)},
		{ID: "local", Label: "Local", Config: testNamedProfileConfig("m", false)},
	})
	if err != nil {
		t.Fatalf("workspace-scoped cloud default rejected: %v", err)
	}
	defer registry.Close()
	if registry.Default() == nil || registry.Default().RuntimeScope() != RuntimeScopeExternalWorkspaceScoped {
		t.Fatal("cloud default not selected")
	}
	if len(registry.List("law")) != 2 || len(registry.List("puit")) != 1 {
		t.Fatal("cloud default visible outside its workspace allowlist")
	}
}
