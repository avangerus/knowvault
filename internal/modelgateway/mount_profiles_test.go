package modelgateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeProfileTestJSON(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func profileTestManifest() mountedProfiles {
	return mountedProfiles{SchemaVersion: ProfilesSchemaVersion, DefaultProfileID: "local", Profiles: []mountedProfileLocation{
		{ID: "local", Label: "Local Qwen", ConfigDirectory: "."},
		{ID: "cloud", Label: "Cloud DeepSeek", ConfigDirectory: "cloud"},
	}}
}

func createProfileTestMount(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	cloud := filepath.Join(root, "cloud")
	if err := os.Mkdir(cloud, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		dir      string
		external bool
	}{{root, false}, {cloud, true}} {
		config := testNamedProfileConfig("local-model", item.external)
		if item.external {
			config.ModelID = "cloud-model"
		}
		mounted := mountedLabConfig{SchemaVersion: config.SchemaVersion, Endpoint: config.Endpoint, ModelID: config.ModelID,
			ThinkingMode: config.ThinkingMode, InsecureLabMode: true, TimeoutSeconds: 120, MaxOutputTokens: 2048, ToolLoop: config.ToolLoop,
			ExternalRuntimeWorkspaceIDs: config.ExternalRuntimeWorkspaceIDs}
		if item.external {
			mounted.APIKeyFile, mounted.TrustBundleFile = "api-key", "trust.pem"
			if err := os.WriteFile(filepath.Join(cloud, "api-key"), []byte("unit-test-secret"), 0o600); err != nil {
				t.Fatal(err)
			}
			writeTestTrustBundle(t, cloud, "trust.pem")
		}
		writeProfileTestJSON(t, filepath.Join(item.dir, "config.json"), mounted)
	}
	writeProfileTestJSON(t, filepath.Join(root, profilesFilename), profileTestManifest())
	return root
}

func TestMountedProfilesKeepLocalDefaultAndFilterCloud(t *testing.T) {
	root := createProfileTestMount(t)
	registry, err := LoadMountedProfilesAt(root)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	if registry.Default().ProviderName() != "local-model" || len(registry.List("law")) != 2 || len(registry.List("puit")) != 1 {
		t.Fatal("mounted registry changed default or external scope")
	}
	cloud, err := registry.Select("law", "cloud")
	if err != nil || cloud.RuntimeScope() != RuntimeScopeExternalWorkspaceScoped || cloud.config.APIKey != "unit-test-secret" || cloud.config.TrustRoots == nil {
		t.Fatal("cloud profile did not load its own secret/trust")
	}
	if registry.Default().config.APIKey != "" || registry.Default().config.TrustRoots != nil {
		t.Fatal("cloud transport settings leaked into local adapter")
	}
}

func TestMountedProfilesPreserveLegacySingleLocalAndCloud(t *testing.T) {
	for _, cloud := range []bool{false, true} {
		t.Run(map[bool]string{false: "local", true: "external"}[cloud], func(t *testing.T) {
			root := createProfileTestMount(t)
			if err := os.Remove(filepath.Join(root, profilesFilename)); err != nil {
				t.Fatal(err)
			}
			if cloud {
				for _, filename := range []string{"config.json", "api-key", "trust.pem"} {
					raw, err := os.ReadFile(filepath.Join(root, "cloud", filename))
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(root, filename), raw, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			registry, err := LoadMountedProfilesAt(root)
			if err != nil {
				t.Fatal(err)
			}
			defer registry.Close()
			list := registry.List("law")
			if len(list) != 1 || list[0].ID != "default" || !list[0].IsDefault {
				t.Fatal("legacy default changed")
			}
			if adapter, err := registry.Select("law", ""); err != nil || adapter != registry.Default() {
				t.Fatal("legacy empty selection unavailable")
			}
			if cloud && len(registry.List("puit")) != 0 {
				t.Fatal("legacy cloud policy widened")
			}
		})
	}
	for _, root := range []string{"", filepath.Join(t.TempDir(), "absent")} {
		if _, err := LoadMountedProfilesAt(root); CodeOf(err) != CodeLabMountUnavailable {
			t.Fatalf("absent legacy mount changed: %v", err)
		}
	}
}

func TestMountedProfilesSingleManifestRequiresLocalDefault(t *testing.T) {
	root := createProfileTestMount(t)
	manifest := profileTestManifest()
	manifest.Profiles = manifest.Profiles[:1]
	writeProfileTestJSON(t, filepath.Join(root, profilesFilename), manifest)
	registry, err := LoadMountedProfilesAt(root)
	if err != nil {
		t.Fatal(err)
	}
	_ = registry.Close()
	// Unlike a legacy mount with no manifest, even a one-entry manifest
	// explicitly promises a local default. Use a fully valid external config
	// here so rejection cannot be explained by a missing key or trust bundle.
	for _, filename := range []string{"config.json", "api-key", "trust.pem"} {
		raw, err := os.ReadFile(filepath.Join(root, "cloud", filename))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, filename), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	assertInvalidProfileMount(t, root)
}

func TestMountedProfilesRejectMalformedManifestWithoutLegacyFallback(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*mountedProfiles)
	}{
		{"unknown-schema", func(m *mountedProfiles) { m.SchemaVersion = "unknown" }},
		{"missing-default", func(m *mountedProfiles) { m.DefaultProfileID = "absent" }},
		{"duplicate-id", func(m *mountedProfiles) { m.Profiles[1].ID = "local" }},
		{"duplicate-directory", func(m *mountedProfiles) { m.Profiles[1].ConfigDirectory = "." }},
		{"default-in-child", func(m *mountedProfiles) { m.Profiles[0].ConfigDirectory = "cloud" }},
		{"parent-directory", func(m *mountedProfiles) { m.Profiles[1].ConfigDirectory = ".." }},
		{"traversal", func(m *mountedProfiles) { m.Profiles[1].ConfigDirectory = "../cloud" }},
		{"nested-directory", func(m *mountedProfiles) { m.Profiles[1].ConfigDirectory = "cloud/sub" }},
		{"windows-directory", func(m *mountedProfiles) { m.Profiles[1].ConfigDirectory = `cloud\sub` }},
		{"absolute-directory", func(m *mountedProfiles) { m.Profiles[1].ConfigDirectory = "/cloud" }},
		{"long-label", func(m *mountedProfiles) { m.Profiles[1].Label = strings.Repeat("a", 81) }},
		{"control-label", func(m *mountedProfiles) { m.Profiles[1].Label = "Cloud\nLocal" }},
		{"long-id", func(m *mountedProfiles) { m.Profiles[1].ID = strings.Repeat("a", 65) }},
		{"empty-profiles", func(m *mountedProfiles) { m.Profiles = nil }},
		{"too-many", func(m *mountedProfiles) {
			for len(m.Profiles) < 9 {
				m.Profiles = append(m.Profiles, m.Profiles[1])
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := createProfileTestMount(t)
			manifest := profileTestManifest()
			test.edit(&manifest)
			writeProfileTestJSON(t, filepath.Join(root, profilesFilename), manifest)
			assertInvalidProfileMount(t, root)
		})
	}
	for _, raw := range []string{
		`{"schema_version":"model-gateway-profiles-v1","schema_version":"model-gateway-profiles-v1"}`,
		`{"schema_version":"model-gateway-profiles-v1","default_profile_id":"local","profiles":[],"unexpected":true}`,
		strings.Repeat(" ", maximumLabConfigBytes+1),
	} {
		root := createProfileTestMount(t)
		if err := os.WriteFile(filepath.Join(root, profilesFilename), []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		assertInvalidProfileMount(t, root)
	}
}

func assertInvalidProfileMount(t *testing.T, root string) {
	t.Helper()
	registry, err := LoadMountedProfilesAt(root)
	if registry != nil {
		_ = registry.Close()
	}
	if CodeOf(err) != CodeLabMountInvalid {
		t.Fatalf("invalid profile mount did not fail closed: %v", err)
	}
}

func TestMountedProfilesRejectSymlinksAndMissingProfileMaterial(t *testing.T) {
	root := createProfileTestMount(t)
	alias := filepath.Join(t.TempDir(), "generation")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	assertInvalidProfileMount(t, alias)
	for _, relative := range []string{profilesFilename, "cloud", "config.json", "cloud/config.json", "cloud/api-key", "cloud/trust.pem"} {
		t.Run(relative, func(t *testing.T) {
			root := createProfileTestMount(t)
			path := filepath.Join(root, relative)
			moved := filepath.Join(t.TempDir(), "moved")
			if err := os.Rename(path, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, path); err != nil {
				t.Fatal(err)
			}
			assertInvalidProfileMount(t, root)
		})
	}
	for _, relative := range []string{"cloud/config.json", "cloud/api-key", "cloud/trust.pem"} {
		root := createProfileTestMount(t)
		if err := os.Remove(filepath.Join(root, relative)); err != nil {
			t.Fatal(err)
		}
		assertInvalidProfileMount(t, root)
	}
}

func TestMountedProfilesRejectMisclassifiedRuntimeAndInvalidCloudConfig(t *testing.T) {
	for _, test := range []struct {
		name, relative string
		edit           func(*mountedLabConfig)
	}{
		{"external-default", "config.json", func(c *mountedLabConfig) {
			c.ExternalRuntimeWorkspaceIDs = []string{"law"}
			c.TrustBundleFile = "trust.pem"
		}},
		{"external-private", "cloud/config.json", func(c *mountedLabConfig) { c.Endpoint = "https://127.0.0.1:443/v1" }},
		{"external-link-local", "cloud/config.json", func(c *mountedLabConfig) { c.Endpoint = "https://169.254.169.254/v1" }},
		{"external-no-allowlist", "cloud/config.json", func(c *mountedLabConfig) { c.ExternalRuntimeWorkspaceIDs = nil }},
		{"external-plain-http", "cloud/config.json", func(c *mountedLabConfig) { c.Endpoint = "http://provider.example/v1" }},
		{"external-no-trust", "cloud/config.json", func(c *mountedLabConfig) { c.TrustBundleFile = "" }},
		{"external-key-traversal", "cloud/config.json", func(c *mountedLabConfig) { c.APIKeyFile = "../api-key" }},
		{"external-wrong-schema", "cloud/config.json", func(c *mountedLabConfig) { c.SchemaVersion = "invalid" }},
		{"external-invalid-bounds", "cloud/config.json", func(c *mountedLabConfig) { c.ToolLoop.MaxTurns = 21 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := createProfileTestMount(t)
			writeTestTrustBundle(t, root, "trust.pem")
			path := filepath.Join(root, test.relative)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var config mountedLabConfig
			if err := json.Unmarshal(raw, &config); err != nil {
				t.Fatal(err)
			}
			test.edit(&config)
			writeProfileTestJSON(t, path, config)
			assertInvalidProfileMount(t, root)
		})
	}
}
