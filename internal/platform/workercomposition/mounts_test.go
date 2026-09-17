package workercomposition

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMountRegistryBindsOnlyExactTrustedTuple(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "finance"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeMountManifest(t, root, `{"schema":"knowvault-source-mount-manifest-v1","roots":[{"alias":"docs-root","identity":"vol-1","directory":"docs"},{"alias":"finance-root","identity":"vol-2","directory":"finance"}]}`)

	registry, err := loadMountRegistry(root)
	if err != nil {
		t.Fatal(err)
	}
	if path, ok := registry.Resolve("docs-root", "vol-1"); !ok || path != filepath.Join(root, "docs") {
		t.Fatalf("docs resolution path=%q ok=%v", path, ok)
	}
	for _, candidate := range []struct{ alias, identity string }{
		{alias: "docs-root", identity: "vol-2"},
		{alias: "../docs", identity: "vol-1"},
		{alias: "docs-root", identity: "../vol-1"},
	} {
		alias, identity := candidate.alias, candidate.identity
		if path, ok := registry.Resolve(alias, identity); ok || path != "" {
			t.Fatalf("untrusted tuple resolved path=%q ok=%v alias=%q identity=%q", path, ok, alias, identity)
		}
	}
}

func TestLoadMountRegistryRejectsStrictManifestViolations(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		`{"schema":"knowvault-source-mount-manifest-v1","roots":[{"alias":"docs-root","identity":"vol-1","directory":"docs"}],"unknown":true}`,
		`{"schema":"knowvault-source-mount-manifest-v1","roots":[{"alias":"docs-root","identity":"vol-1","directory":"../docs"}]}`,
		`{"schema":"knowvault-source-mount-manifest-v1","roots":[{"alias":"docs-root","identity":"vol-1","directory":"docs"},{"alias":"docs-root","identity":"vol-1","directory":"docs"}]}`,
	}
	for index, raw := range cases {
		t.Run(string(rune('a'+index)), func(t *testing.T) {
			writeMountManifest(t, root, raw)
			if registry, err := loadMountRegistry(root); registry != nil || CodeOf(err) != CodeMountsUnavailable {
				t.Fatalf("invalid manifest accepted registry=%#v err=%v", registry, err)
			}
		})
	}
}

func writeMountManifest(t *testing.T, root, raw string) {
	t.Helper()
	path := filepath.Join(root, sourceManifestFilename)
	_ = os.Chmod(path, 0o600)
	if err := os.WriteFile(path, []byte(raw), 0o400); err != nil {
		t.Fatal(err)
	}
}
