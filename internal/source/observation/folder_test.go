package observation

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"knowvault.local/verified-workspace/internal/connector/folder"
)

func TestFolderAdapterProducesBoundedTypedObservationFromRealFiles(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "contract.txt")
	content := []byte("a real document observation\n")
	if err := os.WriteFile(file, content, 0o600); err != nil {
		t.Fatal(err)
	}
	platform := folder.PlatformPOSIX
	if runtime.GOOS == "windows" {
		platform = folder.PlatformWindows
	}
	scope, err := folder.NewScope(folder.ScopeParams{
		RootPath: root, Platform: platform, Access: folder.AccessWorkspaceManaged,
		Recursive: true, MaxFileBytes: 1 << 20, Formats: []folder.Format{folder.FormatTXT},
	})
	if err != nil {
		t.Fatalf("compile real folder scope: %v", err)
	}
	adapter, err := NewFolderAdapter(folder.New(), scope, "org_demo", "scope_demo", 1, KindDocument)
	if err != nil {
		t.Fatal(err)
	}
	page, err := adapter.Observe(context.Background(), Request{
		OrganizationID: "org_demo", SourceScopeID: "scope_demo", SourceScopeRevision: 1,
		MaxObjects: 10, MaxBytes: 1 << 20,
	})
	if err != nil {
		t.Fatalf("observe real folder: %v", err)
	}
	if !page.CoverageComplete || len(page.Objects) != 1 {
		t.Fatalf("page=%+v, want one complete observation", page)
	}
	object := page.Objects[0]
	if object.PayloadKind != PayloadBytes || object.Document == nil || string(object.Document.Bytes) != string(content) || object.VersionKey == "" {
		t.Fatalf("unexpected observed object: %+v", object)
	}
}
