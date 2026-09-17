package operator

import (
	"os"
	"path/filepath"
	"testing"
)

// migrationFiles admits only the versioned 0-prefixed stream: a stray *.sql is
// a deployment input error, never a silent skip, and the admitted set is
// sorted so the application order is deterministic.
func TestMigrationFilesVersionedStreamOnly(t *testing.T) {
	dir := t.TempDir()
	for name, contents := range map[string]string{
		"000002_next.sql": "SELECT 2;",
		"000001_init.sql": "SELECT 1;",
		"000003_more.sql": "SELECT 3;",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	names, err := migrationFiles(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 3 || names[0] != "000001_init.sql" || names[1] != "000002_next.sql" || names[2] != "000003_more.sql" {
		t.Fatalf("names=%v", names)
	}
	if err := os.WriteFile(filepath.Join(dir, "notes.sql"), []byte("SELECT 0;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := migrationFiles(dir); err == nil {
		t.Fatal("non-versioned *.sql was silently skipped")
	}
}

func TestMigrationFilesRejectsEmptyDirectory(t *testing.T) {
	if _, err := migrationFiles(t.TempDir()); err == nil {
		t.Fatal("empty migration directory passed")
	}
}
