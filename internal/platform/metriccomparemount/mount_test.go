package metriccomparemount

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const validProfile = `{
  "workspace_id":"ws_001",
  "connection_id":"customer-gm-live",
  "profile":{
    "exposed_schema_revision":2,
    "metric_id":"gm.assigned-tasks",
    "description":"Assigned-task indicator across subjects at the latest daily snapshot",
    "unit":"unknown",
    "schema":"public",
    "view":"v_kpi_value",
    "subject_column":"subject_id",
    "snapshot_column":"run_time",
    "measure_column":"numeric_value",
    "timezone":"Europe/Moscow",
    "filters":[{"column":"code","value":"contract.manage.taskitems"},{"column":"kpi_range","value":"METER"}]
  }
}`

func writeProfile(t *testing.T, root string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, profileFilename), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func requireCode(t *testing.T, root string, want ErrorCode) {
	t.Helper()
	_, err := LoadMountedAt(root)
	if err == nil || CodeOf(err) != want || err.Error() != string(want) || errors.Unwrap(err) != nil {
		t.Fatalf("mount error %v, want closed %s", err, want)
	}
}

func TestLoadMountedAbsentAndValid(t *testing.T) {
	requireCode(t, filepath.Join(t.TempDir(), "absent"), CodeMountUnavailable)
	root := t.TempDir()
	requireCode(t, root, CodeMountUnavailable)
	writeProfile(t, root, []byte(validProfile))
	mount, err := LoadMountedAt(root)
	if err != nil {
		t.Fatal(err)
	}
	if mount.WorkspaceID != "ws_001" || mount.ConnectionID != "customer-gm-live" ||
		mount.Profile.MetricID() != "gm.assigned-tasks" || mount.Profile.Unit() != "unknown" ||
		mount.Profile.Description() != "Assigned-task indicator across subjects at the latest daily snapshot" ||
		!strings.HasPrefix(mount.Profile.Hash(), "sha256:") {
		t.Fatalf("invalid binding: %+v", mount)
	}
}

func TestLoadMountedRejectsMalformedUnknownDuplicateAndUnsafe(t *testing.T) {
	root := t.TempDir()
	cases := map[string]string{
		"empty":            "",
		"malformed":        "{",
		"unknown top":      strings.Replace(validProfile, `"workspace_id"`, `"extra":1,"workspace_id"`, 1),
		"unknown nested":   strings.Replace(validProfile, `"metric_id"`, `"extra":1,"metric_id"`, 1),
		"control prose":    strings.Replace(validProfile, `"description":"Assigned-task indicator across subjects at the latest daily snapshot"`, `"description":"bad\ntext"`, 1),
		"unknown filter":   strings.Replace(validProfile, `"column"`, `"extra":1,"column"`, 1),
		"duplicate top":    strings.Replace(validProfile, `"workspace_id":"ws_001"`, `"workspace_id":"ws_001","workspace_id":"ws_002"`, 1),
		"duplicate nested": strings.Replace(validProfile, `"unit":"unknown"`, `"unit":"unknown","unit":"tasks"`, 1),
		"unsafe id":        strings.Replace(validProfile, `"workspace_id":"ws_001"`, `"workspace_id":"../ws_001"`, 1),
		"missing profile":  `{"workspace_id":"ws_001","connection_id":"customer-gm-live"}`,
		"invalid spec":     strings.Replace(validProfile, `"measure_column":"numeric_value"`, `"measure_column":"run_time"`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			writeProfile(t, root, []byte(raw))
			requireCode(t, root, CodeMountInvalid)
		})
	}
}

func TestLoadMountedRejectsOversizeAndUnsafeFilesystem(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, bytes.Repeat([]byte{' '}, maximumProfileBytes+1))
	requireCode(t, root, CodeMountInvalid)
	writeProfile(t, root, []byte(validProfile))
	fileRoot := filepath.Join(t.TempDir(), "root-file")
	if err := os.WriteFile(fileRoot, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	requireCode(t, fileRoot, CodeMountInvalid)
	if err := os.Remove(filepath.Join(root, profileFilename)); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, profileFilename), 0o700); err != nil {
		t.Fatal(err)
	}
	requireCode(t, root, CodeMountInvalid)
}

func TestLoadMountedRejectsRootAndFileSymlinks(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, []byte(validProfile))
	rootLink := filepath.Join(t.TempDir(), "root-link")
	if err := os.Symlink(root, rootLink); err != nil {
		if os.IsPermission(err) {
			t.Skipf("symlinks unavailable: %v", err)
		}
		t.Fatal(err)
	}
	requireCode(t, rootLink, CodeMountInvalid)
	fileLinkRoot := t.TempDir()
	if err := os.Symlink(filepath.Join(root, profileFilename), filepath.Join(fileLinkRoot, profileFilename)); err != nil {
		t.Fatal(err)
	}
	requireCode(t, fileLinkRoot, CodeMountInvalid)
}

func TestCodeOfUnknownError(t *testing.T) {
	if CodeOf(nil) != "" || CodeOf(errors.New("private detail")) != CodeMountInvalid {
		t.Fatal("error code leaked detail")
	}
}
