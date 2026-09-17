package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDeploymentImagePinsDistinguishPythonImports(t *testing.T) {
	pinned := "alpine:3.23@sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		name, path, content string
		wantRejected        bool
	}{
		{"python imports", "deploy/supervisor/worker.py", "from __future__ import annotations\nfrom dataclasses import dataclass\nfrom .models import Value\n", false},
		{"pinned docker", "deploy/images/Dockerfile.worker", "FROM " + pinned + "\nFROM scratch\n", false},
		{"unpinned docker", "deploy/images/Dockerfile.worker", "FROM alpine:3.23\n", true},
		{"lowercase docker", "deploy/images/Dockerfile.worker", "from alpine:latest\n", true},
		{"docker is not python", "deploy/images/Dockerfile.worker", "from invalid import bad\n", true},
		{"compose pin", "deploy/compose.yaml", "services:\n  worker:\n    image: " + pinned + "\n", false},
		{"compose latest", "deploy/compose.yaml", "services:\n  worker:\n    image: alpine:latest\n", true},
		{"github service", ".github/workflows/build.yml", "  image: alpine:3.23\n", true},
		{"gitlab service", ".gitlab/build.yml", "image: alpine:3.23\n", true},
		{"python embedded docker", "deploy/build.py", "from pathlib import Path\nTEMPLATE = '''\nFROM alpine:latest\n'''\n", true},
		{"python embedded lower docker", "deploy/build.py", "from pathlib import Path\nTEMPLATE = '''\nfrom alpine:3.23\n'''\n", true},
		{"python pinned embedded docker", "deploy/build.py", "from pathlib import Path\nTEMPLATE = '''\nFROM " + pinned + "\n'''\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, filepath.FromSlash(tc.path))
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			problems := checkDeploymentManifests(root)
			if (len(problems) > 0) != tc.wantRejected {
				t.Fatalf("rejected=%t, want %t: %v", len(problems) > 0, tc.wantRejected, problems)
			}
		})
	}
}
