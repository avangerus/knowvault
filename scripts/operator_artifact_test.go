package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOperatorArtifactSupplyContract(t *testing.T) {
	if problems := checkOperatorArtifact(".."); len(problems) != 0 {
		t.Fatalf("operator artifact contract is not satisfied: %v", problems)
	}
}

func TestOperatorArtifactRejectsIdentityAndInputDrift(t *testing.T) {
	lockRaw, err := os.ReadFile(filepath.Join("..", "architecture", "versions.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock any
	if err := json.Unmarshal(lockRaw, &lock); err != nil {
		t.Fatal(err)
	}
	artifact := lock.(map[string]any)["operator_artifact"].(map[string]any)
	artifact["artifact_identity"] = "sha256:" + strings.Repeat("0", 64)
	if problems := validateOperatorArtifact(lock); len(problems) == 0 {
		t.Fatal("zero artifact identity was accepted")
	}

	root := t.TempDir()
	for _, relative := range []string{
		"architecture/versions.json",
		"deploy/images/Dockerfile.operator",
		"deploy/images/Dockerfile.operator.dockerignore",
	} {
		raw, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	dockerfilePath := filepath.Join(root, "deploy", "images", "Dockerfile.operator")
	dockerfile, err := os.ReadFile(dockerfilePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dockerfilePath, []byte(strings.Replace(string(dockerfile),
		"COPY db/migrations ./db/migrations", "COPY db/ ./db/", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if problems := checkOperatorArtifact(root); len(problems) == 0 {
		t.Fatal("operator migration input drift was accepted")
	}
}
