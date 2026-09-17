package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuntimeMountGroupsKeepWorkerDistinct(t *testing.T) {
	for name, mutation := range map[string]func(map[string]string){
		"valid":                    func(map[string]string) {},
		"worker uses parser group": func(files map[string]string) { files["deploy/images/Dockerfile.worker"] = "USER 65532:65532\n" },
		"server uses worker group": func(files map[string]string) { files["deploy/images/Dockerfile.server"] = "USER 65530:65530\n" },
		"worker mount uses parser group": func(files map[string]string) {
			files["deploy/images/Dockerfile.worker"] += "COPY --chown=0:65532 /a /b\n"
		},
		"identity collision": func(files map[string]string) {
			files["internal/platform/runtimeidentity/mounts.go"] = "const ServerGroupID = 65532\nconst WorkerGroupID = 65532\n"
		},
		"reversed loader alias": func(files map[string]string) {
			path := "internal/platform/secretmount/provider.go"
			files[path] = strings.ReplaceAll(files[path], "const WorkerRuntimeGID = runtimeidentity.WorkerGroupID", "const WorkerRuntimeGID = runtimeidentity.ServerGroupID")
		},
		"unknown documented group":     func(files map[string]string) { files["deploy/images/README.md"] += "root:65599 0750\n" },
		"missing worker documentation": func(files map[string]string) { files["deploy/images/README.md"] = "root:65532 0750\n" },
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			files := map[string]string{
				"internal/platform/runtimeidentity/mounts.go": "const ServerGroupID = 65532\nconst WorkerGroupID = 65530\n",
				"internal/platform/secretmount/provider.go":   "const RuntimeGID = runtimeidentity.ServerGroupID\nconst WorkerRuntimeGID = runtimeidentity.WorkerGroupID\n",
				"deploy/images/Dockerfile.server":             "USER 65532:65532\n",
				"deploy/images/Dockerfile.worker":             "USER 65530:65530\n",
				"deploy/images/README.md":                     "server root:65532 0750\nworker root:65530 0750\n",
			}
			mutation(files)
			for path, content := range files {
				absolute := filepath.Join(root, filepath.FromSlash(path))
				if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(absolute, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			problems := checkRuntimeGIDConsistency(root)
			if name == "valid" && len(problems) != 0 {
				t.Fatalf("valid role split rejected: %v", problems)
			}
			if name != "valid" && len(problems) == 0 {
				t.Fatal("role ownership drift passed")
			}
		})
	}
}
