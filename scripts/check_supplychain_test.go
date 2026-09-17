package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- Supply-chain lifecycle boundary (DEFERRED / QUALIFIED_NOT_ACTIVE / ACTIVE) ---

// qualifiedLock is a minimal version lock declaring one QUALIFIED_NOT_ACTIVE
// component isolated to workers/testworker/, plus one component that stays DEFERRED.
const qualifiedLock = `{
  "deferred_runtime_locks": {
    "components": [
      { "id": "maven.apache-poi", "kind": "MAVEN_ARTIFACT", "stage": "STAGE_2", "lifecycle": "QUALIFIED_NOT_ACTIVE" },
      { "id": "maven.apache-pdfbox", "kind": "MAVEN_ARTIFACT", "stage": "STAGE_2", "lifecycle": "DEFERRED" }
    ]
  },
  "deferred_dependency_locks": {
    "stage_gates": {
      "STAGE_2": [
        {
          "id": "maven.apache-poi",
          "kind": "MAVEN_ARTIFACT",
          "lifecycle": "QUALIFIED_NOT_ACTIVE",
          "qualification": {
            "exact_version": "5.5.1",
            "isolated_subtree": "workers/testworker/",
            "leak_tokens": ["org.apache.poi", "apache-poi"],
            "evidence": "docs/evidence.md"
          }
        },
        { "id": "maven.apache-pdfbox", "kind": "MAVEN_ARTIFACT", "lifecycle": "DEFERRED" }
      ]
    }
  }
}`

// writeQualifiedTree builds a synthetic repository that satisfies the isolation
// boundary, so each mutation below isolates exactly one property.
func writeQualifiedTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	base := map[string]string{
		"architecture/versions.json":      qualifiedLock,
		"docs/evidence.md":                "qualification evidence",
		".dockerignore":                   "**\n\n!cmd\n!cmd/**\n!internal\n!internal/**\n",
		"workers/testworker/pom.xml":      "<project><dependency>org.apache.poi</dependency></project>",
		"workers/testworker/Dockerfile":   "FROM base:1@sha256:" + strings.Repeat("a", 64) + " AS builder\nFROM builder AS runtime\n",
		"workers/testworker/README.md":    "isolated worker",
		"internal/ingestion/pipeline.go":  "package ingestion\n",
		"deploy/images/Dockerfile.worker": "FROM scratch\n",
	}
	for rel, content := range files {
		base[rel] = content
	}
	for rel, content := range base {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestSupplyChainLifecycleBoundaryAcceptsAnIsolatedWorker(t *testing.T) {
	if problems := checkSupplyChainLifecycleBoundary(writeQualifiedTree(t, nil)); len(problems) != 0 {
		t.Fatalf("a correctly isolated worker was rejected: %v", problems)
	}
	if problems := checkSupplyChainLifecycleBoundary(".."); len(problems) != 0 {
		t.Fatalf("live tree fails the supply-chain lifecycle boundary: %v", problems)
	}
}

func TestSupplyChainLifecycleBoundaryRejectsIsolationBreaches(t *testing.T) {
	cases := map[string]map[string]string{
		// Application source in the subtree would make it importable by the product.
		"go source in the isolated subtree": {
			"workers/testworker/helper.go": "package testworker\n",
		},
		"typescript in the isolated subtree": {
			"workers/testworker/helper.ts": "export const x = 1;\n",
		},
		// Default-deny inside the subtree, not only for source languages.
		"unknown file type in the isolated subtree": {
			"workers/testworker/blob.bin": "binary",
		},
		// Reachability from production, in either direction.
		"production tree names the subtree": {
			"internal/ingestion/pipeline.go": "package ingestion\n\nconst image = \"workers/testworker\"\n",
		},
		"deploy manifest names the subtree": {
			"deploy/images/Dockerfile.worker": "FROM scratch\nCOPY workers/testworker /app\n",
		},
		// The production image build context must not re-admit it.
		"dockerignore re-admits the subtree": {
			".dockerignore": "**\n\n!cmd\n!cmd/**\n!workers\n!workers/**\n",
		},
		// An undeclared subtree would get neither of the gates above.
		"undeclared worker subtree": {
			"workers/rogue/pom.xml": "<project/>",
		},
		"stray file directly under workers": {
			"workers/stray.txt": "x",
		},
		// The base image of an isolated build must still be exactly pinned.
		"unpinned base image in the subtree": {
			"workers/testworker/Dockerfile": "FROM base:latest\n",
		},
		"tagged but undigested base image in the subtree": {
			"workers/testworker/Dockerfile": "FROM base:1.2.3\n",
		},
	}
	for name, mutation := range cases {
		t.Run(name, func(t *testing.T) {
			if problems := checkSupplyChainLifecycleBoundary(writeQualifiedTree(t, mutation)); len(problems) == 0 {
				t.Fatalf("isolation breach %q was accepted", name)
			}
		})
	}
}

func TestSupplyChainLifecycleBoundaryRejectsQualificationDrift(t *testing.T) {
	cases := map[string]string{
		"missing evidence document": strings.Replace(qualifiedLock,
			`"evidence": "docs/evidence.md"`, `"evidence": "docs/absent.md"`, 1),
		"non-exact version": strings.Replace(qualifiedLock,
			`"exact_version": "5.5.1"`, `"exact_version": "5.5"`, 1),
		"subtree inside a production tree": strings.Replace(qualifiedLock,
			`"isolated_subtree": "workers/testworker/"`, `"isolated_subtree": "internal/testworker/"`, 1),
		"subtree escaping the repository": strings.Replace(qualifiedLock,
			`"isolated_subtree": "workers/testworker/"`, `"isolated_subtree": "../testworker/"`, 1),
		"subtree that is not a directory path": strings.Replace(qualifiedLock,
			`"isolated_subtree": "workers/testworker/"`, `"isolated_subtree": "workers/testworker"`, 1),
		"no leak tokens declared": strings.Replace(qualifiedLock,
			`"leak_tokens": ["org.apache.poi", "apache-poi"]`, `"leak_tokens": []`, 1),
	}
	for name, lock := range cases {
		t.Run(name, func(t *testing.T) {
			root := writeQualifiedTree(t, map[string]string{"architecture/versions.json": lock})
			if problems := checkSupplyChainLifecycleBoundary(root); len(problems) == 0 {
				t.Fatalf("qualification drift %q was accepted", name)
			}
		})
	}
}

// TestQualifiedTokensStayScopedToTheirSubtree is the load-bearing proof that
// QUALIFIED_NOT_ACTIVE narrows the leak scan rather than suspending it: a declared
// token is tolerated only inside its declared subtree, and a component that is still
// DEFERRED is denied even there.
func TestQualifiedTokensStayScopedToTheirSubtree(t *testing.T) {
	t.Run("declared token inside the declared subtree is allowed", func(t *testing.T) {
		if problems := checkDeferredStageLeaks(writeQualifiedTree(t, nil), true); len(problems) != 0 {
			t.Fatalf("qualified token inside its subtree was rejected: %v", problems)
		}
	})
	t.Run("same token one directory up is denied", func(t *testing.T) {
		root := writeQualifiedTree(t, map[string]string{
			"workers/pom.xml": "<project>org.apache.poi</project>",
		})
		if problems := checkDeferredStageLeaks(root, true); len(problems) == 0 {
			t.Fatal("qualified token outside its subtree was accepted")
		}
	})
	t.Run("same token in the application tree is denied", func(t *testing.T) {
		root := writeQualifiedTree(t, map[string]string{
			"internal/ingestion/pipeline.go": "package ingestion\n\nconst lib = \"org.apache.poi\"\n",
		})
		if problems := checkDeferredStageLeaks(root, true); len(problems) == 0 {
			t.Fatal("qualified token in the application tree was accepted")
		}
	})
	t.Run("a still-deferred component is denied inside the subtree", func(t *testing.T) {
		root := writeQualifiedTree(t, map[string]string{
			"workers/testworker/pom.xml": "<project><dependency>org.apache.pdfbox</dependency></project>",
		})
		if problems := checkDeferredStageLeaks(root, true); len(problems) == 0 {
			t.Fatal("a DEFERRED component was accepted inside a qualified subtree")
		}
	})
	t.Run("a deferred component of another slice is denied inside the subtree", func(t *testing.T) {
		root := writeQualifiedTree(t, map[string]string{
			"workers/testworker/build.sh": "#!/bin/sh\ntesseract --version\n",
		})
		if problems := checkDeferredStageLeaks(root, true); len(problems) == 0 {
			t.Fatal("an unrelated DEFERRED component was accepted inside a qualified subtree")
		}
	})
	t.Run("descriptor file types a JVM worker uses are scanned", func(t *testing.T) {
		for rel, content := range map[string]string{
			"internal/x.java":         "class X { String s = \"org.apache.pdfbox\"; }",
			"internal/build.xml":      "<project>tessdata</project>",
			"internal/app.properties": "lib=gosseract",
		} {
			root := writeQualifiedTree(t, map[string]string{rel: content})
			if problems := checkDeferredStageLeaks(root, true); len(problems) == 0 {
				t.Fatalf("a gated token hid in an unscanned file type: %s", rel)
			}
		}
	})
}

// The isolated office sandbox boundary is now one case of the shared parser sandbox
// boundary, proven by TestParserSandboxGuardRejectsHardeningAndCapabilityRegressions
// in check_architecture_test.go. That test supersedes the office-only mutation suite
// that stood here: it asserts the same capability and hardening regressions against
// the real tree instead of a synthesized root holding a single file, which the shared
// core would have made vacuous.
