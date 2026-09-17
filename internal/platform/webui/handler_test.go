package webui

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var _ func(http.Handler) (*ProductionHandler, error) = NewProduction

func TestProductionRequiresCompleteFixedShapeBeforeServing(t *testing.T) {
	api := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusTeapot) })
	directory := writeAssets(t)
	handler, err := newProduction(api, directory)
	if err != nil || handler == nil {
		t.Fatalf("newProduction() handler=%T err=%v", handler, err)
	}
	t.Cleanup(func() { _ = handler.Close() })
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/workspace/alpha", nil))
	if response.Code != http.StatusOK || response.Body.String() != "<main>KnowVault</main>" {
		t.Fatalf("production SPA status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestProductionRejectsNilAndTypedNilAPI(t *testing.T) {
	directory := writeAssets(t)
	var typedNil *nilHandler
	for name, api := range map[string]http.Handler{"nil": nil, "typed nil": typedNil} {
		t.Run(name, func(t *testing.T) {
			if handler, err := newProduction(api, directory); handler != nil || CodeOf(err) != CodeAssetsUnavailable {
				t.Fatalf("handler=%T err=%v", handler, err)
			}
		})
	}
}

func TestProductionRejectsMissingInvalidEmptyAndOversizedIndex(t *testing.T) {
	api := http.NotFoundHandler()
	tests := map[string]func(*testing.T) string{
		"missing root": func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") },
		"root is file": func(t *testing.T) string {
			path := filepath.Join(t.TempDir(), "root")
			if err := os.WriteFile(path, []byte("not a directory"), 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		},
		"missing index": func(t *testing.T) string { return t.TempDir() },
		"index is directory": func(t *testing.T) string {
			directory := t.TempDir()
			if err := os.Mkdir(filepath.Join(directory, "index.html"), 0o700); err != nil {
				t.Fatal(err)
			}
			return directory
		},
		"empty index": func(t *testing.T) string {
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, "index.html"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
			return directory
		},
		"oversized index": func(t *testing.T) string {
			directory := t.TempDir()
			file, err := os.Create(filepath.Join(directory, "index.html"))
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Truncate(maximumIndexBytes + 1); err != nil {
				_ = file.Close()
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			return directory
		},
	}
	for name, fixture := range tests {
		t.Run(name, func(t *testing.T) {
			if handler, err := newProduction(api, fixture(t)); handler != nil || CodeOf(err) != CodeAssetsUnavailable {
				t.Fatalf("handler=%T err=%v", handler, err)
			}
		})
	}
}

func TestProductionRejectsSymlinkRootAndIndex(t *testing.T) {
	api := http.NotFoundHandler()
	t.Run("root", func(t *testing.T) {
		target := writeAssets(t)
		link := filepath.Join(t.TempDir(), "dist")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if handler, err := newProduction(api, link); handler != nil || CodeOf(err) != CodeAssetsUnavailable {
			t.Fatalf("handler=%T err=%v", handler, err)
		}
	})
	t.Run("index", func(t *testing.T) {
		directory := t.TempDir()
		target := filepath.Join(t.TempDir(), "index-target.html")
		if err := os.WriteFile(target, []byte("index"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(directory, "index.html")); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if handler, err := newProduction(api, directory); handler != nil || CodeOf(err) != CodeAssetsUnavailable {
			t.Fatalf("handler=%T err=%v", handler, err)
		}
	})
}

func TestProductionRootConfinesRelativeAndAbsoluteAssetSymlinks(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		name := "relative"
		if absolute {
			name = "absolute"
		}
		t.Run(name, func(t *testing.T) {
			directory := writeAssets(t)
			assets := filepath.Join(directory, "assets")
			if err := os.Mkdir(assets, 0o700); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(t.TempDir(), "sensitive.txt")
			secret := "must-never-be-served"
			if err := os.WriteFile(outside, []byte(secret), 0o600); err != nil {
				t.Fatal(err)
			}
			target := outside
			if !absolute {
				var err error
				target, err = filepath.Rel(assets, outside)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target, filepath.Join(assets, "leak.txt")); err != nil {
				t.Skipf("symlink unavailable: %v", err)
			}
			handler, err := newProduction(http.NotFoundHandler(), directory)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = handler.Close() })
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/assets/leak.txt", nil))
			if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), secret) {
				t.Fatalf("symlink escaped root: status=%d body=%q", response.Code, response.Body.String())
			}
		})
	}
}

func TestProductionCloseFailsClosedAndIsConcurrentServeSafe(t *testing.T) {
	handler, err := newProduction(http.NotFoundHandler(), writeAssets(t))
	if err != nil {
		t.Fatal(err)
	}
	const requests = 32
	start := make(chan struct{})
	results := make(chan *httptest.ResponseRecorder, requests)
	var wait sync.WaitGroup
	for range requests {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/workspace/alpha", nil))
			results <- response
		}()
	}
	close(start)
	if err := handler.Close(); err != nil {
		t.Fatal(err)
	}
	if err := handler.Close(); err != nil {
		t.Fatalf("idempotent close: %v", err)
	}
	wait.Wait()
	close(results)
	for response := range results {
		switch response.Code {
		case http.StatusOK:
			if response.Body.String() != "<main>KnowVault</main>" {
				t.Fatalf("in-flight response leaked unexpected bytes: %q", response.Body.String())
			}
		case http.StatusServiceUnavailable:
			if response.Body.Len() != 0 {
				t.Fatalf("closed response exposed bytes: %q", response.Body.String())
			}
		default:
			t.Fatalf("unexpected concurrent status=%d body=%q", response.Code, response.Body.String())
		}
	}
	afterClose := httptest.NewRecorder()
	handler.ServeHTTP(afterClose, httptest.NewRequest(http.MethodGet, "/", nil))
	if afterClose.Code != http.StatusServiceUnavailable || afterClose.Body.Len() != 0 {
		t.Fatalf("closed handler status=%d body=%q", afterClose.Code, afterClose.Body.String())
	}
}

func TestProductionErrorsAreContentFreeAndRedacted(t *testing.T) {
	secretPath := filepath.Join(t.TempDir(), "sensitive-deployment-path")
	_, err := newProduction(http.NotFoundHandler(), secretPath)
	if err == nil || err.Error() != string(CodeAssetsUnavailable) || strings.Contains(err.Error(), secretPath) {
		t.Fatalf("unsafe production error: %v", err)
	}
	for _, formatted := range []string{fmt.Sprintf("%v", err), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(formatted, secretPath) || (strings.Contains(formatted, "webui.Error") && !strings.Contains(formatted, "REDACTED")) {
			t.Fatalf("unsafe formatting: %q", formatted)
		}
	}
	var typedNil *Error
	if CodeOf(typedNil) != CodeAssetsUnavailable {
		t.Fatal("typed-nil error did not fail closed")
	}
}

type nilHandler struct{}

func (*nilHandler) ServeHTTP(http.ResponseWriter, *http.Request) {}

func TestAPIPathsNeverFallThroughToUI(t *testing.T) {
	directory := writeAssets(t)
	api := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	response := httptest.NewRecorder()
	newHandler(api, directory).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/unknown", nil))

	if response.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want API status", response.Code)
	}
}

func TestAPIAliasesNeverFallThroughToUI(t *testing.T) {
	directory := writeAssets(t)
	api := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	handler := newHandler(api, directory)

	for _, target := range []string{"/api", "/api%2Fv1%2Fsystem%2Fhealth", "/api%5Cv1"} {
		t.Run(target, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, target, nil))
			if response.Code != http.StatusTeapot {
				t.Fatalf("status = %d, want API status", response.Code)
			}
		})
	}
}

func TestUnknownNonAPIPathServesIndex(t *testing.T) {
	directory := writeAssets(t)
	response := httptest.NewRecorder()
	newHandler(http.NotFoundHandler(), directory).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/workspace/alpha", nil))

	if response.Code != http.StatusOK || response.Body.String() != "<main>KnowVault</main>" {
		t.Fatalf("unexpected SPA response: status=%d body=%q", response.Code, response.Body.String())
	}
}

func TestStaticAssetsOnlyAllowGetAndHead(t *testing.T) {
	response := httptest.NewRecorder()
	newHandler(http.NotFoundHandler(), writeAssets(t)).ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/", nil))
	if response.Code != http.StatusMethodNotAllowed || response.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("unexpected method response: status=%d allow=%q", response.Code, response.Header().Get("Allow"))
	}
}

func TestUnknownStaticAssetIsNotAnSPAPath(t *testing.T) {
	response := httptest.NewRecorder()
	newHandler(http.NotFoundHandler(), writeAssets(t)).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/assets/missing.js", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", response.Code)
	}
}

func writeAssets(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "index.html"), []byte("<main>KnowVault</main>"), 0o600); err != nil {
		t.Fatal(err)
	}
	return directory
}
