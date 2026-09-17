// Package webui serves the static, same-origin React application while keeping
// the API namespace owned exclusively by the API handler.
package webui

import (
	"errors"
	"io/fs"
	"net/http"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"
)

const (
	imageAssetDirectory = "/web/dist"
	apiPath             = "/api"
	apiPrefix           = apiPath + "/"
	assetPrefix         = "assets/"
	encodedSlash        = "%2f"
	encodedEscape       = "%5c"
	maximumIndexBytes   = 2 << 20
)

// ErrorCode is content-free and safe for startup diagnostics.
type ErrorCode string

const CodeAssetsUnavailable ErrorCode = "WEB_UI_ASSETS_UNAVAILABLE"

// Error deliberately retains neither a filesystem path nor an underlying OS
// error because both are deployment details that do not belong in logs.
type Error struct{ code ErrorCode }

func (*Error) String() string   { return "webui.Error{[REDACTED]}" }
func (*Error) GoString() string { return "webui.Error{[REDACTED]}" }
func (value *Error) Error() string {
	if value == nil {
		return string(CodeAssetsUnavailable)
	}
	return string(value.code)
}

func CodeOf(err error) ErrorCode {
	var assetError *Error
	if errors.As(err, &assetError) && assetError != nil {
		return assetError.code
	}
	return CodeAssetsUnavailable
}

// ProductionHandler owns the confined UI root for the complete serving
// lifetime. Close waits for in-flight requests and permanently fails closed.
type ProductionHandler struct {
	mu      sync.RWMutex
	root    *os.Root
	handler http.Handler
	closed  bool
}

func (*ProductionHandler) String() string   { return "webui.ProductionHandler{[REDACTED]}" }
func (*ProductionHandler) GoString() string { return "webui.ProductionHandler{[REDACTED]}" }

// NewProduction validates and pins the fixed image-owned UI root before the
// process is allowed to open a listener. There is no public arbitrary-path
// constructor.
func NewProduction(api http.Handler) (*ProductionHandler, error) {
	return newProduction(api, imageAssetDirectory)
}

// newProduction is the package-private filesystem fixture seam. Production
// always calls NewProduction and therefore always uses /web/dist.
func newProduction(api http.Handler, assetDirectory string) (*ProductionHandler, error) {
	if unavailable(api) {
		return nil, &Error{code: CodeAssetsUnavailable}
	}
	root, err := openProductionAssets(assetDirectory)
	if err != nil {
		return nil, &Error{code: CodeAssetsUnavailable}
	}
	return &ProductionHandler{root: root, handler: combinedHandler(api, spaFileServer(root.FS()))}, nil
}

func (handler *ProductionHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if handler == nil {
		writeProductionUnavailable(writer)
		return
	}
	handler.mu.RLock()
	defer handler.mu.RUnlock()
	if handler.closed || handler.root == nil || handler.handler == nil {
		writeProductionUnavailable(writer)
		return
	}
	handler.handler.ServeHTTP(writer, request)
}

func (handler *ProductionHandler) Close() error {
	if handler == nil {
		return nil
	}
	handler.mu.Lock()
	defer handler.mu.Unlock()
	if handler.closed {
		return nil
	}
	handler.closed = true
	handler.handler = nil
	root := handler.root
	handler.root = nil
	if root != nil && root.Close() != nil {
		return &Error{code: CodeAssetsUnavailable}
	}
	return nil
}

func writeProductionUnavailable(writer http.ResponseWriter) {
	if writer == nil {
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusServiceUnavailable)
}

// New is the temporary non-production scaffold seam. It preserves the old
// runtime-unavailable response until cmd/server is replaced by strict
// production composition; production wiring must call NewProduction.
func New(api http.Handler) http.Handler {
	return newHandler(api, imageAssetDirectory)
}

// newHandler is the package-private asset fixture seam. Production has no API
// that accepts an alternate filesystem root.
func newHandler(api http.Handler, assetDirectory string) http.Handler {
	if api == nil {
		return http.NotFoundHandler()
	}
	return combinedHandler(api, staticHandler(assetDirectory))
}

func combinedHandler(api, assets http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if apiRequest(r) {
			api.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		assets.ServeHTTP(w, r)
	})
}

func openProductionAssets(assetDirectory string) (*os.Root, error) {
	if strings.TrimSpace(assetDirectory) == "" {
		return nil, &Error{code: CodeAssetsUnavailable}
	}
	rootInfo, err := os.Lstat(assetDirectory)
	if err != nil || rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return nil, &Error{code: CodeAssetsUnavailable}
	}
	root, err := os.OpenRoot(assetDirectory)
	if err != nil {
		return nil, &Error{code: CodeAssetsUnavailable}
	}
	fail := func() (*os.Root, error) {
		_ = root.Close()
		return nil, &Error{code: CodeAssetsUnavailable}
	}
	openedRootInfo, err := root.Stat(".")
	currentRootInfo, currentRootErr := os.Lstat(assetDirectory)
	if err != nil || currentRootErr != nil || currentRootInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(rootInfo, openedRootInfo) || !os.SameFile(openedRootInfo, currentRootInfo) {
		return fail()
	}
	indexInfo, err := root.Lstat("index.html")
	if err != nil || indexInfo.Mode()&os.ModeSymlink != 0 || !indexInfo.Mode().IsRegular() || indexInfo.Size() < 1 || indexInfo.Size() > maximumIndexBytes {
		return fail()
	}
	index, err := root.Open("index.html")
	if err != nil {
		return fail()
	}
	openedInfo, err := index.Stat()
	closeErr := index.Close()
	if err != nil || closeErr != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(indexInfo, openedInfo) || openedInfo.Size() != indexInfo.Size() {
		return fail()
	}
	return root, nil
}

func unavailable(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

// apiRequest reserves the entire API namespace, including encoded delimiter
// aliases. A malformed API-like path must receive the API's denial, never HTML.
func apiRequest(r *http.Request) bool {
	escaped := strings.ToLower(r.URL.EscapedPath())
	if escaped == apiPath || strings.HasPrefix(escaped, apiPrefix) ||
		strings.HasPrefix(escaped, apiPath+encodedSlash) || strings.HasPrefix(escaped, apiPath+encodedEscape) {
		return true
	}
	decoded := strings.ToLower(r.URL.Path)
	return decoded == apiPath || strings.HasPrefix(decoded, apiPrefix) || strings.HasPrefix(decoded, apiPath+"\\")
}

func staticHandler(assetDirectory string) http.Handler {
	if strings.TrimSpace(assetDirectory) == "" {
		return unavailableHandler()
	}
	info, err := os.Stat(assetDirectory)
	if err != nil || !info.IsDir() {
		return unavailableHandler()
	}
	return spaFileServer(os.DirFS(assetDirectory))
}

func unavailableHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "user interface is not installed", http.StatusServiceUnavailable)
	})
}

func spaFileServer(assets fs.FS) http.Handler {
	files := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleanPath := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
		if cleanPath == "." || cleanPath == "" {
			serveIndex(w, r, assets)
			return
		}
		if _, err := fs.Stat(assets, cleanPath); err == nil {
			w.Header().Set("X-Content-Type-Options", "nosniff")
			files.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(cleanPath, assetPrefix) {
			http.NotFound(w, r)
			return
		}
		serveIndex(w, r, assets)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, assets fs.FS) {
	body, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
