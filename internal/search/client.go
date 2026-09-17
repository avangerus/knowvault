// Package search is the narrow, server-owned OpenSearch transport boundary.
//
// The package deliberately exposes no raw query DSL.  Callers provide a
// tenant-bound, typed text query and an immutable index document; the client
// constructs the filter and endpoint itself.  PostgreSQL remains the
// authorization authority: a Search result is only a candidate set and must
// be post-authorized before any Evidence or answer is disclosed.
package search

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/platform/netcanon"
)

const (
	defaultTimeout        = 5 * time.Second
	maximumQueryBytes     = 32 << 10
	maximumTextBytes      = 8 << 20
	maximumResponseBytes  = 8 << 20
	maximumPageSize       = 100
	maximumPageOffset     = 10000
	maximumGeneration     = int64(9007199254740991)
	maximumDocumentIDSize = 256
	// maximumScopeFilterSize bounds the server-built source-scope pre-filter of
	// a k-NN query. A workspace binds sources, not objects, so the live
	// authorized scope set of one workspace is small by construction; the bound
	// keeps a pathological binding from turning one question into an unbounded
	// terms clause.
	maximumScopeFilterSize = 256
	// maximumDocumentScopeIDs bounds the scope memberships carried on one
	// indexed passage. An object belongs to the scopes that collected it, not
	// to a tenant's whole catalogue.
	maximumDocumentScopeIDs = 256
)

// VersionState is the closed, server-owned lifecycle vocabulary carried on an
// indexed passage. It exists so the current-version state is a pre-filter of
// the retrieval query rather than a property discovered after ranking. It is
// never a caller-supplied string: the indexer copies the catalogue's own value
// and the retrieval path selects one of these constants.
const (
	VersionStateCurrent    = "CURRENT"
	VersionStateSuperseded = "SUPERSEDED"
)

// ErrorCode is the content-free error vocabulary exposed to the application
// and metrics.  Response bodies and URLs are deliberately never included.
type ErrorCode string

const (
	CodeInvalid                  ErrorCode = "SEARCH_REQUEST_INVALID"
	CodeUnavailable              ErrorCode = "SEARCH_DEPENDENCY_UNAVAILABLE"
	CodeRejected                 ErrorCode = "SEARCH_DEPENDENCY_REJECTED"
	CodeResponse                 ErrorCode = "SEARCH_RESPONSE_INVALID"
	CodeConflict                 ErrorCode = "SEARCH_GENERATION_CONFLICT"
	CodePersistence              ErrorCode = "SEARCH_PERSISTENCE_FAILED"
	CodeVectorProfileUnavailable ErrorCode = "SEARCH_VECTOR_PROFILE_UNAVAILABLE"
)

// Error hides the dependency's body, credentials and endpoint.  The cause is
// retained for trusted diagnostics only.
type Error struct {
	code   ErrorCode
	cause  error
	status int
}

func (e *Error) Error() string { return string(e.code) }
func (e *Error) Unwrap() error { return e.cause }
func (e *Error) StatusCode() int {
	if e == nil {
		return 0
	}
	return e.status
}

func CodeOf(err error) ErrorCode {
	var typed *Error
	if errors.As(err, &typed) {
		return typed.code
	}
	return CodeUnavailable
}

// Config is a complete, tenant-bound search capability.  Endpoint and alias
// are deployment configuration, never request data.  TLS roots are mandatory
// and are purpose-specific; the system trust pool and proxy environment are
// not consulted.
type Config struct {
	Endpoint       string
	IndexAlias     string
	OrganizationID string
	// Generation and GenerationFence are immutable deployment bindings.  An
	// applier must construct a new client for every alias generation; accepting
	// a document from another generation would let a stale worker repopulate a
	// newly cut-over alias.
	Generation      int64
	GenerationFence int64
	// VectorProfileHash and VectorDimension are optional only for a lexical
	// client. A VectorSearch call is unavailable until both are deployment
	// supplied and exact-match every query/index document.
	VectorProfileHash string
	VectorDimension   int
	TrustRoots        *x509.CertPool
	ClientCertificate *tls.Certificate
	HTTPClient        *http.Client
	Timeout           time.Duration
}

// Client owns one immutable organization/index generation endpoint.  It is
// safe for concurrent use.
type Client struct {
	endpoint          url.URL
	indexAlias        string
	organizationID    string
	generation        int64
	generationFence   int64
	vectorProfileHash string
	vectorDimension   int
	http              *http.Client
	revisions         *revisionIndices
}

// OrganizationID returns the immutable tenant binding of this capability.
// It is intended only for composing a request with the authenticated access
// context; callers cannot change the binding or use it as a search filter.
func (client *Client) OrganizationID() string {
	if client == nil {
		return ""
	}
	return client.organizationID
}

// VectorProfile returns the immutable profile binding configured for this
// client. A zero hash/dimension pair means that the client is lexical-only;
// callers cannot activate vectors by supplying request fields.
func (client *Client) VectorProfile() (string, int) {
	if client == nil {
		return "", 0
	}
	return client.vectorProfileHash, client.vectorDimension
}

// Close retires any idle connections owned by this immutable capability.  A
// production composition calls it during reverse-order shutdown; callers do
// not gain access to the underlying HTTP transport or its TLS material.
func (client *Client) Close() error {
	if client == nil || client.http == nil {
		return nil
	}
	if closer, ok := client.http.Transport.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
	return nil
}

// New validates the deployment endpoint and builds a hardened HTTPS client.
// A custom HTTP client is accepted only for composition tests and controlled
// transports; production composition should leave it nil so the no-proxy,
// purpose-specific TLS profile is installed here.
func New(config Config) (*Client, error) {
	if !validOpaque(config.OrganizationID) || !validAlias(config.IndexAlias) ||
		!validGeneration(config.Generation) || !validGeneration(config.GenerationFence) ||
		config.TrustRoots == nil || len(config.TrustRoots.Subjects()) == 0 {
		return nil, &Error{code: CodeInvalid}
	}
	if (config.VectorProfileHash == "") != (config.VectorDimension == 0) ||
		config.VectorProfileHash != "" && (!validSHA256(config.VectorProfileHash) || config.VectorDimension < 1 || config.VectorDimension > 65536) {
		return nil, &Error{code: CodeInvalid}
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil || !validEndpoint(parsed) {
		return nil, &Error{code: CodeInvalid}
	}
	timeout := config.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	if timeout > 60*time.Second {
		return nil, &Error{code: CodeInvalid}
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		tlsConfig := &tls.Config{
			RootCAs:    config.TrustRoots,
			ServerName: parsed.Hostname(),
			MinVersion: tls.VersionTLS12,
		}
		if config.ClientCertificate != nil {
			tlsConfig.Certificates = []tls.Certificate{*config.ClientCertificate}
		}
		transport := &http.Transport{
			Proxy:                  nil,
			TLSClientConfig:        tlsConfig,
			DisableCompression:     true,
			MaxResponseHeaderBytes: 1 << 20,
			ForceAttemptHTTP2:      true,
		}
		httpClient = &http.Client{Transport: transport, Timeout: timeout}
	} else if httpClient.Timeout <= 0 || httpClient.Timeout > 60*time.Second {
		return nil, &Error{code: CodeInvalid}
	}
	return &Client{endpoint: *parsed, indexAlias: config.IndexAlias,
		organizationID: config.OrganizationID, generation: config.Generation,
		generationFence: config.GenerationFence, vectorProfileHash: config.VectorProfileHash,
		vectorDimension: config.VectorDimension, http: httpClient, revisions: &revisionIndices{ready: make(map[string]bool)}}, nil
}

// IndexDocument is the only document shape accepted by Index.  It contains
// hashes and references, not caller-controlled ACLs or arbitrary index fields.
type IndexDocument struct {
	ProfileRevision      int64     `json:"profile_revision,omitempty"`
	ID                   string    `json:"id"`
	OrganizationID       string    `json:"organization_id"`
	SourceObjectID       string    `json:"source_object_id"`
	SourceVersionID      string    `json:"source_version_id"`
	ExtractionID         string    `json:"extraction_id"`
	EvidenceFragmentID   string    `json:"evidence_fragment_id"`
	EvidenceFragmentIDs  []string  `json:"evidence_fragment_ids,omitempty"`
	EvidenceTextHashes   []string  `json:"evidence_text_hashes,omitempty"`
	EvidenceAnchorHashes []string  `json:"evidence_anchor_hashes,omitempty"`
	Text                 string    `json:"text"`
	ContentHash          string    `json:"content_hash"`
	TextHash             string    `json:"text_hash"`
	AnchorHash           string    `json:"anchor_hash"`
	EmbeddingProfileHash string    `json:"embedding_profile_hash,omitempty"`
	EmbeddingDimension   int       `json:"embedding_dimension,omitempty"`
	Embedding            []float32 `json:"embedding,omitempty"`
	// SourceScopeIDs are the scope memberships of the passage's object at the
	// moment it was indexed. They exist so a retrieval query can restrict
	// candidates to the scopes a workspace actually binds BEFORE ranking,
	// instead of ranking a tenant's whole corpus and discarding the foreign
	// part afterwards. They are a narrowing pre-filter only: PostgreSQL
	// post-authorization remains the authority on every returned passage, so a
	// membership that changed after indexing can never widen an answer.
	SourceScopeIDs []string `json:"source_scope_ids,omitempty"`
	// VersionState is the catalogue's own lifecycle value for the passage's
	// version at index time. Only a CURRENT version is ever admitted to the
	// index, so the field makes that fact filterable rather than implicit.
	VersionState    string `json:"version_state,omitempty"`
	Generation      int64  `json:"index_generation"`
	GenerationFence int64  `json:"generation_fence"`
}

// Query is intentionally smaller than the OpenSearch DSL.  The tenant filter
// is always generated from the Client's immutable organization binding.
type Query struct {
	ProfileRevision int64
	ProfileHash     string
	Text            string
	Size            int
	From            int
	Operator        MatchOperator
	SourceScopeIDs  []string
	VersionState    string
}

// VectorQuery is the complete typed input to the k-NN adapter. The embedding
// bytes come from a separately qualified model provider; this package never
// invents, pads or truncates them.
type VectorQuery struct {
	ProfileRevision int64
	Vector          []float32
	ProfileHash     string
	Dimension       int
	Size            int
	From            int
	// SourceScopeIDs is the server-built authorized scope set of the asking
	// workspace, resolved from live PostgreSQL state by the caller. When it is
	// present the k-NN query ranks only passages of those scopes, so the
	// rights-bearing scope is applied before ranking rather than after it. It
	// is never caller-supplied DSL and never widens access: an empty set means
	// the caller did not scope the query and the existing tenant/profile
	// filters alone apply, and PostgreSQL post-authorization still gates every
	// returned passage either way.
	SourceScopeIDs []string
	// VersionState, when set, restricts ranking to passages the catalogue
	// recorded in that lifecycle state, so "only current versions" is a
	// property of the query and not of the ranking that follows it.
	VersionState string
}

// MatchOperator is a deliberately tiny, server-owned choice for lexical
// matching. MatchAll is the default used by direct callers; the question
// retrieval compiler may use MatchAny for natural-language questions whose
// interrogative terms are not present in source text. PostgreSQL Evidence
// post-authorization remains mandatory for either mode.
type MatchOperator string

const (
	MatchAll MatchOperator = "and"
	MatchAny MatchOperator = "or"
)

type Hit struct {
	ID       string
	Score    float64
	Document IndexDocument
}

type Result struct {
	Total      int
	TotalExact bool
	Hits       []Hit
}

// Index writes one document to the configured alias.  A generation/fence
// conflict is surfaced as CodeConflict so the caller can stop stale writers;
// it is never retried against another alias.
func (client *Client) Index(ctx context.Context, document IndexDocument) error {
	if client == nil || client.http == nil || !client.validDocument(document) || ctx == nil {
		return &Error{code: CodeInvalid}
	}
	payload, err := json.Marshal(document)
	if err != nil {
		return &Error{code: CodeInvalid, cause: err}
	}
	index, err := client.revisionIndex(document.ProfileRevision, document.EmbeddingProfileHash)
	if err != nil {
		return err
	}
	if document.ProfileRevision > 1 {
		if err := client.EnsureRevisionIndex(ctx, document.ProfileRevision); err != nil {
			return err
		}
	}
	request, err := client.request(ctx, http.MethodPut, "/"+index+"/_doc/"+url.PathEscape(document.ID), payload)
	if err != nil {
		return err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusConflict {
		return &Error{code: CodeConflict, status: response.StatusCode}
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &Error{code: CodeRejected, status: response.StatusCode}
	}
	if err := drainBounded(response.Body); err != nil {
		return &Error{code: CodeResponse, cause: err, status: response.StatusCode}
	}
	return nil
}

// Delete removes one stale document from the configured alias.  The caller
// supplies only the immutable chunk ID; tenant and alias remain server-bound.
func (client *Client) Delete(ctx context.Context, documentID string) error {
	if client == nil || client.http == nil || !validOpaque(documentID) || len(documentID) > maximumDocumentIDSize || ctx == nil {
		return &Error{code: CodeInvalid}
	}
	request, err := client.request(ctx, http.MethodDelete, "/"+client.indexAlias+"/_doc/"+url.PathEscape(documentID), nil)
	if err != nil {
		return err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNotFound && (response.StatusCode < 200 || response.StatusCode >= 300) {
		return &Error{code: CodeRejected, status: response.StatusCode}
	}
	if err := drainBounded(response.Body); err != nil {
		return &Error{code: CodeResponse, cause: err, status: response.StatusCode}
	}
	return nil
}

// Search executes a bounded lexical candidate query.  No raw query DSL,
// index name, organization filter or ACL predicate can enter this method.
func (client *Client) Search(ctx context.Context, query Query) (Result, error) {
	if client == nil || client.http == nil || ctx == nil || !validQuery(query) {
		return Result{}, &Error{code: CodeInvalid}
	}
	body := struct {
		Size           int  `json:"size"`
		From           int  `json:"from"`
		TrackTotalHits bool `json:"track_total_hits"`
		Query          struct {
			Bool struct {
				Filter []map[string]any `json:"filter"`
				Must   []map[string]any `json:"must"`
			} `json:"bool"`
		} `json:"query"`
	}{Size: query.Size, From: query.From, TrackTotalHits: true}
	body.Query.Bool.Filter = []map[string]any{exactFieldFilter("organization_id", client.organizationID)}
	if len(query.SourceScopeIDs) > 0 {
		body.Query.Bool.Filter = append(body.Query.Bool.Filter, anyFieldFilter("source_scope_ids", query.SourceScopeIDs))
	}
	if query.VersionState != "" {
		body.Query.Bool.Filter = append(body.Query.Bool.Filter, exactFieldFilter("version_state", query.VersionState))
	}
	operator := query.Operator
	if operator == "" {
		operator = MatchAll
	}
	body.Query.Bool.Must = []map[string]any{{"match": map[string]any{"text": map[string]any{"query": query.Text, "operator": string(operator)}}}}
	payload, err := json.Marshal(body)
	if err != nil {
		return Result{}, &Error{code: CodeInvalid, cause: err}
	}
	index, err := client.revisionIndex(query.ProfileRevision, query.ProfileHash)
	if err != nil {
		return Result{}, err
	}
	request, err := client.request(ctx, http.MethodPost, "/"+index+"/_search", payload)
	if err != nil {
		return Result{}, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return Result{}, &Error{code: CodeUnavailable, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Result{}, &Error{code: CodeRejected, status: response.StatusCode}
	}
	return client.parseSearchResponse(response.Body, response.StatusCode, false)
}

// EnsureIndex provisions this deployment's backing index with the exact
// vector field the mounted profile needs, and is a no-op for a lexical
// deployment. It exists because OpenSearch cannot add a knn_vector field to
// an index that already has documents: an index created implicitly by the
// first write maps `embedding` as an ordinary float array, which accepts
// every document and then fails every k-NN query — a deployment that looks
// healthy and answers nothing semantically. Creating it up front is the only
// point at which that is decidable.
//
// It is idempotent and never rewrites an existing index: a deployment that
// already has one keeps whatever mapping it was created with, and moving it
// to a new vector space is the operator's explicit profile revision.
func (client *Client) EnsureIndex(ctx context.Context) error {
	if client == nil || client.http == nil || ctx == nil {
		return &Error{code: CodeInvalid}
	}
	if client.vectorProfileHash == "" || client.vectorDimension < 1 {
		return nil
	}
	probe, err := client.request(ctx, http.MethodGet, "/"+client.indexAlias, nil)
	if err != nil {
		return err
	}
	probeResponse, err := client.http.Do(probe)
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(probeResponse.Body, maximumResponseBytes))
	_ = probeResponse.Body.Close()
	if probeResponse.StatusCode >= 200 && probeResponse.StatusCode < 300 {
		return nil
	}
	if probeResponse.StatusCode != http.StatusNotFound {
		return &Error{code: CodeRejected, status: probeResponse.StatusCode}
	}
	payload, err := json.Marshal(map[string]any{
		"settings": map[string]any{"index": map[string]any{"knn": true}},
		"mappings": map[string]any{"properties": map[string]any{
			"embedding": map[string]any{
				"type":      "knn_vector",
				"dimension": client.vectorDimension,
				"method": map[string]any{
					"name": "hnsw", "space_type": "cosinesimil", "engine": "lucene",
				},
			},
			// The pre-filter fields are mapped as exact keywords rather than
			// left to dynamic string mapping. A dynamically mapped identifier
			// becomes an analyzed text field with a `.keyword` sub-field, and a
			// term predicate against the analyzed form silently matches nothing
			// — which on a scope or lifecycle filter is the difference between
			// "ranked inside the workspace" and "ranked over the whole tenant".
			// Queries still carry the `.keyword` fallback for indexes created
			// before this mapping existed.
			"organization_id":        map[string]any{"type": "keyword"},
			"embedding_profile_hash": map[string]any{"type": "keyword"},
			"source_scope_ids":       map[string]any{"type": "keyword"},
			"version_state":          map[string]any{"type": "keyword"},
		}},
	})
	if err != nil {
		return &Error{code: CodeInvalid, cause: err}
	}
	create, err := client.request(ctx, http.MethodPut, "/"+client.indexAlias, payload)
	if err != nil {
		return err
	}
	createResponse, err := client.http.Do(create)
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	defer createResponse.Body.Close()
	raw, readErr := io.ReadAll(io.LimitReader(createResponse.Body, maximumResponseBytes+1))
	if readErr != nil || len(raw) > maximumResponseBytes {
		return &Error{code: CodeResponse, cause: readErr}
	}
	// A concurrent worker may have won the race; an existing index is the
	// state this method wanted.
	if createResponse.StatusCode == http.StatusBadRequest || createResponse.StatusCode == http.StatusConflict {
		var failure struct {
			Error struct {
				Type string `json:"type"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &failure) == nil && failure.Error.Type == "resource_already_exists_exception" {
			return nil
		}
		return &Error{code: CodeRejected, status: createResponse.StatusCode}
	}
	if createResponse.StatusCode < 200 || createResponse.StatusCode >= 300 {
		return &Error{code: CodeRejected, status: createResponse.StatusCode}
	}
	return nil
}

// VectorSearch executes a server-built k-NN query. It requires an active
// deployment profile on the immutable client and exact profile/dimension
// equality on the query and every returned document. A lexical-only client
// cannot accidentally become a vector client by request input.
func (client *Client) VectorSearch(ctx context.Context, query VectorQuery) (Result, error) {
	if client == nil || client.http == nil || ctx == nil {
		return Result{}, &Error{code: CodeInvalid}
	}
	if client.vectorProfileHash == "" {
		return Result{}, &Error{code: CodeVectorProfileUnavailable}
	}
	if !validVectorQuery(query, client.vectorProfileHash, client.vectorDimension) {
		return Result{}, &Error{code: CodeInvalid}
	}
	k := query.Size + query.From
	body := struct {
		Size           int  `json:"size"`
		From           int  `json:"from"`
		TrackTotalHits bool `json:"track_total_hits"`
		Query          struct {
			Bool struct {
				Filter []map[string]any `json:"filter"`
				Must   []map[string]any `json:"must"`
			} `json:"bool"`
		} `json:"query"`
	}{Size: query.Size, From: query.From, TrackTotalHits: true}
	body.Query.Bool.Filter = []map[string]any{
		exactFieldFilter("organization_id", client.organizationID),
		exactFieldFilter("embedding_profile_hash", client.vectorProfileHash),
	}
	// The scope and version-state predicates sit in the same bool filter as the
	// tenant and profile predicates, which the lucene k-NN engine applies while
	// it walks the graph. That is the whole reason this deployment maps
	// `embedding` with engine `lucene`: the rights-bearing scope and the
	// current-version state narrow the candidate set BEFORE ranking, so a
	// workspace's k nearest neighbours are k neighbours it may actually read,
	// not k tenant-wide neighbours of which most are then discarded.
	if len(query.SourceScopeIDs) > 0 {
		body.Query.Bool.Filter = append(body.Query.Bool.Filter, anyFieldFilter("source_scope_ids", query.SourceScopeIDs))
	}
	if query.VersionState != "" {
		body.Query.Bool.Filter = append(body.Query.Bool.Filter, exactFieldFilter("version_state", query.VersionState))
	}
	body.Query.Bool.Must = []map[string]any{{"knn": map[string]any{
		"embedding": map[string]any{"vector": query.Vector, "k": k},
	}}}
	payload, err := json.Marshal(body)
	if err != nil {
		return Result{}, &Error{code: CodeInvalid, cause: err}
	}
	index, err := client.revisionIndex(query.ProfileRevision, query.ProfileHash)
	if err != nil {
		return Result{}, err
	}
	request, err := client.request(ctx, http.MethodPost, "/"+index+"/_search", payload)
	if err != nil {
		return Result{}, err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return Result{}, &Error{code: CodeUnavailable, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return Result{}, &Error{code: CodeRejected, status: response.StatusCode}
	}
	return client.parseSearchResponse(response.Body, response.StatusCode, true)
}

// exactFieldFilter keeps tenant and deployment-profile predicates exact across
// both supported index mappings. Operators may provision identifiers as
// keyword fields (the preferred contract) or rely on OpenSearch's dynamic
// string mapping, which creates a <field>.keyword multi-field. The fallback
// is still a server-built filter, never caller-provided DSL; parsed hits are
// additionally checked by validDocument before they can become Evidence.
func exactFieldFilter(field, value string) map[string]any {
	return map[string]any{"bool": map[string]any{
		"should": []any{
			map[string]any{"term": map[string]string{field: value}},
			map[string]any{"term": map[string]string{field + ".keyword": value}},
		},
		"minimum_should_match": 1,
	}}
}

// anyFieldFilter keeps a bounded server-built set predicate exact across both
// supported index mappings, exactly as exactFieldFilter does for one value. The
// values are never caller-provided DSL: they are identifiers the server read
// out of its own authorization state.
func anyFieldFilter(field string, values []string) map[string]any {
	terms := make([]any, 0, len(values))
	for _, value := range values {
		terms = append(terms, value)
	}
	return map[string]any{"bool": map[string]any{
		"should": []any{
			map[string]any{"terms": map[string]any{field: terms}},
			map[string]any{"terms": map[string]any{field + ".keyword": terms}},
		},
		"minimum_should_match": 1,
	}}
}

func (client *Client) parseSearchResponse(reader io.Reader, status int, vector bool) (Result, error) {
	raw, err := io.ReadAll(io.LimitReader(reader, maximumResponseBytes+1))
	if err != nil || len(raw) > maximumResponseBytes {
		return Result{}, &Error{code: CodeResponse, cause: err, status: status}
	}
	var wire searchResponse
	if err := json.Unmarshal(raw, &wire); err != nil || wire.Hits.Hits == nil || wire.Hits.Total.Value < 0 || wire.Hits.Total.Value < len(wire.Hits.Hits) || len(wire.Hits.Hits) > maximumPageSize ||
		wire.Hits.Total.Relation != "" && wire.Hits.Total.Relation != "eq" && wire.Hits.Total.Relation != "gte" {
		return Result{}, &Error{code: CodeResponse, cause: err, status: status}
	}
	relation := wire.Hits.Total.Relation
	if relation == "" {
		relation = "eq"
	}
	result := Result{Total: wire.Hits.Total.Value, TotalExact: relation == "eq", Hits: make([]Hit, 0, len(wire.Hits.Hits))}
	for _, item := range wire.Hits.Hits {
		if !validOpaque(item.ID) || item.Score < 0 || item.Source.ID != item.ID ||
			!client.validIndexedDocument(item.Source, vector) {
			return Result{}, &Error{code: CodeResponse, status: status}
		}
		result.Hits = append(result.Hits, Hit{ID: item.ID, Score: item.Score, Document: item.Source})
	}
	return result, nil
}

type searchResponse struct {
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		Hits []struct {
			ID     string        `json:"_id"`
			Score  float64       `json:"_score"`
			Source IndexDocument `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

func (client *Client) request(ctx context.Context, method, path string, payload []byte) (*http.Request, error) {
	if client == nil || ctx == nil || path == "" || !strings.HasPrefix(path, "/") {
		return nil, &Error{code: CodeInvalid}
	}
	target := client.endpoint
	escapedPath := strings.TrimSuffix(target.Path, "/") + path
	decodedPath, err := url.PathUnescape(escapedPath)
	if err != nil {
		return nil, &Error{code: CodeInvalid, cause: err}
	}
	target.Path = decodedPath
	if decodedPath == escapedPath {
		target.RawPath = ""
	} else {
		target.RawPath = escapedPath
	}
	target.RawQuery = ""
	target.Fragment = ""
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	request, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return nil, &Error{code: CodeInvalid, cause: err}
	}
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request, nil
}

// validDocument is the WRITE-side contract: what this deployment may put
// into its index. A vector-capable client writes only complete vector
// documents; a lexical client writes only lexical ones.
func (client *Client) validDocument(document IndexDocument) bool {
	if !client.validDocumentShape(document) {
		return false
	}
	if client.vectorProfileHash == "" {
		return document.EmbeddingProfileHash == "" && len(document.Embedding) == 0
	}
	return document.EmbeddingProfileHash == client.vectorProfileHash &&
		document.EmbeddingDimension == client.vectorDimension &&
		len(document.Embedding) == client.vectorDimension && validVector(document.Embedding)
}

// validIndexedDocument is the READ-side contract: what this deployment may
// accept back out of its index. It is deliberately weaker about vectors than
// the write side, and must be.
//
// An index legitimately holds passages that carry no vector — everything
// written before a vector profile revision, and anything a re-index pass
// could not rebuild. Those are still valid LEXICAL matches; they are simply
// invisible to the semantic channel. Applying the write-side rule on read
// made a single such passage fail the entire lexical search for every
// question that matched it, which surfaced as an unavailable answer rather
// than as the missing vector it actually was.
//
// SRCH-010 is untouched: a hit admitted to the VECTOR channel still has to
// carry this exact profile and dimension (requireVector), on top of the
// server-built profile-hash filter in the query itself.
func (client *Client) validIndexedDocument(document IndexDocument, requireVector bool) bool {
	if !client.validDocumentShape(document) {
		return false
	}
	if requireVector {
		return client.vectorProfileHash != "" &&
			document.EmbeddingProfileHash == client.vectorProfileHash &&
			document.EmbeddingDimension == client.vectorDimension &&
			len(document.Embedding) == client.vectorDimension && validVector(document.Embedding)
	}
	if document.EmbeddingProfileHash == "" {
		return len(document.Embedding) == 0
	}
	// A vector is present: it must still be a well-formed vector of its own
	// declared dimension. It may belong to a profile this client does not
	// serve (a superseded revision); the vector channel will not return it.
	return len(document.Embedding) == document.EmbeddingDimension && validVector(document.Embedding)
}

// validScopeFilter bounds a server-built scope set: distinct, opaque and small.
// An empty set is valid and means "not scoped by this predicate".
func validScopeFilter(values []string, maximum int) bool {
	if len(values) > maximum {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validOpaque(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func (client *Client) validDocumentShape(document IndexDocument) bool {
	if document.ProfileRevision < 0 || document.ProfileRevision > maximumGeneration ||
		document.ProfileRevision > 1 && !validSHA256(document.EmbeddingProfileHash) {
		return false
	}
	if !validScopeFilter(document.SourceScopeIDs, maximumDocumentScopeIDs) {
		return false
	}
	if document.VersionState != "" && document.VersionState != VersionStateCurrent &&
		document.VersionState != VersionStateSuperseded {
		return false
	}
	if client == nil || document.OrganizationID != client.organizationID ||
		!validOpaque(document.ID) || len(document.ID) > maximumDocumentIDSize ||
		!validOpaque(document.SourceObjectID) || !validOpaque(document.SourceVersionID) ||
		!validOpaque(document.ExtractionID) || !validOpaque(document.EvidenceFragmentID) ||
		!validDigest(document.ContentHash) || !validDigest(document.TextHash) || !validDigest(document.AnchorHash) ||
		document.Generation != client.generation || document.GenerationFence != client.generationFence ||
		len(document.Text) == 0 || len(document.Text) > maximumTextBytes || !utf8.ValidString(document.Text) {
		return false
	}
	if (document.EmbeddingProfileHash == "") != (document.EmbeddingDimension == 0) ||
		document.EmbeddingProfileHash != "" && (!validSHA256(document.EmbeddingProfileHash) || document.EmbeddingDimension < 1 || document.EmbeddingDimension > 65536) {
		return false
	}
	if len(document.EvidenceFragmentIDs) > 256 {
		return false
	}
	if len(document.EvidenceFragmentIDs) > 0 {
		seen := make(map[string]struct{}, len(document.EvidenceFragmentIDs))
		for _, fragmentID := range document.EvidenceFragmentIDs {
			if !validOpaque(fragmentID) {
				return false
			}
			if _, duplicate := seen[fragmentID]; duplicate {
				return false
			}
			seen[fragmentID] = struct{}{}
		}
		if _, present := seen[document.EvidenceFragmentID]; !present {
			return false
		}
		if len(document.EvidenceFragmentIDs) > 1 {
			if len(document.EvidenceTextHashes) != len(document.EvidenceFragmentIDs) ||
				len(document.EvidenceAnchorHashes) != len(document.EvidenceFragmentIDs) {
				return false
			}
		}
		if len(document.EvidenceTextHashes) != 0 || len(document.EvidenceAnchorHashes) != 0 {
			if len(document.EvidenceTextHashes) != len(document.EvidenceFragmentIDs) ||
				len(document.EvidenceAnchorHashes) != len(document.EvidenceFragmentIDs) {
				return false
			}
			primaryIndex := -1
			for index, fragmentID := range document.EvidenceFragmentIDs {
				if !validDigest(document.EvidenceTextHashes[index]) || !validDigest(document.EvidenceAnchorHashes[index]) {
					return false
				}
				if fragmentID == document.EvidenceFragmentID {
					primaryIndex = index
				}
			}
			if primaryIndex < 0 || document.EvidenceTextHashes[primaryIndex] != document.TextHash ||
				document.EvidenceAnchorHashes[primaryIndex] != document.AnchorHash {
				return false
			}
		}
	} else if len(document.EvidenceTextHashes) != 0 || len(document.EvidenceAnchorHashes) != 0 {
		return false
	}
	return true
}

func validGeneration(value int64) bool {
	return value >= 1 && value <= maximumGeneration
}

func validQuery(query Query) bool {
	if !validScopeFilter(query.SourceScopeIDs, maximumScopeFilterSize) ||
		query.VersionState != "" && query.VersionState != VersionStateCurrent && query.VersionState != VersionStateSuperseded {
		return false
	}
	return query.Text != "" && utf8.ValidString(query.Text) && len([]byte(query.Text)) <= maximumQueryBytes && strings.TrimSpace(query.Text) != "" &&
		query.Size >= 1 && query.Size <= maximumPageSize && query.From >= 0 && query.From <= maximumPageOffset &&
		(query.Operator == "" || query.Operator == MatchAll || query.Operator == MatchAny)
}

func validVectorQuery(query VectorQuery, profileHash string, dimension int) bool {
	if !validScopeFilter(query.SourceScopeIDs, maximumScopeFilterSize) {
		return false
	}
	if query.VersionState != "" && query.VersionState != VersionStateCurrent && query.VersionState != VersionStateSuperseded {
		return false
	}
	if profileHash == "" || !validSHA256(profileHash) || dimension < 1 || dimension > 65536 ||
		query.ProfileHash != profileHash || query.Dimension != dimension || query.Size < 1 || query.Size > maximumPageSize || query.From < 0 || query.From > maximumPageOffset || query.Size+query.From > maximumPageSize || len(query.Vector) != dimension {
		return false
	}
	return validVector(query.Vector)
}

func validVector(vector []float32) bool {
	for _, value := range vector {
		if math.IsNaN(float64(value)) || math.IsInf(float64(value), 0) {
			return false
		}
	}
	return true
}

func validEndpoint(value *url.URL) bool {
	if value == nil || value.Scheme != "https" || value.User != nil || value.Host == "" || value.Path != "" || value.RawPath != "" || value.RawQuery != "" || value.Fragment != "" || value.Opaque != "" {
		return false
	}
	host := value.Hostname()
	if !netcanon.ValidCanonicalHost(host) || strings.HasSuffix(host, ".") || host != strings.ToLower(host) || net.ParseIP(host) != nil {
		return false
	}
	port := value.Port()
	if port == "" {
		return value.Host == host
	}
	portNumber, err := strconv.Atoi(port)
	return err == nil && portNumber > 0 && portNumber <= 65535 && strconv.Itoa(portNumber) == port && net.JoinHostPort(host, port) == value.Host
}

func validAlias(value string) bool {
	if value == "" || len(value) > 128 || value != strings.ToLower(value) || strings.ContainsAny(value, "/\\?#") {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') || character == '-' || (character == '_' && index > 0) {
			continue
		}
		return false
	}
	return true
}

func validOpaque(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x20 || (character >= 0x7f && character <= 0x9f) {
			return false
		}
	}
	return true
}

func validSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

// Evidence text and anchor equality projections are organization-keyed HMACs,
// while source-version/chunk hashes are plain SHA-256.  The index stores both
// forms as opaque integrity references; rejecting the keyed form here would
// make a real Evidence-backed chunk impossible to publish.
func validDigest(value string) bool {
	if validSHA256(value) {
		return true
	}
	const prefix = "hmac-sha256:k"
	if !strings.HasPrefix(value, prefix) {
		return false
	}
	remainder := value[len(prefix):]
	separator := strings.IndexByte(remainder, ':')
	if separator < 1 || separator > 9 || separator+1+64 != len(remainder) || remainder[0] == '0' {
		return false
	}
	for _, character := range remainder[:separator] {
		if character < '0' || character > '9' {
			return false
		}
	}
	for _, character := range remainder[separator+1:] {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return false
		}
	}
	return true
}

func drainBounded(reader io.Reader) error {
	if reader == nil {
		return nil
	}
	count, err := io.Copy(io.Discard, io.LimitReader(reader, maximumResponseBytes+1))
	if err != nil {
		return err
	}
	if count > maximumResponseBytes {
		return errors.New("response exceeds bounded search transport limit")
	}
	return nil
}
