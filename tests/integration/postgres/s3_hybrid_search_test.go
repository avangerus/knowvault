package postgres_test

// S3 (search by meaning without losing exactness): the negative controls of
// Outcome 2 and Outcome 3, proved end to end against real PostgreSQL.
//
// The corpus, the catalogue, the authorization chain and every gate are real:
// the files are ingested by the production folder pipeline, the semantic terms
// are the ones that pipeline extracted, and every hit is post-authorized by
// app.evidence_fragment_readable. Two dependencies are in-process fakes
// because this suite deliberately has no qualified OpenSearch or GPU: a small
// index that stores what the applier writes and honours the server-built bool
// filters of a k-NN query, and an embedding endpoint whose vectors are a fixed
// function of the text. A fake vector space is exactly right for these
// controls -- what is under test is whether the workspace, the scope, the
// version state and the revoked grant are applied, not whether bge-m3 is good
// at Russian.

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/embedding"
	"knowvault.local/verified-workspace/internal/knowledgegraph"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/retrieval"
	"knowvault.local/verified-workspace/internal/search"
	"knowvault.local/verified-workspace/internal/searchprofile"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

const (
	s3Dimension  = 4
	s3ForeignDoc = "chunk_foreign_workspace"
)

// s3Passage is one file of the S3 corpus and the chunk text indexed for it.
type s3Passage struct {
	file string
	text string
}

// s3Vector is the deterministic embedding of one text. It is a topic
// projection, not a model: passages and questions about the same subject land
// on the same axis, which is the only property these controls need.
func s3Vector(text string) []float32 {
	lowered := strings.ToLower(text)
	switch {
	case strings.Contains(lowered, "\u043c\u0443\u0441\u043e\u0440") || strings.Contains(lowered, "\u043e\u0442\u0445\u043e\u0434") || strings.Contains(lowered, "\u0443\u0442\u0438\u043b\u0438\u0437"):
		return []float32{1, 0, 0, 0}
	case strings.Contains(lowered, "\u0433\u043e\u0441\u0442"):
		return []float32{0, 1, 0, 0}
	case strings.Contains(lowered, "\u0442\u043e\u0440\u0441") || strings.Contains(lowered, "\u0440\u0435\u0441\u043f\u0438\u0440\u0430\u0442\u043e\u0440") || strings.Contains(lowered, "\u0441\u0443\u0434\u043e\u0432"):
		return []float32{0, 0, 1, 0}
	default:
		return []float32{0, 0, 0, 1}
	}
}

// s3EmbeddingTransport answers the embedding gateway exactly as the qualified
// runtime does, with the deterministic vector above.
type s3EmbeddingTransport struct{ t *testing.T }

func (transport s3EmbeddingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	raw, _ := io.ReadAll(request.Body)
	var wire struct {
		Model string `json:"model"`
		Input string `json:"input"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return s3Response(http.StatusBadRequest, `{}`), nil
	}
	body, _ := json.Marshal(map[string]any{
		"object": "list", "model": wire.Model,
		"data": []any{map[string]any{"object": "embedding", "index": 0, "embedding": s3Vector(wire.Input)}},
	})
	return s3Response(http.StatusOK, string(body)), nil
}

// s3IndexTransport is a minimal OpenSearch stand-in. It stores what the applier
// writes and, on a k-NN search, applies every server-built bool filter of the
// query before ranking -- which is the behaviour under test. A document the
// filters exclude is never scored, so a control that expects a foreign
// workspace's passage to be absent is proving the filter, not the fake.
type s3IndexTransport struct {
	mutex            sync.Mutex
	t                *testing.T
	documents        map[string]map[string]any
	afterSearch      func()
	lastSearchHitIDs []string
}

func (transport *s3IndexTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	transport.mutex.Lock()
	defer transport.mutex.Unlock()
	path := request.URL.Path
	switch {
	case request.Method == http.MethodPut && strings.Contains(path, "/_doc/"):
		raw, _ := io.ReadAll(request.Body)
		var document map[string]any
		if err := json.Unmarshal(raw, &document); err != nil {
			return s3Response(http.StatusBadRequest, `{}`), nil
		}
		id, _ := document["id"].(string)
		transport.documents[id] = document
		return s3Response(http.StatusOK, `{"result":"created"}`), nil
	case request.Method == http.MethodDelete && strings.Contains(path, "/_doc/"):
		segments := strings.Split(path, "/_doc/")
		delete(transport.documents, segments[len(segments)-1])
		return s3Response(http.StatusOK, `{"result":"deleted"}`), nil
	case request.Method == http.MethodGet:
		if strings.HasSuffix(path, "/_mapping") {
			properties := map[string]any{"embedding": map[string]any{"type": "knn_vector", "dimension": s3Dimension, "method": map[string]any{"engine": "lucene", "space_type": "cosinesimil"}}}
			for _, field := range []string{"organization_id", "embedding_profile_hash", "source_scope_ids", "version_state"} {
				properties[field] = map[string]any{"type": "keyword"}
			}
			raw, _ := json.Marshal(map[string]any{strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/_mapping"): map[string]any{"mappings": map[string]any{"properties": properties}}})
			return s3Response(http.StatusOK, string(raw)), nil
		}
		return s3Response(http.StatusOK, `{}`), nil
	case request.Method == http.MethodPost && strings.HasSuffix(path, "/_search"):
		raw, _ := io.ReadAll(request.Body)
		response, err := transport.search(raw)
		afterSearch := transport.afterSearch
		transport.afterSearch = nil
		if afterSearch != nil {
			afterSearch()
		}
		return response, err
	}
	return s3Response(http.StatusNotFound, `{}`), nil
}

func (transport *s3IndexTransport) search(raw []byte) (*http.Response, error) {
	var body struct {
		Query struct {
			Bool struct {
				Filter []map[string]any `json:"filter"`
				Must   []map[string]any `json:"must"`
			} `json:"bool"`
		} `json:"query"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return s3Response(http.StatusBadRequest, `{}`), nil
	}
	var queryVector []float32
	var queryText string
	for _, must := range body.Query.Bool.Must {
		if match, ok := must["match"].(map[string]any); ok {
			if field, ok := match["text"].(map[string]any); ok {
				queryText, _ = field["query"].(string)
			}
		}
		knn, ok := must["knn"].(map[string]any)
		if !ok {
			continue
		}
		field, ok := knn["embedding"].(map[string]any)
		if !ok {
			continue
		}
		for _, value := range field["vector"].([]any) {
			queryVector = append(queryVector, float32(value.(float64)))
		}
	}
	hits := make([]any, 0, len(transport.documents))
	transport.lastSearchHitIDs = transport.lastSearchHitIDs[:0]
	for id, document := range transport.documents {
		if !s3DocumentMatches(document, body.Query.Bool.Filter) {
			continue
		}
		score := 0.0
		if queryText != "" {
			text, _ := document["text"].(string)
			for _, term := range strings.Fields(strings.ToLower(queryText)) {
				if strings.Contains(strings.ToLower(text), term) {
					score++
				}
			}
			if score == 0 {
				continue
			}
		}
		if len(queryVector) > 0 {
			score = s3Cosine(queryVector, s3DocumentVector(document))
			// A nearest-neighbour engine does not return the whole corpus; a
			// cutoff keeps an unrelated passage out of the channel the way a
			// real index's k does.
			if score < 0.5 {
				continue
			}
		}
		hits = append(hits, map[string]any{"_id": id, "_score": score, "_source": document})
		if fragmentID, _ := document["evidence_fragment_id"].(string); fragmentID != "" {
			transport.lastSearchHitIDs = append(transport.lastSearchHitIDs, fragmentID)
		}
	}
	response, _ := json.Marshal(map[string]any{
		"hits": map[string]any{
			"total": map[string]any{"value": len(hits), "relation": "eq"},
			"hits":  hits,
		},
	})
	return s3Response(http.StatusOK, string(response)), nil
}

// s3DocumentMatches applies the query's bool filter clauses. Every clause must
// match; inside a clause any of the server-built term/terms predicates may.
func s3DocumentMatches(document map[string]any, filters []map[string]any) bool {
	for _, filter := range filters {
		clause, ok := filter["bool"].(map[string]any)
		if !ok {
			return false
		}
		matched := false
		for _, rawShould := range clause["should"].([]any) {
			should := rawShould.(map[string]any)
			if term, present := should["term"].(map[string]any); present {
				for field, value := range term {
					if s3FieldContains(document, field, []any{value}) {
						matched = true
					}
				}
			}
			if terms, present := should["terms"].(map[string]any); present {
				for field, values := range terms {
					if s3FieldContains(document, field, values.([]any)) {
						matched = true
					}
				}
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// s3FieldContains resolves a predicate against one document field, accepting
// the `.keyword` spelling the production filter also offers.
func s3FieldContains(document map[string]any, field string, values []any) bool {
	field = strings.TrimSuffix(field, ".keyword")
	stored, present := document[field]
	if !present {
		return false
	}
	candidates := map[string]struct{}{}
	switch typed := stored.(type) {
	case string:
		candidates[typed] = struct{}{}
	case []any:
		for _, value := range typed {
			if text, ok := value.(string); ok {
				candidates[text] = struct{}{}
			}
		}
	default:
		return false
	}
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			continue
		}
		if _, hit := candidates[text]; hit {
			return true
		}
	}
	return false
}

func s3DocumentVector(document map[string]any) []float32 {
	raw, ok := document["embedding"].([]any)
	if !ok {
		return nil
	}
	vector := make([]float32, 0, len(raw))
	for _, value := range raw {
		number, ok := value.(float64)
		if !ok {
			return nil
		}
		vector = append(vector, float32(number))
	}
	return vector
}

func s3Cosine(left, right []float32) float64 {
	if len(left) == 0 || len(left) != len(right) {
		return 0
	}
	var dot, leftNorm, rightNorm float64
	for index := range left {
		dot += float64(left[index]) * float64(right[index])
		leftNorm += float64(left[index]) * float64(left[index])
		rightNorm += float64(right[index]) * float64(right[index])
	}
	if leftNorm == 0 || rightNorm == 0 {
		return 0
	}
	return dot / (math.Sqrt(leftNorm) * math.Sqrt(rightNorm))
}

func s3Response(status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body))}
}

// s3EmbeddingProfile builds a qualified-shaped profile for the fake endpoint.
// The identity is computed by the production canonicalization, so a profile
// whose declared hash did not match its content would be refused here exactly
// as it is on a real deployment.
func s3EmbeddingProfile(t *testing.T) embedding.Profile {
	t.Helper()
	profile := embedding.Profile{
		SchemaVersion: embedding.ProfileSchemaVersion,
		ID:            "s3-fixture-v1", ModelID: "knowvault/s3-fixture",
		ArtifactHash:      "sha256:" + strings.Repeat("a", 64),
		TokenizerHash:     "sha256:" + strings.Repeat("b", 64),
		RuntimeHash:       "sha256:" + strings.Repeat("c", 64),
		ConfigurationHash: "sha256:" + strings.Repeat("d", 64),
		Endpoint:          "https://knowvault-embedding", ServerName: "knowvault-embedding",
		Dimension: s3Dimension, MaxInputBytes: 8192, Revision: 1,
	}
	raw, err := profile.CanonicalBytes()
	if err != nil {
		t.Fatalf("s3 profile canonical bytes: %v", err)
	}
	profile.ProfileHash = canon.Hash(raw)
	return profile
}

// TestS3HybridWorkspaceSearchNegativeControls proves the S3 Outcome 2 and
// Outcome 3 controls over a real ingested corpus.
func TestS3HybridWorkspaceSearchNegativeControls(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)
	root := t.TempDir()
	directory := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	// Three passages. "waste" carries no word of the synonym question; "gost"
	// carries an exact identifier; the two "torc" files each define the same
	// name as a different thing, which is what makes the homonym real rather
	// than staged.
	passages := []s3Passage{
		{file: "waste.txt", text: "\u0432\u044b\u0432\u043e\u0437 \u043c\u0443\u0441\u043e\u0440\u0430 \u0441\u043e \u0434\u0432\u043e\u0440\u0430 \u043f\u0440\u043e\u0438\u0437\u0432\u043e\u0434\u0438\u0442\u0441\u044f \u0435\u0436\u0435\u0434\u043d\u0435\u0432\u043d\u043e \u043f\u043e \u0433\u0440\u0430\u0444\u0438\u043a\u0443\n"},
		{file: "gost.txt", text: "\u0440\u0435\u0433\u043b\u0430\u043c\u0435\u043d\u0442 \u0413\u041e\u0421\u0422-12345 \u043f\u0440\u0438\u043c\u0435\u043d\u044f\u0435\u0442\u0441\u044f \u043a\u043e \u0432\u0441\u0435\u043c \u043e\u0431\u044a\u0435\u043a\u0442\u0430\u043c\n"},
		{file: "torc-ships.txt", text: "\u0422\u041e\u0420\u0421 \u2014 \u044d\u0442\u043e \u0440\u0435\u043c\u043e\u043d\u0442 \u0441\u0443\u0434\u043e\u0432\n"},
		{file: "torc-illness.txt", text: "\u0422\u041e\u0420\u0421 \u2014 \u044d\u0442\u043e \u0442\u044f\u0436\u0451\u043b\u044b\u0439 \u043e\u0441\u0442\u0440\u044b\u0439 \u0440\u0435\u0441\u043f\u0438\u0440\u0430\u0442\u043e\u0440\u043d\u044b\u0439 \u0441\u0438\u043d\u0434\u0440\u043e\u043c\n"},
	}
	for _, passage := range passages {
		writeS1dFile(t, filepath.Join(directory, passage.file), passage.text)
	}
	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	fixture := seedS1dScopeAuthority(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer,
		s1dScopeID, configHash, 1, "binding_01ARZ3NDEKTSV4RRFFQ69G5FAV", "grant_s1d_admin", "confirmation_s1d_admin")

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue := mustQueue(t, workerStore)
	handler := newS1dHandler(t, workerStore, queue, codec, root).WithKnowledgeGraph(knowledgegraph.NewRepository())
	runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "s3-sync")

	profile := s3EmbeddingProfile(t)
	embeddingClient, err := embedding.New(profile, s3TrustRoots(), nil,
		&http.Client{Transport: s3EmbeddingTransport{t: t}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("s3 embedding client: %v", err)
	}
	index := &s3IndexTransport{t: t, documents: map[string]map[string]any{}}
	searchClient, err := search.New(search.Config{
		Endpoint: "https://search.example", IndexAlias: "org-s1d-v1", OrganizationID: s1dOrg,
		Generation: 1, GenerationFence: 1, TrustRoots: s3TrustRoots(),
		VectorProfileHash: profile.ProfileHash, VectorDimension: s3Dimension,
		HTTPClient: &http.Client{Transport: index, Timeout: 5 * time.Second},
	})
	if err != nil {
		t.Fatalf("s3 search client: %v", err)
	}
	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatalf("s3 viewer: %v", err)
	}
	s3IndexCorpus(t, ctx, admin, workerStore, codec, viewer, searchClient, embeddingClient, profile, passages)

	// A passage of the same tenant that belongs to a scope this workspace does
	// not bind. It is in the same index -- that is the whole point of one index
	// per organization -- and its topic is exactly the synonym question's.
	index.documents[s3ForeignDoc] = map[string]any{
		"id": s3ForeignDoc, "organization_id": s1dOrg,
		"source_object_id": "obj_foreign", "source_version_id": "ver_foreign",
		"extraction_id": "ext_foreign", "evidence_fragment_id": "frag_foreign",
		"text": "\u0443\u0442\u0438\u043b\u0438\u0437\u0430\u0446\u0438\u044f \u043e\u0442\u0445\u043e\u0434\u043e\u0432 \u0434\u0440\u0443\u0433\u043e\u0433\u043e \u0437\u0430\u043a\u0430\u0437\u0447\u0438\u043a\u0430", "version_state": search.VersionStateCurrent,
		"source_scope_ids":       []any{"scope_09FOREIGNFOREIGNFOREIGNFO"},
		"embedding_profile_hash": profile.ProfileHash, "embedding_dimension": s3Dimension,
		"embedding":        []any{1.0, 0.0, 0.0, 0.0},
		"text_hash":        "sha256:" + strings.Repeat("1", 64),
		"anchor_hash":      "sha256:" + strings.Repeat("2", 64),
		"content_hash":     "sha256:" + strings.Repeat("3", 64),
		"index_generation": 1.0, "generation_fence": 1.0,
	}

	vectorProvider, err := retrieval.NewOpenSearchVectorProvider(embeddingClient, searchClient)
	if err != nil {
		t.Fatalf("s3 vector provider: %v", err)
	}
	executor, err := retrieval.NewExecutorWithGraphAndVector(searchClient, viewer, appStore,
		knowledgegraph.NewRepository(), vectorProvider)
	if err != nil {
		t.Fatalf("s3 executor: %v", err)
	}
	access := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_s3"}
	run := func(t *testing.T, query string, mode retrieval.SearchMode) retrieval.WorkspaceSearchPage {
		t.Helper()
		page, err := executor.SearchWorkspace(ctx, access, s1dWorkspace, query,
			retrieval.WorkspaceSearchOptions{Mode: mode, Limit: 20})
		if err != nil {
			t.Fatalf("SearchWorkspace(%q, %s): %v", query, mode, err)
		}
		return page
	}
	texts := func(page retrieval.WorkspaceSearchPage) []string {
		values := make([]string, 0, len(page.Hits))
		for _, hit := range page.Hits {
			values = append(values, string(hit.Fragment.Text))
		}
		return values
	}
	contains := func(values []string, needle string) bool {
		for _, value := range values {
			if strings.Contains(value, needle) {
				return true
			}
		}
		return false
	}

	const synonymQuestion = "\u0443\u0442\u0438\u043b\u0438\u0437\u0430\u0446\u0438\u044f \u043e\u0442\u0445\u043e\u0434\u043e\u0432"
	const identifierQuestion = "\u0413\u041e\u0421\u0422-12345"

	t.Run("a synonym absent from the document is found by meaning and not by words", func(t *testing.T) {
		lexical := run(t, synonymQuestion, retrieval.SearchModeLexical)
		if contains(texts(lexical), "\u0432\u044b\u0432\u043e\u0437 \u043c\u0443\u0441\u043e\u0440\u0430") {
			t.Fatalf("lexical mode matched a document that contains none of the question's words: %v", texts(lexical))
		}
		vector := run(t, synonymQuestion, retrieval.SearchModeVector)
		if !contains(texts(vector), "\u0432\u044b\u0432\u043e\u0437 \u043c\u0443\u0441\u043e\u0440\u0430") {
			t.Fatalf("vector mode did not find the passage by meaning: %v", texts(vector))
		}
		hybrid := run(t, synonymQuestion, retrieval.SearchModeHybrid)
		if !contains(texts(hybrid), "\u0432\u044b\u0432\u043e\u0437 \u043c\u0443\u0441\u043e\u0440\u0430") {
			t.Fatalf("hybrid mode did not find the passage by meaning: %v", texts(hybrid))
		}
		if hybrid.Profile.Degraded || !hybrid.Profile.Vector || hybrid.Profile.Fusion != "rrf" || hybrid.Profile.K != 60 {
			t.Fatalf("hybrid profile = %+v, want an undegraded rrf/k=60 profile with a vector channel", hybrid.Profile)
		}
		for _, hit := range hybrid.Hits {
			if hit.Fragment.SourcePath == "" {
				t.Fatal("authorized search hit omitted its source path")
			}
			if strings.Contains(string(hit.Fragment.Text), "\u0432\u044b\u0432\u043e\u0437 \u043c\u0443\u0441\u043e\u0440\u0430") && hit.Channel != retrieval.HitChannelVector {
				t.Fatalf("meaning-only hit reported channel %q, want %q", hit.Channel, retrieval.HitChannelVector)
			}
		}
	})

	t.Run("an exact identifier is found by words and by the hybrid", func(t *testing.T) {
		for _, mode := range []retrieval.SearchMode{retrieval.SearchModeLexical, retrieval.SearchModeHybrid} {
			page := run(t, identifierQuestion, mode)
			if !contains(texts(page), "\u0413\u041e\u0421\u0422-12345") {
				t.Fatalf("%s mode lost the exact identifier: %v", mode, texts(page))
			}
		}
	})

	t.Run("another workspace's passage appears in no mode", func(t *testing.T) {
		for _, mode := range []retrieval.SearchMode{retrieval.SearchModeLexical, retrieval.SearchModeVector, retrieval.SearchModeHybrid} {
			page := run(t, synonymQuestion, mode)
			if contains(texts(page), "\u0434\u0440\u0443\u0433\u043e\u0433\u043e \u0437\u0430\u043a\u0430\u0437\u0447\u0438\u043a\u0430") {
				t.Fatalf("%s mode returned a passage of a scope this workspace does not bind: %v", mode, texts(page))
			}
			for _, hit := range page.Hits {
				if hit.Fragment.FragmentID == "frag_foreign" {
					t.Fatalf("%s mode returned the foreign fragment id", mode)
				}
			}
		}
	})

	t.Run("a homonym resolves to exactly two addressed term hits", func(t *testing.T) {
		page := run(t, "\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435 \u0422\u041e\u0420\u0421", retrieval.SearchModeHybrid)
		if len(page.TermHits) != 2 {
			for _, hit := range page.TermHits {
				t.Logf("term hit: kind=%s fragment=%s text=%q", hit.TermKind, hit.Fragment.FragmentID, hit.Fragment.Text)
			}
			t.Fatalf("term hits = %d, want exactly two (the workspace calls two different things \u0422\u041e\u0420\u0421)", len(page.TermHits))
		}
		seen := map[string]bool{}
		for _, hit := range page.TermHits {
			if hit.Channel != retrieval.HitChannelTerm {
				t.Fatalf("term hit channel = %q, want %q", hit.Channel, retrieval.HitChannelTerm)
			}
			// A term hit is an ordinary addressable fragment: it must resolve to
			// a real span through the same read the address names.
			if hit.Fragment.FragmentID == "" || len(hit.Fragment.Text) == 0 || len(hit.Fragment.Anchor) == 0 {
				t.Fatalf("term hit does not resolve to a real span: %+v", hit.Fragment)
			}
			if _, err := viewer.Read(ctx, access, s1dWorkspace, hit.Fragment.FragmentID); err != nil {
				t.Fatalf("term hit address does not resolve through the read gate: %v", err)
			}
			seen[hit.Fragment.SourceObjectID] = true
		}
		if len(seen) != 2 {
			t.Fatalf("the two term hits came from %d object(s), want two different things", len(seen))
		}
		// The term channel is additional, never a replacement.
		if len(page.Hits) == 0 {
			t.Fatal("the ranked page disappeared when the term channel answered")
		}
	})

	t.Run("a workspace question whose words name nothing in the catalogue has no term channel", func(t *testing.T) {
		page := run(t, synonymQuestion, retrieval.SearchModeHybrid)
		if len(page.TermHits) != 0 {
			t.Fatalf("term hits = %d for a question the catalogue defines nothing for", len(page.TermHits))
		}
	})

	t.Run("the inventory says which profile embedded which object", func(t *testing.T) {
		inventory, err := viewer.ListObjects(ctx, access, s1dWorkspace, false, 0, 50)
		if err != nil {
			t.Fatalf("inventory: %v", err)
		}
		if len(inventory.Items) < len(passages) {
			t.Fatalf("inventory listed %d object(s), want at least %d", len(inventory.Items), len(passages))
		}
		for _, item := range inventory.Items {
			if item.EmbeddingProfileHash != profile.ProfileHash {
				t.Fatalf("object %s reports profile hash %q, want the mounted one", item.SourceObjectID, item.EmbeddingProfileHash)
			}
			if item.EmbeddingProfileID != profile.ID {
				t.Fatalf("object %s reports profile id %q, want %q", item.SourceObjectID, item.EmbeddingProfileID, profile.ID)
			}
		}
	})

	// Half of the version control of Outcome 2. The other half -- a superseded
	// hit returned and labelled old -- is not delivered by this stage and is
	// not faked here: app.evidence_fragment_readable discloses the current
	// version only, so no surface of this tree can disclose superseded content
	// at all. What this stage does guarantee is that the default page is
	// current-only and that one superseded version in a workspace no longer
	// refuses the whole all_versions page.
	t.Run("a superseded version never appears in the default page", func(t *testing.T) {
		writeS1dFile(t, filepath.Join(directory, "waste.txt"), "\u0432\u044b\u0432\u043e\u0437 \u043c\u0443\u0441\u043e\u0440\u0430 \u0441\u043e \u0434\u0432\u043e\u0440\u0430 \u043f\u0440\u043e\u0438\u0437\u0432\u043e\u0434\u0438\u0442\u0441\u044f \u0434\u0432\u0430\u0436\u0434\u044b \u0432 \u0434\u0435\u043d\u044c\n")
		runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "s3-resync")
		var superseded int64
		if err := admin.QueryRow(ctx, `SELECT count(*) FROM public.source_version
			WHERE organization_id=$1 AND state <> 'CURRENT'`, s1dOrg).Scan(&superseded); err != nil {
			t.Fatalf("count superseded versions: %v", err)
		}
		if superseded == 0 {
			t.Fatal("the re-sync produced no superseded version, so this control proves nothing")
		}
		for _, hit := range run(t, "\u0432\u044b\u0432\u043e\u0437 \u043c\u0443\u0441\u043e\u0440\u0430", retrieval.SearchModeHybrid).Hits {
			if hit.VersionState != search.VersionStateCurrent {
				t.Fatalf("default search returned a %s hit: %q", hit.VersionState, hit.Fragment.Text)
			}
			if strings.Contains(string(hit.Fragment.Text), "\u0435\u0436\u0435\u0434\u043d\u0435\u0432\u043d\u043e \u043f\u043e \u0433\u0440\u0430\u0444\u0438\u043a\u0443") {
				t.Fatalf("default search returned the superseded text: %q", hit.Fragment.Text)
			}
		}
		page, err := executor.SearchWorkspace(ctx, access, s1dWorkspace, "\u0432\u044b\u0432\u043e\u0437 \u043c\u0443\u0441\u043e\u0440\u0430",
			retrieval.WorkspaceSearchOptions{Mode: retrieval.SearchModeHybrid, Limit: 20, AllVersions: true})
		if err != nil {
			t.Fatalf("all-versions search refused the whole page because of one superseded version: %v", err)
		}
		if len(page.Hits) == 0 {
			t.Fatal("all-versions search returned nothing at all")
		}
		for _, hit := range page.Hits {
			if strings.Contains(string(hit.Fragment.Text), "\u0435\u0436\u0435\u0434\u043d\u0435\u0432\u043d\u043e \u043f\u043e \u0433\u0440\u0430\u0444\u0438\u043a\u0443") &&
				hit.VersionState != search.VersionStateSuperseded {
				t.Fatalf("a superseded hit was returned without being labelled old: %+v", hit)
			}
		}
	})

	t.Run("an object removed after indexing is rejected while the workspace stays active", func(t *testing.T) {
		var removedFragmentID string
		for _, document := range index.documents {
			text, _ := document["text"].(string)
			if !strings.Contains(text, "\u0432\u044b\u0432\u043e\u0437 \u043c\u0443\u0441\u043e\u0440\u0430") {
				continue
			}
			removedFragmentID, _ = document["evidence_fragment_id"].(string)
			break
		}
		if removedFragmentID == "" {
			t.Fatal("the indexed waste passage has no evidence fragment id")
		}
		// Remove the object after the external index has selected the candidate
		// but before SearchWorkspace re-resolves it. This is the exact stale-index
		// race the post-authorization gate must make safe.
		removedDuringSearch := false
		index.afterSearch = func() {
			if err := os.Remove(filepath.Join(directory, "waste.txt")); err != nil {
				t.Fatalf("remove indexed file: %v", err)
			}
			runSync(t, ctx, handler, queue, workerAccess(t, s1dOrg), "s3-remove-after-index")
			removedDuringSearch = true
		}
		vectorPage, err := executor.SearchWorkspace(ctx, access, s1dWorkspace, synonymQuestion,
			retrieval.WorkspaceSearchOptions{Mode: retrieval.SearchModeVector, Limit: 20})
		if err != nil {
			t.Fatalf("vector mode refused an otherwise active workspace after one object was removed: %v", err)
		}
		if !removedDuringSearch {
			t.Fatal("the object was not removed between external retrieval and live authorization")
		}
		selectedByIndex := false
		for _, fragmentID := range index.lastSearchHitIDs {
			if fragmentID == removedFragmentID {
				selectedByIndex = true
				break
			}
		}
		if !selectedByIndex {
			t.Fatal("the external index did not return the soon-to-be-removed fragment before live authorization")
		}

		// The fake external index deliberately receives no delete.
		stillIndexed := false
		for _, document := range index.documents {
			fragmentID, _ := document["evidence_fragment_id"].(string)
			if fragmentID == removedFragmentID {
				stillIndexed = true
				break
			}
		}
		if !stillIndexed {
			t.Fatal("the external index lost the removed fragment, so the stale-index control proves nothing")
		}
		if _, err := viewer.Read(ctx, access, s1dWorkspace, removedFragmentID); err == nil {
			t.Fatal("the live evidence gate still admitted the removed fragment")
		}
		pages := map[retrieval.SearchMode]retrieval.WorkspaceSearchPage{
			retrieval.SearchModeVector: vectorPage,
		}
		hybridPage, err := executor.SearchWorkspace(ctx, access, s1dWorkspace, synonymQuestion,
			retrieval.WorkspaceSearchOptions{Mode: retrieval.SearchModeHybrid, Limit: 20})
		if err != nil {
			t.Fatalf("hybrid mode refused an otherwise active workspace after one object was removed: %v", err)
		}
		pages[retrieval.SearchModeHybrid] = hybridPage
		for mode, page := range pages {
			for _, hit := range page.Hits {
				if hit.Fragment.FragmentID == removedFragmentID {
					t.Fatalf("%s mode returned the removed fragment retained by the stale index", mode)
				}
			}
		}
	})

	t.Run("a right revoked after indexing removes the hit from every mode", func(t *testing.T) {
		var confirmationID, confirmationHash string
		if err := admin.QueryRow(ctx, `SELECT confirmation_id, confirmation_hash
			FROM public.workspace_managed_grant_confirmation
			WHERE organization_id=$1 AND workspace_id=$2 LIMIT 1`, s1dOrg, s1dWorkspace).
			Scan(&confirmationID, &confirmationHash); err != nil {
			t.Fatalf("resolve confirmation: %v", err)
		}
		// The revocation goes through the production authority runtime, so it
		// carries its command receipt and is exactly the revocation an operator
		// performs -- not a row poked into the table.
		if _, err := newAuthorityRuntime(t, ctx).RevokeManagedConfirmation(ctx,
			authorityAccess(fixture, s1dOwner, "req_s3_revoke"),
			workspacerepository.RevokeConfirmationRequest{
				IdempotencyKey: authorityIdempotencyKey("s3-confirm-revoke"), OrganizationID: s1dOrg,
				WorkspaceID: s1dWorkspace, ConfirmationID: confirmationID, ConfirmationHash: confirmationHash,
				ExpectedPolicyRevision: fixture.policyID,
			}); err != nil {
			t.Fatalf("revoke confirmation: %v", err)
		}
		// The index still holds every passage: nothing was re-indexed, and the
		// vectors are exactly the ones that answered a moment ago.
		if len(index.documents) < len(passages) {
			t.Fatalf("index lost documents (%d) before the revocation control", len(index.documents))
		}
		for _, mode := range []retrieval.SearchMode{retrieval.SearchModeLexical, retrieval.SearchModeVector, retrieval.SearchModeHybrid} {
			page, err := executor.SearchWorkspace(ctx, access, s1dWorkspace, synonymQuestion,
				retrieval.WorkspaceSearchOptions{Mode: mode, Limit: 20})
			if err == nil && len(page.Hits) > 0 {
				t.Fatalf("%s mode still returned %d hit(s) after the grant was revoked: %v", mode, len(page.Hits), texts(page))
			}
			if err == nil && len(page.TermHits) > 0 {
				t.Fatalf("%s mode still returned a term hit after the grant was revoked", mode)
			}
		}
	})
}

// s3IndexCorpus writes one search chunk per ingested passage and runs the real
// applier against the fake index, so every indexed document is the one
// production would have written -- including the scope memberships and the
// version state the pre-filter relies on.
func s3IndexCorpus(t *testing.T, ctx context.Context, admin *pgxpool.Pool, workerStore *database.Store,
	codec *artifactcrypto.Codec, viewer *evidence.Viewer, searchClient *search.Client, embeddingClient *embedding.Client,
	profile embedding.Profile, passages []s3Passage) {
	t.Helper()
	repository, err := search.NewRepository()
	if err != nil {
		t.Fatalf("s3 search repository: %v", err)
	}
	workerAccessContext := workerAccess(t, s1dOrg)
	rows, err := admin.Query(ctx, `
		SELECT version.id, active.extraction_id, fragment.id, fragment.ordinal
		  FROM public.source_object object
		  JOIN public.source_version version
		    ON version.organization_id = object.organization_id AND version.id = object.current_version_id
		  JOIN public.source_version_active_extraction active
		    ON active.organization_id = version.organization_id AND active.source_version_id = version.id
		  JOIN public.evidence_fragment fragment
		    ON fragment.organization_id = active.organization_id AND fragment.extraction_id = active.extraction_id
		 WHERE object.organization_id = $1 AND object.queryable
		 ORDER BY version.id, fragment.ordinal`, s1dOrg)
	if err != nil {
		t.Fatalf("s3 corpus fragments: %v", err)
	}
	type fragmentRef struct {
		versionID, extractionID, fragmentID string
		ordinal                             int64
	}
	references := make([]fragmentRef, 0, 8)
	for rows.Next() {
		var reference fragmentRef
		if err := rows.Scan(&reference.versionID, &reference.extractionID, &reference.fragmentID, &reference.ordinal); err != nil {
			rows.Close()
			t.Fatalf("s3 corpus scan: %v", err)
		}
		references = append(references, reference)
	}
	rows.Close()
	if len(references) < len(passages) {
		t.Fatalf("s3 corpus produced %d fragment(s), want at least %d", len(references), len(passages))
	}
	if err := workerStore.Write(ctx, workerAccessContext, func(txCtx context.Context, transaction database.Transaction) error {
		if err := repository.EnsureMountedLexicalProfile(txCtx, transaction, workerAccessContext, 1, 1); err != nil {
			return err
		}
		revision, err := repository.StageRevision(txCtx, transaction, workerAccessContext, profile.ID, profile.ProfileHash, 1, 1)
		if err != nil {
			return err
		}
		return repository.ActivateRevision(txCtx, transaction, workerAccessContext, revision.ActivationRevision, time.Now().UTC())
	}); err != nil {
		t.Fatalf("s3 activate search profile: %v", err)
	}
	memberAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_s3_index"}
	for _, reference := range references {
		// The chunk text is the fragment's own canonical text, read back through
		// the authorized viewer the production chunker's input ultimately comes
		// from, so the passage that is embedded is the passage that is cited.
		fragment, err := viewer.Read(ctx, memberAccess, s1dWorkspace, reference.fragmentID)
		if err != nil {
			t.Fatalf("s3 chunk text for %s: %v", reference.fragmentID, err)
		}
		text := string(fragment.Text)
		chunkID := mustID(t, "chunk")
		owner := mustSearchOwner(t, s1dOrg, chunkID)
		envelope, err := codec.Seal(owner, []byte(text))
		if err != nil {
			t.Fatalf("s3 seal chunk: %v", err)
		}
		if err := workerStore.Write(ctx, workerAccessContext, func(txCtx context.Context, transaction database.Transaction) error {
			chunk := search.Chunk{ID: chunkID, OrganizationID: s1dOrg,
				SourceVersionID: reference.versionID, ExtractionID: reference.extractionID,
				ChunkHash: envelope.PlaintextHash(), TokenCount: 8,
				EmbeddingProfileHash:       profile.ProfileHash,
				EmbeddingModelArtifactHash: profile.ArtifactHash,
				EmbeddingDimension:         profile.Dimension,
			}
			if err := repository.CreateChunk(txCtx, transaction, workerAccessContext, chunk, mustID(t, "artifact"), envelope); err != nil {
				return err
			}
			return repository.AddFragment(txCtx, transaction, workerAccessContext, chunkID, reference.fragmentID, reference.ordinal)
		}); err != nil {
			t.Fatalf("s3 durable chunk: %v", err)
		}
	}
	applier, err := search.NewApplierWithEmbedding(workerStore, repository, codec, searchClient, embeddingClient)
	if err != nil {
		t.Fatalf("s3 applier: %v", err)
	}
	applied, err := applier.Drain(ctx, workerAccessContext, 100)
	if err != nil || applied < len(references) {
		t.Fatalf("s3 applier drained %d event(s): %v", applied, err)
	}
	// Reindex must rebuild already embedded chunks too. Their durable original
	// profile hash is not an empty outbox payload and cannot be silently skipped.
	rebuilt, cursor, err := applier.Reindex(ctx, workerAccessContext, "", 100)
	if err != nil || cursor != "" || rebuilt != len(references) {
		t.Fatalf("s3 reindex rebuilt %d/%d chunks, cursor=%q: %v", rebuilt, len(references), cursor, err)
	}
}

// s3TrustRoots supplies a non-empty administrator-owned trust pool. No TLS
// handshake happens in this suite: both transports are in process, and the
// pool only proves the production constructors refuse an unmounted channel.
func s3TrustRoots() *x509.CertPool {
	roots := x509.NewCertPool()
	roots.AddCert(&x509.Certificate{RawSubject: []byte("knowvault-embedding")})
	return roots
}

// TestS3RetrievalProfileChannelAuthorityAndJournal proves S3 Outcome 4 against
// the real workspace authority and the real audit journal: only an OWNER of the
// workspace may select the retrieval profile of a call, anyone else's attempt
// changes nothing, and every presented value is findable in the journal under
// an action that names the profile that was asked for.
func TestS3RetrievalProfileChannelAuthorityAndJournal(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	const organizationID, workspaceID, ownerID, outsiderID = "org_alpha", "ws_alpha", "usr_alice", "usr_bob"
	seedOrganization(t, ctx, admin, organizationID, ownerID, workspaceID)
	if _, err := admin.Exec(ctx, `INSERT INTO public.principal (id, organization_id, type, display_name, status)
		VALUES ($1,$2,'USER',$1,'ACTIVE')`, outsiderID, organizationID); err != nil {
		t.Fatalf("seed non-owner principal: %v", err)
	}

	storeConfig := database.DefaultConfig()
	storeConfig.URL = applicationURL(t, testDatabaseURL(t))
	appStore, err := database.Open(ctx, storeConfig)
	if err != nil {
		t.Fatalf("s3 application store: %v", err)
	}
	t.Cleanup(appStore.Close)
	auditStore, err := audit.NewStore(appStore)
	if err != nil {
		t.Fatalf("s3 audit store: %v", err)
	}
	workspaceStore, err := workspacerepository.New(appStore, auditStore)
	if err != nil {
		t.Fatalf("s3 workspace authority: %v", err)
	}
	searchRepository, err := search.NewRepository()
	if err != nil {
		t.Fatalf("s3 search repository: %v", err)
	}
	profile := s3EmbeddingProfile(t)
	profiles, err := searchprofile.New(appStore, auditStore, workspaceStore, searchRepository,
		searchprofile.MountedProfile{ProfileID: profile.ID, ProfileHash: profile.ProfileHash,
			Dimension: profile.Dimension, Generation: 1, GenerationFence: 1})
	if err != nil {
		t.Fatalf("s3 profile authority: %v", err)
	}
	ownerAccess := database.AccessContext{OrganizationID: organizationID, PrincipalID: ownerID, RequestID: "req_s3_owner"}
	outsiderAccess := database.AccessContext{OrganizationID: organizationID, PrincipalID: outsiderID, RequestID: "req_s3_outsider"}

	t.Run("an owner running an ablation gets the profile asked for", func(t *testing.T) {
		selected, granted, err := profiles.ResolveCallProfile(ctx, ownerAccess, workspaceID, "lexical")
		if err != nil || !granted || selected != searchprofile.CallProfileLexical {
			t.Fatalf("owner ablation = (%q, %v, %v), want a granted lexical profile", selected, granted, err)
		}
	})

	t.Run("a non-owner's profile is ignored and the call keeps the default", func(t *testing.T) {
		selected, granted, err := profiles.ResolveCallProfile(ctx, outsiderAccess, workspaceID, "vector")
		if err != nil || granted || selected != searchprofile.CallProfileHybrid {
			t.Fatalf("non-owner ablation = (%q, %v, %v), want the default hybrid and no grant", selected, granted, err)
		}
	})

	t.Run("a profile nobody can run is refused rather than silently defaulted", func(t *testing.T) {
		selected, granted, err := profiles.ResolveCallProfile(ctx, ownerAccess, workspaceID, "graph")
		if err != nil || granted || selected != searchprofile.CallProfileHybrid {
			t.Fatalf("unknown ablation = (%q, %v, %v), want the default hybrid and no grant", selected, granted, err)
		}
	})

	t.Run("presenting no profile is not an event", func(t *testing.T) {
		before := s3ProfileCallEvents(t, ctx, admin, organizationID)
		if _, granted, err := profiles.ResolveCallProfile(ctx, outsiderAccess, workspaceID, ""); err != nil || granted {
			t.Fatalf("absent profile = (%v, %v), want no grant and no error", granted, err)
		}
		if after := s3ProfileCallEvents(t, ctx, admin, organizationID); len(after) != len(before) {
			t.Fatalf("an ordinary call without a profile wrote %d journal event(s)", len(after)-len(before))
		}
	})

	t.Run("every presented profile is findable in the journal", func(t *testing.T) {
		events := s3ProfileCallEvents(t, ctx, admin, organizationID)
		want := map[string]string{
			"search.profile_call_lexical": "SUCCESS",
			"search.profile_call_vector":  "DENIED",
			"search.profile_call_hybrid":  "DENIED",
		}
		seen := map[string]string{}
		for _, event := range events {
			seen[event.action] = event.outcome
			if event.resourceID != profile.ProfileHash {
				t.Fatalf("journal entry %s does not anchor on the mounted profile: %q", event.action, event.resourceID)
			}
		}
		for action, outcome := range want {
			if seen[action] != outcome {
				t.Fatalf("journal has %s = %q, want %q (events: %+v)", action, seen[action], outcome, events)
			}
		}
	})

	t.Run("a deployment with nothing to ablate records nothing", func(t *testing.T) {
		bare, err := searchprofile.New(appStore, auditStore, workspaceStore, searchRepository, searchprofile.MountedProfile{})
		if err != nil {
			t.Fatalf("s3 lexical-only profile authority: %v", err)
		}
		before := s3ProfileCallEvents(t, ctx, admin, organizationID)
		selected, granted, err := bare.ResolveCallProfile(ctx, ownerAccess, workspaceID, "vector")
		if err != nil || granted || selected != searchprofile.CallProfileHybrid {
			t.Fatalf("lexical-only ablation = (%q, %v, %v), want the default and no grant", selected, granted, err)
		}
		if after := s3ProfileCallEvents(t, ctx, admin, organizationID); len(after) != len(before) {
			t.Fatal("a deployment with no vector space to ablate wrote a profile-selection event")
		}
	})
}

type s3ProfileEvent struct {
	action, outcome, resourceID string
}

func s3ProfileCallEvents(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID string) []s3ProfileEvent {
	t.Helper()
	rows, err := admin.Query(ctx, `SELECT action, outcome, resource_id FROM public.audit_event
		WHERE organization_id=$1 AND action LIKE 'search.profile_call_%' ORDER BY sequence`, organizationID)
	if err != nil {
		t.Fatalf("read profile call journal: %v", err)
	}
	defer rows.Close()
	events := make([]s3ProfileEvent, 0, 4)
	for rows.Next() {
		var event s3ProfileEvent
		if err := rows.Scan(&event.action, &event.outcome, &event.resourceID); err != nil {
			t.Fatalf("scan profile call journal: %v", err)
		}
		events = append(events, event)
	}
	return events
}
