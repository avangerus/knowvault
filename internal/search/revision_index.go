package search

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type revisionIndices struct {
	sync.Mutex
	ready map[string]bool
}

// Revision one is the deployed legacy layout. Later vector spaces get a
// physical index keyed by the complete profile identity, never an overwrite
// of an incompatible vector field. Revision/hash come from PostgreSQL or the
// mounted profile; no public tool accepts these selectors.
func (client *Client) revisionIndex(revision int64, profileHash string) (string, error) {
	if client == nil || revision < 0 || revision > maximumGeneration {
		return "", &Error{code: CodeInvalid}
	}
	if revision <= 1 {
		return client.indexAlias, nil
	}
	if !validSHA256(profileHash) {
		return "", &Error{code: CodeInvalid}
	}
	return client.indexAlias + "-p-" + strconv.FormatInt(revision, 10) + "-" + strings.TrimPrefix(profileHash, "sha256:"), nil
}

func (client *Client) EnsureRevisionIndex(ctx context.Context, revision int64) error {
	index, err := client.revisionIndex(revision, client.vectorProfileHash)
	if err != nil {
		return err
	}
	if client.revisions != nil {
		client.revisions.Lock()
		defer client.revisions.Unlock()
		if client.revisions.ready[index] {
			return nil
		}
	}
	qualified := *client
	qualified.indexAlias = index
	if err := qualified.EnsureIndex(ctx); err != nil {
		return err
	}
	if revision > 1 {
		if err := qualified.checkVectorMapping(ctx); err != nil {
			return err
		}
	}
	if client.revisions != nil {
		client.revisions.ready[index] = true
	}
	return nil
}

func (client *Client) checkVectorMapping(ctx context.Context) error {
	request, err := client.request(ctx, http.MethodGet, "/"+client.indexAlias+"/_mapping", nil)
	if err != nil {
		return err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return &Error{code: CodeRejected, status: response.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil || len(raw) > maximumResponseBytes {
		return &Error{code: CodeResponse, cause: err}
	}
	var mappings map[string]struct {
		Mappings struct {
			Properties map[string]struct {
				Type      string `json:"type"`
				Dimension int    `json:"dimension"`
				Method    struct {
					Engine    string `json:"engine"`
					SpaceType string `json:"space_type"`
				} `json:"method"`
			} `json:"properties"`
		} `json:"mappings"`
	}
	if json.Unmarshal(raw, &mappings) != nil || len(mappings) != 1 {
		return &Error{code: CodeResponse}
	}
	properties := mappings[client.indexAlias].Mappings.Properties
	vector := properties["embedding"]
	if vector.Type != "knn_vector" || vector.Dimension != client.vectorDimension || vector.Method.Engine != "lucene" || vector.Method.SpaceType != "cosinesimil" {
		return &Error{code: CodeVectorProfileUnavailable}
	}
	for _, field := range []string{"organization_id", "embedding_profile_hash", "source_scope_ids", "version_state"} {
		if properties[field].Type != "keyword" {
			return &Error{code: CodeVectorProfileUnavailable}
		}
	}
	return nil
}

// Refresh is required before activating the durable revision: successful PUTs
// alone do not guarantee that the first query can see the completed corpus.
func (client *Client) RefreshRevision(ctx context.Context, revision int64) error {
	index, err := client.revisionIndex(revision, client.vectorProfileHash)
	if err != nil {
		return err
	}
	request, err := client.request(ctx, http.MethodPost, "/"+index+"/_refresh", nil)
	if err != nil {
		return err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return &Error{code: CodeRejected, status: response.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil || len(raw) > maximumResponseBytes {
		return &Error{code: CodeResponse, cause: err}
	}
	var result struct {
		Shards *struct {
			Total      int `json:"total"`
			Successful int `json:"successful"`
			Failed     int `json:"failed"`
		} `json:"_shards"`
	}
	if json.Unmarshal(raw, &result) != nil || result.Shards == nil || result.Shards.Total < 1 || result.Shards.Successful < 1 || result.Shards.Failed != 0 {
		return &Error{code: CodeResponse}
	}
	return nil
}

// DeleteProfileCopies erases the immutable chunk from every retained revision.
// Both the namespace and tenant predicate are deployment-owned; an OpenSearch
// partial failure is never acknowledged as a successful purge.
func (client *Client) DeleteProfileCopies(ctx context.Context, documentID string) error {
	if client == nil || client.http == nil || ctx == nil || !validOpaque(documentID) || len(documentID) > maximumDocumentIDSize {
		return &Error{code: CodeInvalid}
	}
	// Enumerate only this deployment's derived indices, then delete by ID.
	// delete_by_query is unsuitable: a just-written, unrefreshed document is
	// invisible to its search snapshot and could survive a reported purge.
	request, err := client.request(ctx, http.MethodGet, "/"+client.indexAlias+"-p-*/_settings", nil)
	if err != nil {
		return err
	}
	response, err := client.http.Do(request)
	if err != nil {
		return &Error{code: CodeUnavailable, cause: err}
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return &Error{code: CodeRejected, status: response.StatusCode}
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumResponseBytes+1))
	if err != nil || len(raw) > maximumResponseBytes {
		return &Error{code: CodeResponse, cause: err}
	}
	var revisions map[string]json.RawMessage
	if json.Unmarshal(raw, &revisions) != nil || revisions == nil || len(revisions) > 4096 {
		return &Error{code: CodeResponse}
	}
	indices := []string{client.indexAlias}
	for index := range revisions {
		suffix, ok := strings.CutPrefix(index, client.indexAlias+"-p-")
		revisionText, hash, split := strings.Cut(suffix, "-")
		revision, err := strconv.ParseInt(revisionText, 10, 64)
		if !ok || !split || err != nil || revision <= 1 || revision > maximumGeneration || strconv.FormatInt(revision, 10) != revisionText || !validSHA256("sha256:"+hash) {
			return &Error{code: CodeResponse}
		}
		indices = append(indices, index)
	}
	sort.Strings(indices)
	for _, index := range indices {
		qualified := *client
		qualified.indexAlias = index
		if err := qualified.Delete(ctx, documentID); err != nil {
			return err
		}
	}
	return nil
}

func (applier *Applier) EnsureRevisionIndex(ctx context.Context, revision int64) error {
	if applier == nil || applier.client == nil {
		return &Error{code: CodeInvalid}
	}
	return applier.client.EnsureRevisionIndex(ctx, revision)
}

func (applier *Applier) RefreshRevision(ctx context.Context, revision int64) error {
	if applier == nil || applier.client == nil {
		return &Error{code: CodeInvalid}
	}
	return applier.client.RefreshRevision(ctx, revision)
}
