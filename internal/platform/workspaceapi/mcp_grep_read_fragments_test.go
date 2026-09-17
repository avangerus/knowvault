package workspaceapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

func grepReadFragmentsFixture(t *testing.T, text string, cuts []int, anchorIndex, matchStart, matchLength int) GrepHit {
	t.Helper()
	if len(cuts) < 2 || cuts[0] != 0 || cuts[len(cuts)-1] != len(text) ||
		anchorIndex < 0 || anchorIndex >= len(cuts)-1 {
		t.Fatalf("invalid grep read-fragment fixture cuts=%v anchor=%d text_length=%d", cuts, anchorIndex, len(text))
	}

	const firstOrdinal int64 = 31
	spans := make([]evidence.ObjectFragmentSpan, 0, len(cuts)-1)
	fragmentIDs := make([]string, 0, len(cuts)-1)
	for index := 0; index+1 < len(cuts); index++ {
		if cuts[index] >= cuts[index+1] {
			t.Fatalf("fixture fragment %d is empty or reversed: cuts=%v", index, cuts)
		}
		fragmentID := fmt.Sprintf("fragment_readfrag_%02d", index)
		fragmentIDs = append(fragmentIDs, fragmentID)
		spans = append(spans, evidence.ObjectFragmentSpan{
			FragmentID: fragmentID,
			Ordinal:    firstOrdinal + int64(index),
			Offset:     cuts[index],
			Length:     cuts[index+1] - cuts[index],
		})
	}

	anchorStart, anchorEnd := cuts[anchorIndex], cuts[anchorIndex+1]
	anchor := evidence.Fragment{
		FragmentID:         fragmentIDs[anchorIndex],
		Text:               append([]byte(nil), []byte(text)[anchorStart:anchorEnd]...),
		ExtractionID:       "extraction_read_fragments",
		SourceVersionID:    "version_immutable_read_fragments",
		Ordinal:            firstOrdinal + int64(anchorIndex),
		ExternalVersionKey: "refs/heads/main",
		ContentHash:        strings.Repeat("ab", 32),
		ObservedAt:         time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC),
		SourceObjectID:     "source_object_read_fragments",
		ConnectionID:       "connection_read_fragments",
		ObjectType:         mcpGrepCodeObjectType,
	}
	object := evidence.WholeObject{
		Fragment:      anchor,
		Text:          []byte(text),
		Fragments:     spans,
		FragmentCount: int64(len(spans)),
		FirstOrdinal:  firstOrdinal,
		LastOrdinal:   firstOrdinal + int64(len(spans)) - 1,
	}

	hit := GrepHit{
		Fragment: anchor,
		Object:   object,
		Offset:   int64(matchStart),
		Length:   int64(matchLength),
	}
	if matchStart >= 0 && matchLength >= 0 && matchStart+matchLength <= len(text) {
		hit.Excerpt = string([]byte(text)[matchStart : matchStart+matchLength])
	}
	return hit
}

func cloneGrepReadFragmentsHit(hit GrepHit) GrepHit {
	hit.Fragment.Text = append([]byte(nil), hit.Fragment.Text...)
	hit.Object.Fragment.Text = append([]byte(nil), hit.Object.Fragment.Text...)
	hit.Object.Text = append([]byte(nil), hit.Object.Text...)
	hit.Object.Fragments = append([]evidence.ObjectFragmentSpan(nil), hit.Object.Fragments...)
	return hit
}

func assertInvalidGrepReadFragments(t *testing.T, hit GrepHit) {
	t.Helper()
	_, _, _, err := mcpGrepReadFragments(nil, hit)
	if !errors.Is(err, errMCPGrepReadFragmentsInvalid) {
		t.Fatalf("malformed grep hit error=%v, want %v", err, errMCPGrepReadFragmentsInvalid)
	}
}

func TestMCPGrepReadFragmentsUseWholeOverlappingSourceFragments(t *testing.T) {
	text := "xéyz"
	hit := grepReadFragmentsFixture(t, text, []int{0, 1, 3, 4, 5}, 0, 1, 3)
	key := address.NewSpanDigestKey([]byte("unit-test organization span digest key"), 1)
	ref := "refs/heads/main"

	projection, err := mcpGrepHitProjectionKeyedChecked(&key, hit, ref)
	if err != nil {
		t.Fatalf("valid grep hit projection failed: %v", err)
	}
	readFragments, ok := projection["read_fragments"].([]any)
	if !ok || len(readFragments) != 2 {
		t.Fatalf("read_fragments=%#v, want two complete overlaps", projection["read_fragments"])
	}
	if projection["read_fragments_total"] != int64(2) || projection["read_fragments_has_more"] != false {
		t.Fatalf("fragment overlap summary total=%#v has_more=%#v", projection["read_fragments_total"], projection["read_fragments_has_more"])
	}

	wantIDs := []string{"fragment_readfrag_01", "fragment_readfrag_02"}
	wantText := []string{"é", "y"}
	for index, raw := range readFragments {
		entry, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("read fragment %d has unexpected type %T", index, raw)
		}
		if entry["fragment_id"] != wantIDs[index] || entry["length"] != int64(len(wantText[index])) {
			t.Fatalf("read fragment %d=%#v, want id=%q full byte length=%d", index, entry, wantIDs[index], len(wantText[index]))
		}
		canonical, ok := entry["canonical_address"].(string)
		if !ok {
			t.Fatalf("read fragment %d has no canonical address: %#v", index, entry)
		}
		parsed, err := address.Parse(canonical)
		if err != nil {
			t.Fatalf("read fragment %d address did not parse: %v", index, err)
		}
		if parsed.Source != hit.Object.Fragment.SourceObjectID ||
			parsed.Object != wantIDs[index] ||
			parsed.Version != hit.Object.Fragment.SourceVersionID {
			t.Fatalf("read fragment %d address identity=%#v, want source/version from immutable object and fragment %q", index, parsed, wantIDs[index])
		}
		if parsed.CharStart != 0 || parsed.CharEnd != len([]rune(wantText[index])) {
			t.Fatalf("read fragment %d address span=%d..%d, want complete fragment", index, parsed.CharStart, parsed.CharEnd)
		}
		verified, err := key.VerifySpan([]byte(wantText[index]), parsed)
		if err != nil || string(verified) != wantText[index] {
			t.Fatalf("read fragment %d address does not verify its exact original bytes: text=%q err=%v", index, verified, err)
		}
	}

	wholeAddress, err := address.Parse(projection["canonical_address"].(string))
	if err != nil {
		t.Fatalf("whole-object address did not parse: %v", err)
	}
	if wholeAddress.Version != ref {
		t.Fatalf("whole-object address version=%q, want existing Git ref alias %q", wholeAddress.Version, ref)
	}
	if projection["offset"] != hit.Offset || projection["length"] != hit.Length ||
		projection["match_hash"] != address.WholeHash([]byte(text)[hit.Offset:hit.Offset+hit.Length]) {
		t.Fatalf("existing match projection changed: offset=%#v length=%#v hash=%#v", projection["offset"], projection["length"], projection["match_hash"])
	}
	if !reflect.DeepEqual(projection["address"], mcpGrepAddress(hit.Object, hit.Offset, hit.Length, ref)) ||
		projection["canonical_address"] != mcpGrepCanonicalAddressKeyed(&key, hit.Object, ref) {
		t.Fatal("read-fragment projection changed the existing whole-object address")
	}
}

func TestMCPGrepReadFragmentsCapsResultsButCountsEveryOverlap(t *testing.T) {
	text := "0123456789"
	cuts := make([]int, len(text)+1)
	for index := range cuts {
		cuts[index] = index
	}
	hit := grepReadFragmentsFixture(t, text, cuts, 4, 0, len(text))

	fragments, total, hasMore, err := mcpGrepReadFragments(nil, hit)
	if err != nil {
		t.Fatalf("valid ten-fragment hit rejected: %v", err)
	}
	if len(fragments) != mcpGrepReadFragmentsMax || total != 10 || !hasMore {
		t.Fatalf("fragments=%d total=%d has_more=%v, want 8, 10, true", len(fragments), total, hasMore)
	}
	for index, raw := range fragments {
		entry := raw.(map[string]any)
		wantID := fmt.Sprintf("fragment_readfrag_%02d", index)
		if entry["fragment_id"] != wantID || entry["length"] != int64(1) {
			t.Fatalf("fragment[%d]=%#v, want ordinal result %q with full byte length 1", index, entry, wantID)
		}
		parsed, err := address.Parse(entry["canonical_address"].(string))
		if err != nil || parsed.Object != wantID || parsed.Version != hit.Object.Fragment.SourceVersionID {
			t.Fatalf("fragment[%d] canonical identity=%#v err=%v", index, parsed, err)
		}
	}
}

func TestMCPGrepTextRendersReadFragmentsHasMoreBooleans(t *testing.T) {
	for _, hasMore := range []bool{false, true} {
		t.Run(fmt.Sprintf("has_more_%t", hasMore), func(t *testing.T) {
			match := map[string]any{
				"address":                 map[string]any{},
				"canonical_address":       "kv1:source/object:version:txt:0-1:0123456789abcdef",
				"fragment_id":             "fragment_readfrag_00",
				"offset":                  int64(0),
				"length":                  int64(1),
				"version_id":              "version_immutable_read_fragments",
				"read_fragments_total":    int64(1),
				"read_fragments_has_more": hasMore,
				"read_fragments": []any{map[string]any{
					"canonical_address": "kv1:source/object:version:txt:0-1:0123456789abcdef",
					"fragment_id":       "fragment_readfrag_00",
					"length":            int64(1),
				}},
			}
			text := mcpGrepText([]any{match}, 0, 10, false, nil)
			want := fmt.Sprintf("read_fragments_has_more=%t", hasMore)
			if !strings.Contains(text, want) {
				t.Fatalf("grep text=%q, want %q", text, want)
			}
			if !strings.Contains(text, "fragment_read_hint=knowvault_read(address=read_fragments[].canonical_address,offset=0,limit=min(read_fragments[].length,65536)); if has_more, follow knowvault_read next_offset") {
				t.Fatalf("grep text=%q, missing direct fragment read hint", text)
			}
		})
	}
}

func TestMCPGrepReadFragmentsRejectMalformedGeometryAndMatchRanges(t *testing.T) {
	base := grepReadFragmentsFixture(t, "abcdef", []int{0, 2, 4, 6}, 1, 1, 4)
	cases := []struct {
		name   string
		mutate func(*GrepHit)
	}{
		{name: "gap", mutate: func(hit *GrepHit) { hit.Object.Fragments[1].Offset++ }},
		{name: "overlap", mutate: func(hit *GrepHit) { hit.Object.Fragments[1].Offset-- }},
		{name: "out of order", mutate: func(hit *GrepHit) {
			hit.Object.Fragments[0], hit.Object.Fragments[1] = hit.Object.Fragments[1], hit.Object.Fragments[0]
		}},
		{name: "ordinal gap", mutate: func(hit *GrepHit) { hit.Object.Fragments[1].Ordinal += 2 }},
		{name: "duplicate fragment", mutate: func(hit *GrepHit) { hit.Object.Fragments[1].FragmentID = hit.Object.Fragments[0].FragmentID }},
		{name: "zero length fragment", mutate: func(hit *GrepHit) { hit.Object.Fragments[0].Length = 0 }},
		{name: "out of bounds fragment", mutate: func(hit *GrepHit) { hit.Object.Fragments[0].Length = len(hit.Object.Text) + 1 }},
		{name: "missing span metadata", mutate: func(hit *GrepHit) { hit.Object.Fragments = nil }},
		{name: "fragment count drift", mutate: func(hit *GrepHit) { hit.Object.FragmentCount-- }},
		{name: "first ordinal drift", mutate: func(hit *GrepHit) { hit.Object.FirstOrdinal++ }},
		{name: "last ordinal drift", mutate: func(hit *GrepHit) { hit.Object.LastOrdinal++ }},
		{name: "hit source object drift", mutate: func(hit *GrepHit) { hit.Fragment.SourceObjectID = "source_other" }},
		{name: "whole source version drift", mutate: func(hit *GrepHit) { hit.Object.Fragment.SourceVersionID = "version_rotated" }},
		{name: "empty match", mutate: func(hit *GrepHit) { hit.Length = 0 }},
		{name: "negative match offset", mutate: func(hit *GrepHit) { hit.Offset = -1 }},
		{name: "match past object", mutate: func(hit *GrepHit) { hit.Offset = int64(len(hit.Object.Text)) }},
		{name: "match length past object", mutate: func(hit *GrepHit) { hit.Length = int64(len(hit.Object.Text)) }},
		{name: "invalid whole UTF-8", mutate: func(hit *GrepHit) { hit.Object.Text = []byte{0xff} }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			hit := cloneGrepReadFragmentsHit(base)
			test.mutate(&hit)
			assertInvalidGrepReadFragments(t, hit)
		})
	}

	t.Run("fragment splits UTF-8 rune", func(t *testing.T) {
		hit := grepReadFragmentsFixture(t, "éx", []int{0, 2, 3}, 0, 0, 2)
		hit.Object.Fragments[0].Length = 1
		hit.Object.Fragments[1].Offset = 1
		assertInvalidGrepReadFragments(t, hit)
	})
	t.Run("match splits UTF-8 rune", func(t *testing.T) {
		hit := grepReadFragmentsFixture(t, "éx", []int{0, 2, 3}, 0, 1, 1)
		assertInvalidGrepReadFragments(t, hit)
	})
}

func TestMCPAndRESTGrepHideMalformedReadFragmentMetadata(t *testing.T) {
	hit := grepReadFragmentsFixture(t, "private-secret-text", []int{0, 7, 14, 19}, 0, 0, 7)
	hit.Object.Fragments[1].Offset++
	service := &fakeGrepEvidence{page: GrepPage{Hits: []GrepHit{hit}}}
	harness := grepHarness(t, service)

	mcpResponse := httptest.NewRecorder()
	harness.handler.ServeHTTP(mcpResponse, harness.request(http.MethodPost, apiPrefix+"/mcp",
		"{\"jsonrpc\":\"2.0\",\"id\":\"g\",\"method\":\"tools/call\",\"params\":{\"name\":\""+
			mcpToolGrep+"\",\"arguments\":{\"workspace_id\":\"ws_alpha\",\"pattern\":\"private\"}}}"))
	var envelope mcpGrepEnvelope
	if err := json.Unmarshal(mcpResponse.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("decode malformed-hit MCP response: %v: %s", err, mcpResponse.Body.String())
	}
	if mcpResponse.Code != http.StatusOK || envelope.Error == nil ||
		envelope.Error.Code != -32000 || envelope.Error.Message != "service unavailable" {
		t.Fatalf("malformed-hit MCP response status=%d envelope=%#v body=%s", mcpResponse.Code, envelope, mcpResponse.Body.String())
	}
	if strings.Contains(mcpResponse.Body.String(), "private-secret-text") ||
		strings.Contains(mcpResponse.Body.String(), "fragment_readfrag_") {
		t.Fatalf("malformed-hit MCP response disclosed object or fragment data: %s", mcpResponse.Body.String())
	}

	restResponse := callRestGrep(t, harness, http.MethodGet, "?pattern=private")
	if restResponse.Code != http.StatusServiceUnavailable {
		t.Fatalf("malformed-hit REST status=%d body=%s, want 503", restResponse.Code, restResponse.Body.String())
	}
	if strings.Contains(restResponse.Body.String(), "private-secret-text") ||
		strings.Contains(restResponse.Body.String(), "fragment_readfrag_") {
		t.Fatalf("malformed-hit REST response disclosed object or fragment data: %s", restResponse.Body.String())
	}
}

func TestMCPGrepReadFragmentsAcceptVerifiedCanonicalLFGaps(t *testing.T) {
	hit := grepReadFragmentsFixture(t, "first\nsecond\n", []int{0, 6, 13}, 0, 3, 7)
	hit.Object.Representation = evidence.CanonicalTextV1LayoutV2
	for index := range hit.Object.Fragments {
		hit.Object.Fragments[index].Length--
	}
	hit.Fragment.Text = []byte("first")
	hit.Object.Fragment.Text = []byte("first")
	fragments, total, more, err := mcpGrepReadFragments(nil, hit)
	if err != nil || total != 2 || more || len(fragments) != 2 {
		t.Fatalf("canonical gap rejected: %v", err)
	}
	for index, text := range []string{"first", "second"} {
		entry := fragments[index].(map[string]any)
		selector, err := address.Parse(entry["canonical_address"].(string))
		if err != nil {
			t.Fatal(err)
		}
		actual, err := address.VerifySpan([]byte(text), selector)
		if err != nil || string(actual) != text {
			t.Fatal("read hint includes bytes outside its exact fragment")
		}
	}
	for _, change := range []string{"legacy", "non-LF gap", "non-LF tail", "negative span"} {
		t.Run(change, func(t *testing.T) {
			bad := cloneGrepReadFragmentsHit(hit)
			switch change {
			case "legacy":
				bad.Object.Representation = evidence.LegacyFragmentConcatV1
			case "non-LF gap":
				bad.Object.Text[5] = 'x'
			case "non-LF tail":
				bad.Object.Text[12] = 'x'
			case "negative span":
				bad.Object.Fragments[0].Offset = -1
			}
			assertInvalidGrepReadFragments(t, bad)
		})
	}
	// A query matching only the retained separator still has the whole-object
	// address, but must not fabricate a fragment containing that separator.
	hit.Offset, hit.Length = 5, 1
	fragments, total, more, err = mcpGrepReadFragments(nil, hit)
	if err != nil || len(fragments) != 0 || total != 0 || more {
		t.Fatal("separator-only hit fabricated fragment evidence")
	}
}
