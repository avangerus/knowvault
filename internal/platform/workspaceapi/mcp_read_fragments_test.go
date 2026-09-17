package workspaceapi

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

func TestWholeAddressReadsWithoutCursorAndPageHasFragmentProofs(t *testing.T) {
	anchor, whole, _ := testWholeObjectAnchor(t)
	other := "fragment_01H9ABCDEFGHJKMNPQRSTVWXYA"
	object := evidence.WholeObject{Fragment: anchor, Text: whole, FragmentCount: 2, FirstOrdinal: 1, LastOrdinal: 2,
		Fragments: []evidence.ObjectFragmentSpan{
			{FragmentID: anchor.FragmentID, Ordinal: 1, Offset: 0, Length: len(anchor.Text)},
			{FragmentID: other, Ordinal: 2, Offset: len(anchor.Text), Length: len(whole) - len(anchor.Text)},
		}}
	harness := wholeObjectHarness(t, &fakeWholeObjectEvidence{object: object})
	emitted, err := harness.handler.canonicalEvidenceWholeAddress(object)
	if err != nil {
		t.Fatal(err)
	}
	response := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{"workspace_id": "ws_alpha", "address": emitted.String(), "limit": 64}))
	if response.Error != nil {
		t.Fatalf("valid whole address refused without cursor: %+v", response.Error)
	}
	encoded, _ := json.Marshal(response.Result.Structured["fragments"])
	var parts []readPageFragment
	if json.Unmarshal(encoded, &parts) != nil || len(parts) != 2 {
		t.Fatalf("missing fragment proofs: %s", encoded)
	}
	pageText := response.Result.Structured["text"].(string)
	for i, part := range parts {
		selector, err := address.Parse(part.Address)
		if err != nil || selector.Object != object.Fragments[i].FragmentID {
			t.Fatalf("wrong fragment address: %+v", part)
		}
		span := object.Fragments[i]
		original := whole[span.Offset : span.Offset+span.Length]
		if !harness.handler.verifyAddressSpan(original, selector) || !strings.Contains(string(original), pageText[part.PageOffset:part.PageOffset+part.Length]) {
			t.Fatal("page proof does not match fragment bytes")
		}
	}
	emitted.SpanHash = strings.Repeat("0", 16)
	refused := mcpEvidenceRead(t, harness, mcpAddressArguments(t, map[string]any{"workspace_id": "ws_alpha", "address": emitted.String(), "limit": 64}))
	if refused.Error == nil || refused.Error.Code != -32005 || refused.Result.Structured["text"] != nil {
		t.Fatal("tampered whole address disclosed content")
	}
}

func TestWholeReadFragmentSourcePageURLsAcrossPages(t *testing.T) {
	anchor, _, _ := testWholeObjectAnchor(t)
	other := "fragment_01H9ABCDEFGHJKMNPQRSTVWXYA"
	whole := append(append([]byte(nil), anchor.Text...), []byte("second fragment spans pages")...)
	object := evidence.WholeObject{Fragment: anchor, Text: whole, FragmentCount: 2, FirstOrdinal: 1, LastOrdinal: 2,
		Fragments: []evidence.ObjectFragmentSpan{
			{FragmentID: anchor.FragmentID, Ordinal: 1, Offset: 0, Length: len(anchor.Text)},
			{FragmentID: other, Ordinal: 2, Offset: len(anchor.Text), Length: len(whole) - len(anchor.Text)},
		}}
	limit := len(anchor.Text) + 4 // The first page includes both fragments.
	for _, surface := range []string{"mcp", "rest"} {
		t.Run(surface, func(t *testing.T) {
			harness := wholeObjectHarness(t, &fakeWholeObjectEvidence{object: object})
			if err := harness.handler.EnableEvidencePageOrigin("https://knowledge.example"); err != nil {
				t.Fatal(err)
			}
			cursor := "v1:0"
			assembled := ""
			links := make(map[string]string)
			for pageCount := 0; ; pageCount++ {
				if pageCount > len(whole) {
					t.Fatal("whole-object pagination did not terminate")
				}
				var body map[string]any
				if surface == "mcp" {
					response := mcpEvidenceReadByName(t, harness, mcpToolEvidenceRead, mcpAddressArguments(t, map[string]any{
						"workspace_id": "ws_alpha", "fragment_id": anchor.FragmentID, "cursor": cursor, "limit": limit,
					}))
					if response.Error != nil {
						t.Fatalf("whole-object read refused: %+v", response.Error)
					}
					body = response.Result.Structured
				} else {
					response, projection := callRestRead(t, harness, http.MethodGet,
						"?fragment_id="+anchor.FragmentID+"&cursor="+url.QueryEscape(cursor)+"&limit="+strconv.Itoa(limit), "")
					if response.Code != http.StatusOK {
						t.Fatalf("whole-object read status=%d body=%s", response.Code, response.Body.String())
					}
					body = projection
				}
				pageText := body["text"].(string)
				if body["offset"] != float64(len(assembled)) || body["whole_hash"] != address.WholeHash(whole) || body["page_hash"] != mcpEvidencePageHash([]byte(pageText)) {
					t.Fatal("whole-object page offsets or hashes changed")
				}
				assembled += pageText
				encoded, err := json.Marshal(body["fragments"])
				if err != nil {
					t.Fatal(err)
				}
				var parts []readPageFragment
				if err := json.Unmarshal(encoded, &parts); err != nil || len(parts) == 0 || (pageCount == 0 && len(parts) != 2) {
					t.Fatalf("missing page fragment proofs: %s", encoded)
				}
				for _, part := range parts {
					link, err := url.Parse(part.SourcePageURL)
					if err != nil || link.Scheme != "https" || link.Host != "knowledge.example" {
						t.Fatalf("invalid fragment source page URL: %q", part.SourcePageURL)
					}
					target, rawQuery, _ := strings.Cut(link.Fragment, "?")
					query, err := url.ParseQuery(rawQuery)
					if err != nil || target != "evidence/ws_alpha/"+part.FragmentID || query.Get("address") != part.Address {
						t.Fatalf("source page URL does not select its own fragment: %+v", part)
					}
					if previous := links[part.FragmentID]; previous != "" && previous != part.SourcePageURL {
						t.Fatal("fragment source page URL changed between pages")
					}
					links[part.FragmentID] = part.SourcePageURL
				}
				if body["has_more"] == false {
					if pageCount == 0 || body["next_cursor"] != nil || body["complete"] != true {
						t.Fatal("whole-object pagination completion changed")
					}
					break
				}
				cursor = body["next_cursor"].(string)
			}
			if assembled != string(whole) || len(links) != 2 || links[anchor.FragmentID] == links[other] {
				t.Fatal("whole text changed or distinct fragment source page URLs missing")
			}
		})
	}
}
