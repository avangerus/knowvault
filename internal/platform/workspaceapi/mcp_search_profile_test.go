package workspaceapi

// S3 Outcome 4: the retrieval profile of a call is selectable for measurement
// and never by the model. These tests pin the two halves of that: the tool
// schema has no profile member and refuses one, and the transport channel that
// does carry a profile is honoured only through the authority that journals the
// decision.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/retrieval"
	"knowvault.local/verified-workspace/internal/searchprofile"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

// fakeHybridSearch records the options the transport resolved for one call and
// returns one addressed hit, so a test can read back which retrieval profile
// actually ran.
type fakeHybridSearch struct {
	options    retrieval.WorkspaceSearchOptions
	profile    retrieval.WorkspaceSearchProfile
	hit        evidence.Fragment
	term       bool
	partial    bool
	hasMore    bool
	nextOffset int64
}

func (fake *fakeHybridSearch) SearchWorkspace(_ context.Context, _ database.AccessContext,
	_ string, query string, options retrieval.WorkspaceSearchOptions) (retrieval.WorkspaceSearchPage, error) {
	fake.options = options
	profile := fake.profile
	profile.Mode = options.Mode
	page := retrieval.WorkspaceSearchPage{
		Hits: []retrieval.WorkspaceHit{{Fragment: fake.hit, Excerpt: "\u2026\u0432\u044b\u0434\u0435\u0440\u0436\u043a\u0430\u2026", Score: 0.0328,
			Channel: retrieval.HitChannelHybrid, VersionState: "CURRENT"}},
		Profile: profile,
		Partial: fake.partial, HasMore: fake.hasMore, NextOffset: fake.nextOffset,
	}
	if fake.term {
		page.TermHits = []retrieval.WorkspaceHit{{Fragment: fake.hit, Excerpt: "\u2026\u043e\u043f\u0440\u0435\u0434\u0435\u043b\u0435\u043d\u0438\u0435\u2026", Score: 1,
			Channel: retrieval.HitChannelTerm, VersionState: "CURRENT", TermKind: "SYNONYM"}}
	}
	return page, nil
}

// fakeProfileChannel stands in for the owner-only authority. It grants exactly
// what it is told to, so a test can separate "the transport forwarded the
// channel" from "the authority allowed it".
type fakeProfileChannel struct {
	grant     bool
	requested string
	calls     int
}

func (fake *fakeProfileChannel) ResolveCallProfile(_ context.Context, _ database.AccessContext,
	_ string, requested string) (searchprofile.CallProfile, bool, error) {
	fake.calls++
	fake.requested = requested
	if !fake.grant {
		return searchprofile.CallProfileHybrid, false, nil
	}
	return searchprofile.CallProfile(requested), true, nil
}

func hybridSearchHarness(t *testing.T, grant bool) (*testHarness, *fakeHybridSearch, *fakeProfileChannel) {
	t.Helper()
	service := &fakeSearchEvidence{page: evidence.SearchPage{Hits: []evidence.SearchHit{testSearchHit(t)}}}
	harness := searchHarness(t, service)
	hybrid := &fakeHybridSearch{hit: testSearchHit(t).Fragment,
		profile: retrieval.WorkspaceSearchProfile{Lexical: true, Vector: true, Fusion: "rrf", K: 60, ProfileID: "bge-m3-gguf-q8-v1"}}
	channel := &fakeProfileChannel{grant: grant}
	harness.handler.EnableHybridSearch(hybrid, channel)
	return harness, hybrid, channel
}

func callMCPSearchWithProfile(t *testing.T, harness *testHarness, arguments, profile string) mcpSearchEnvelope {
	t.Helper()
	request := harness.request(http.MethodPost, apiPrefix+"/mcp",
		`{"jsonrpc":"2.0","id":"s","method":"tools/call","params":{"name":"knowvault_search","arguments":`+arguments+`}}`)
	if profile != "" {
		request.Header.Set(searchProfileHeader, profile)
	}
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("MCP knowvault_search status=%d body=%s", response.Code, response.Body.String())
	}
	var envelope mcpSearchEnvelope
	if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("MCP knowvault_search did not decode: %v: %s", err, response.Body.String())
	}
	return envelope
}

// The tool schema is the model's whole surface. A profile member there would
// make the retrieval algorithm part of the answer, so it is absent and an
// argument naming it is refused before anything is read.
func TestSearchToolSchemaCarriesNoRetrievalProfileAndRefusesOne(t *testing.T) {
	harness, hybrid, channel := hybridSearchHarness(t, true)
	schema := listToolSchemas(t, harness)["knowvault_search"]
	properties := schema["properties"].(map[string]any)
	for _, forbidden := range []string{"profile", "mode", "rerank", "reranker", "vector", "lexical"} {
		if _, present := properties[forbidden]; present {
			t.Fatalf("knowvault_search advertises the retrieval knob %q", forbidden)
		}
	}
	if schema["additionalProperties"] != false {
		t.Fatalf("knowvault_search schema is not closed: %#v", schema["additionalProperties"])
	}
	envelope := callMCPSearchWithProfile(t, harness, "{\"workspace_id\":\"ws_alpha\",\"query\":\"\u043c\u0443\u0441\u043e\u0440\",\"profile\":\"lexical\"}", "")
	if envelope.Error == nil || envelope.Error.Code != -32602 {
		t.Fatalf("a profile argument was not refused as an unknown member: %#v", envelope.Error)
	}
	if channel.calls != 0 {
		t.Fatal("a refused argument reached the profile authority")
	}
	if hybrid.options.Limit != 0 {
		t.Fatal("a refused argument reached retrieval")
	}
}

// A granted channel changes the retrieval the call runs and says so in the
// result, so a measurement run never has to assume which algorithm produced the
// score it compares.
func TestSearchProfileChannelIsHonouredWhenGrantedAndEchoed(t *testing.T) {
	harness, hybrid, channel := hybridSearchHarness(t, true)
	envelope := callMCPSearchWithProfile(t, harness, "{\"workspace_id\":\"ws_alpha\",\"query\":\"\u043c\u0443\u0441\u043e\u0440\"}", "lexical")
	if envelope.Error != nil {
		t.Fatalf("granted profile call refused: %#v", envelope.Error)
	}
	if channel.requested != "lexical" || channel.calls != 1 {
		t.Fatalf("profile authority saw requested=%q calls=%d", channel.requested, channel.calls)
	}
	if hybrid.options.Mode != retrieval.SearchModeLexical {
		t.Fatalf("retrieval ran mode %q, want lexical", hybrid.options.Mode)
	}
	body := envelope.Result.Content[0]["text"].(string)
	if !strings.Contains(body, `"mode":"lexical"`) {
		t.Fatalf("the text channel does not name the profile that ran: %s", body)
	}
}

// A channel the authority refuses changes nothing: the call runs the product
// default. The refusal itself is journalled by the authority, which is what
// makes "the model does not pick the algorithm" observable afterwards.
func TestSearchProfileChannelIsIgnoredWhenTheAuthorityRefuses(t *testing.T) {
	harness, hybrid, channel := hybridSearchHarness(t, false)
	envelope := callMCPSearchWithProfile(t, harness, "{\"workspace_id\":\"ws_alpha\",\"query\":\"\u043c\u0443\u0441\u043e\u0440\"}", "vector")
	if envelope.Error != nil {
		t.Fatalf("refused profile call did not fall back to the default: %#v", envelope.Error)
	}
	if channel.calls != 1 || channel.requested != "vector" {
		t.Fatalf("profile authority saw requested=%q calls=%d", channel.requested, channel.calls)
	}
	if hybrid.options.Mode != retrieval.SearchModeHybrid {
		t.Fatalf("an unauthorized profile changed the retrieval to %q", hybrid.options.Mode)
	}
}

// A deployment with no profile authority has nowhere to record the decision, so
// a presented channel is ignored rather than granted unjournalled.
func TestSearchProfileChannelIsIgnoredWithoutAnAuthority(t *testing.T) {
	service := &fakeSearchEvidence{page: evidence.SearchPage{Hits: []evidence.SearchHit{testSearchHit(t)}}}
	harness := searchHarness(t, service)
	hybrid := &fakeHybridSearch{hit: testSearchHit(t).Fragment}
	harness.handler.EnableHybridSearch(hybrid, nil)
	if envelope := callMCPSearchWithProfile(t, harness, "{\"workspace_id\":\"ws_alpha\",\"query\":\"\u043c\u0443\u0441\u043e\u0440\"}", "vector"); envelope.Error != nil {
		t.Fatalf("call refused: %#v", envelope.Error)
	}
	if hybrid.options.Mode != retrieval.SearchModeHybrid {
		t.Fatalf("an unjournalled profile was honoured: %q", hybrid.options.Mode)
	}
}

// A deployment with no hybrid capability keeps the lexical page it served
// before and says so, instead of letting a client read a lexical answer as a
// hybrid one.
func TestSearchWithoutHybridCapabilityReportsALexicalDegradedProfile(t *testing.T) {
	service := &fakeSearchEvidence{page: evidence.SearchPage{Hits: []evidence.SearchHit{testSearchHit(t)}}}
	harness := searchHarness(t, service)
	envelope := callMCPSearchWithProfile(t, harness, `{"workspace_id":"ws_alpha","query":"alpha"}`, "")
	if envelope.Error != nil {
		t.Fatalf("lexical-only call refused: %#v", envelope.Error)
	}
	body := envelope.Result.Content[0]["text"].(string)
	if !strings.Contains(body, `"mode":"lexical"`) || !strings.Contains(body, `"degraded":true`) {
		t.Fatalf("a lexical-only deployment did not report itself as such: %s", body)
	}
	if len(envelope.Result.Structured.Results) != 1 {
		t.Fatalf("the existing lexical page changed shape: %#v", envelope.Result.Structured.Results)
	}
	if envelope.Result.Structured.Results[0]["channel"] != "lexical" {
		t.Fatalf("a lexical hit did not name its channel: %#v", envelope.Result.Structured.Results[0])
	}
}

func TestSearchPartialCoverageAndConsumedOffsetHaveRESTMCPParity(t *testing.T) {
	for _, partial := range []bool{false, true} {
		for _, hasMore := range []bool{false, true} {
			t.Run("partial="+strconv.FormatBool(partial)+"/more="+strconv.FormatBool(hasMore), func(t *testing.T) {
				harness, hybrid, _ := hybridSearchHarness(t, true)
				hybrid.partial, hybrid.hasMore, hybrid.nextOffset = partial, hasMore, 7
				hybrid.profile.Diversity = "file-copy-units-v1"
				// One displayed hit may consume two ranked groups if a group
				// loses access during the final read. Preserve the core cursor.
				mcp := httptest.NewRecorder()
				harness.handler.ServeHTTP(mcp, harness.request(http.MethodPost, apiPrefix+"/mcp",
					`{"jsonrpc":"2.0","id":"partial","method":"tools/call","params":{"name":"knowvault_search","arguments":{"workspace_id":"ws_alpha","query":"alpha","offset":5,"limit":20}}}`))
				var envelope struct {
					Result struct {
						Structured map[string]any `json:"structuredContent"`
						Content    []struct {
							Text string `json:"text"`
						} `json:"content"`
					} `json:"result"`
				}
				if mcp.Code != http.StatusOK || json.Unmarshal(mcp.Body.Bytes(), &envelope) != nil {
					t.Fatalf("MCP response: %d %s", mcp.Code, mcp.Body.String())
				}
				for _, method := range []string{http.MethodGet, http.MethodPost} {
					path := apiPrefix + "/workspaces/ws_alpha/tools/search?query=alpha&offset=5&limit=20"
					rest := httptest.NewRecorder()
					harness.handler.ServeHTTP(rest, harness.request(method, path, ""))
					var decoded map[string]any
					if rest.Code != http.StatusOK || json.Unmarshal(rest.Body.Bytes(), &decoded) != nil {
						t.Fatalf("REST %s: %d %s", method, rest.Code, rest.Body.String())
					}
					if !reflect.DeepEqual(decoded, envelope.Result.Structured) {
						t.Fatalf("REST/MCP search projection differs: REST=%#v MCP=%#v", decoded, envelope.Result.Structured)
					}
				}
				page := envelope.Result.Structured
				if page["profile"].(map[string]any)["diversity"] != "file-copy-units-v1" ||
					!strings.Contains(envelope.Result.Content[0].Text, `"diversity":"file-copy-units-v1"`) {
					t.Fatal("search copy ordering was not disclosed to every client")
				}
				if page["partial"] != partial || page["has_more"] != hasMore {
					t.Fatalf("lost independent coverage/pagination flags: %#v", page)
				}
				var wantNext any
				if hasMore {
					wantNext = float64(7)
				}
				if page["next_offset"] != wantNext {
					t.Fatalf("next_offset=%v want %v", page["next_offset"], wantNext)
				}
				if len(envelope.Result.Content) != 1 || !strings.Contains(envelope.Result.Content[0].Text, "partial="+strconv.FormatBool(partial)) {
					t.Fatal("text-only client lost partial coverage flag")
				}
			})
		}
	}
}

// The text channel is the whole result for a client that does not parse
// structuredContent, so a term hit has to reach it too, with the same address.
func TestSearchTextChannelCarriesTermHitsAndTheirAddresses(t *testing.T) {
	harness, hybrid, _ := hybridSearchHarness(t, true)
	hybrid.term = true
	envelope := callMCPSearchWithProfile(t, harness, "{\"workspace_id\":\"ws_alpha\",\"query\":\"\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435 \u0442\u043e\u0440\u0441\"}", "")
	if envelope.Error != nil {
		t.Fatalf("term call refused: %#v", envelope.Error)
	}
	body := envelope.Result.Content[0]["text"].(string)
	if !strings.Contains(body, "[term 1] canonical_address=") || !strings.Contains(body, "channel=term") ||
		!strings.Contains(body, "term_kind=SYNONYM") {
		t.Fatalf("the text channel lost the term hit: %s", body)
	}
	var structured struct {
		Result struct {
			Structured struct {
				Terms []map[string]any `json:"terms"`
			} `json:"structuredContent"`
		} `json:"result"`
	}
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodPost, apiPrefix+"/mcp",
		"{\"jsonrpc\":\"2.0\",\"id\":\"s\",\"method\":\"tools/call\",\"params\":{\"name\":\"knowvault_search\",\"arguments\":{\"workspace_id\":\"ws_alpha\",\"query\":\"\u0447\u0442\u043e \u0442\u0430\u043a\u043e\u0435 \u0442\u043e\u0440\u0441\"}}}"))
	if err := json.Unmarshal(response.Body.Bytes(), &structured); err != nil {
		t.Fatalf("structured decode: %v", err)
	}
	if len(structured.Result.Structured.Terms) != 1 {
		t.Fatalf("structuredContent lost the term hit: %#v", structured.Result.Structured.Terms)
	}
	canonical, _ := structured.Result.Structured.Terms[0]["canonical_address"].(string)
	if canonical == "" || !strings.Contains(body, "canonical_address="+canonical+" ") {
		t.Fatalf("the two channels carry different term addresses: text=%s structured=%s", body, canonical)
	}
}
