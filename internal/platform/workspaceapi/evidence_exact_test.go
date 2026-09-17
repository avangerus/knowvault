package workspaceapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/evidence"
)

type exactEvidenceService struct {
	fakeEvidenceService
	exactFragment                                 evidence.Fragment
	exactError                                    error
	exactCalls, wholeCalls, currentWholeCalls     int
	exactVersion, exactWorkspace, exactFragmentID string
	wholeText                                     []byte
	inventory                                     []evidence.ObjectInventoryItem
}

func (service *exactEvidenceService) ListObjects(context.Context, database.AccessContext, string, bool, int64, int64) (evidence.ObjectInventoryPage, error) {
	return evidence.ObjectInventoryPage{Items: service.inventory}, nil
}

func (service *exactEvidenceService) ReadExactVersion(_ context.Context, _ database.AccessContext, workspaceID, fragmentID, versionID string) (evidence.Fragment, error) {
	service.exactCalls++
	service.exactVersion, service.exactWorkspace, service.exactFragmentID = versionID, workspaceID, fragmentID
	return service.exactFragment, service.exactError
}

func (service *exactEvidenceService) ReadObject(context.Context, database.AccessContext, string, string) (evidence.WholeObject, error) {
	service.currentWholeCalls++
	return evidence.WholeObject{}, evidence.ErrNotFound
}

func (service *exactEvidenceService) ReadObjectExactVersion(ctx context.Context, access database.AccessContext, workspaceID, fragmentID, versionID string) (evidence.WholeObject, error) {
	service.wholeCalls++
	fragment, err := service.ReadExactVersion(ctx, access, workspaceID, fragmentID, versionID)
	text := fragment.Text
	if service.wholeText != nil {
		text = service.wholeText
	}
	return evidence.WholeObject{Fragment: fragment, Text: text, FragmentCount: 1, FirstOrdinal: fragment.Ordinal, LastOrdinal: fragment.Ordinal}, err
}

func TestEvidencePageAcceptsVerifiedWholeAndGitRefAddresses(t *testing.T) {
	for _, mode := range []string{"whole", "ref", "whole_tampered", "ref_unknown"} {
		t.Run(mode, func(t *testing.T) {
			harness := newTestHarness(t)
			fragment := testEvidenceFragment(t)
			service := &exactEvidenceService{exactFragment: fragment, fakeEvidenceService: fakeEvidenceService{err: evidence.ErrNotFound}}
			harness.handler.evidence = service
			selector := mcpTestCanonicalAddress(t, fragment)
			if strings.HasPrefix(mode, "whole") {
				service.wholeText = append(append([]byte(nil), fragment.Text...), []byte(" hidden tail of the same extraction")...)
				selector.CharStart, selector.CharEnd = 0, utf8.RuneCount(service.wholeText)
				var err error
				selector, err = selector.WithSpanHash(service.wholeText)
				if err != nil {
					t.Fatal(err)
				}
				if mode == "whole_tampered" {
					service.wholeText[len(service.wholeText)-1] = 'X'
				}
			} else {
				selector.Version = "commit-abc"
				service.inventory = []evidence.ObjectInventoryItem{{SourceObjectID: fragment.SourceObjectID, SourceVersionID: fragment.SourceVersionID, ObjectType: "GIT_FILE", ExternalVersionKey: "native:commit:commit-abc"}}
				if mode == "ref_unknown" {
					selector.Version = "commit-unknown"
				}
			}
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/evidence/"+fragment.FragmentID+"?address="+url.QueryEscape(selector.String()), ""))
			if strings.Contains(mode, "_") {
				if response.Code != http.StatusNotFound || strings.Contains(response.Body.String(), string(fragment.Text)) {
					t.Fatal("invalid whole/ref address disclosed data")
				}
			} else {
				var body map[string]any
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil || body["text"] != string(fragment.Text) {
					t.Fatalf("valid %s page failed: status=%d", mode, response.Code)
				}
				if strings.Contains(response.Body.String(), "hidden tail") {
					t.Fatal("source page disclosed the whole-object tail")
				}
				if service.exactVersion != fragment.SourceVersionID {
					t.Fatal("ref/exact read lost immutable version")
				}
			}
			if service.call != "" || service.currentWholeCalls != 0 {
				t.Fatal("whole/ref page fell back to a current read")
			}
		})
	}
}

func TestExactAddressSelectsRetainedVersionOnEveryReadSurface(t *testing.T) {
	for _, surface := range []string{"page", "rest", "mcp", "rest_whole", "mcp_whole"} {
		t.Run(surface, func(t *testing.T) {
			harness := newTestHarness(t)
			fragment := testEvidenceFragment(t)
			fragment.SourcePath = "manuals/retained.txt"
			fragment.IsCurrentVersion = false
			service := &exactEvidenceService{fakeEvidenceService: fakeEvidenceService{err: evidence.ErrNotFound}, exactFragment: fragment}
			harness.handler.evidence = service
			if err := harness.handler.EnableEvidencePageOrigin("https://knowledge.example"); err != nil {
				t.Fatal(err)
			}
			canonical := mcpTestCanonicalAddress(t, fragment).String()
			var body map[string]any
			if strings.HasPrefix(surface, "mcp") {
				args := map[string]any{"workspace_id": "ws_alpha", "address": canonical}
				if surface == "mcp_whole" {
					args["cursor"] = ""
				}
				result := mcpEvidenceRead(t, harness, mcpAddressArguments(t, args))
				if result.Error != nil {
					t.Fatalf("exact read refused: %#v", result.Error)
				}
				body = result.Result.Structured
			} else {
				path := workspacesPath + "/ws_alpha/tools/read?address=" + url.QueryEscape(canonical)
				if surface == "page" {
					path = workspacesPath + "/ws_alpha/evidence/" + fragment.FragmentID + "?address=" + url.QueryEscape(canonical)
				}
				if surface == "rest_whole" {
					path += "&cursor=v1%3A0"
				}
				request := harness.request(http.MethodGet, path, "")
				request.Host = "attacker.invalid"
				request.Header.Set("Origin", "https://attacker.invalid")
				response := httptest.NewRecorder()
				harness.handler.ServeHTTP(response, request)
				if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &body) != nil {
					t.Fatalf("exact read status=%d body=%s", response.Code, response.Body.String())
				}
			}
			if service.call != "" || service.currentWholeCalls != 0 || service.exactCalls != 1 || service.exactVersion != fragment.SourceVersionID || service.exactWorkspace != "ws_alpha" || service.exactFragmentID != fragment.FragmentID {
				t.Fatal("exact request fell back to current data or lost immutable identity")
			}
			if body["text"] != string(fragment.Text) {
				t.Fatal("exact bytes changed")
			}
			{
				link, _ := body["source_page_url"].(string)
				if !strings.HasPrefix(link, "https://knowledge.example/#evidence/ws_alpha/"+fragment.FragmentID+"?address=") || body["is_current_version"] != false {
					t.Fatal("human source link or historical metadata missing")
				}
				parsed, err := url.Parse(link)
				if err != nil {
					t.Fatal(err)
				}
				query, err := url.ParseQuery(strings.SplitN(parsed.Fragment, "?", 2)[1])
				if err != nil || query.Get("address") != canonical {
					t.Fatal("source page link lost exact canonical address")
				}
			}
		})
	}
}

func TestEvidencePageExactFailuresNeverReturnCurrentData(t *testing.T) {
	for _, problem := range []string{"source", "version", "object", "hash", "revoked", "duplicate", "empty", "malformed"} {
		t.Run(problem, func(t *testing.T) {
			harness := newTestHarness(t)
			fragment := testEvidenceFragment(t)
			service := &exactEvidenceService{exactFragment: fragment}
			service.result = fragment
			harness.handler.evidence = service
			selector := mcpTestCanonicalAddress(t, fragment)
			switch problem {
			case "source":
				selector.Source += "_other"
			case "version":
				selector.Version += "_other"
			case "object":
				selector.Object += "_other"
			case "hash":
				selector.SpanHash = selector.SpanHash[:len(selector.SpanHash)-1] + "0"
				if selector.SpanHash == mcpTestCanonicalAddress(t, fragment).SpanHash {
					selector.SpanHash = selector.SpanHash[:len(selector.SpanHash)-1] + "1"
				}
			case "revoked":
				service.exactError = evidence.ErrNotFound
			}
			query := "?address=" + url.QueryEscape(selector.String())
			if problem == "duplicate" {
				query += "&address=" + url.QueryEscape(selector.String())
			}
			if problem == "empty" {
				query = "?address="
			}
			if problem == "malformed" {
				query = "?address=invalid"
			}
			response := httptest.NewRecorder()
			harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/evidence/"+fragment.FragmentID+query, ""))
			if response.Code != http.StatusNotFound && response.Code != http.StatusBadRequest {
				t.Fatalf("invalid exact page returned %d", response.Code)
			}
			if service.call != "" || strings.Contains(response.Body.String(), string(fragment.Text)) || strings.Contains(response.Body.String(), fragment.FragmentID) {
				t.Fatal("exact denial leaked bytes/identity or fell back to current")
			}
		})
	}
}

func TestBareFragmentReadsStayCurrentOnly(t *testing.T) {
	harness := newTestHarness(t)
	fragment := testEvidenceFragment(t)
	service := &exactEvidenceService{fakeEvidenceService: fakeEvidenceService{err: evidence.ErrNotFound}, exactFragment: fragment}
	harness.handler.evidence = service
	response := httptest.NewRecorder()
	harness.handler.ServeHTTP(response, harness.request(http.MethodGet, workspacesPath+"/ws_alpha/evidence/"+fragment.FragmentID, ""))
	if response.Code != http.StatusNotFound || service.call != "read" || service.exactCalls != 0 {
		t.Fatal("bare fragment unexpectedly obtained historical data")
	}
}

func TestExactCodeRefUsesResolvedImmutableVersion(t *testing.T) {
	selector := address.Address{Version: "main"}
	if exactAddressVersion(&selector, "version_immutable") != "version_immutable" || exactAddressVersion(&selector, "") != "main" || exactAddressVersion(nil, "version_immutable") != "" {
		t.Fatal("exact ref selection drifted")
	}
}

func TestEvidencePageOriginRejectsNonOrigins(t *testing.T) {
	for _, origin := range []string{"", "http://example.org", "//example.org", "https://user@example.org", "https://example.org/", "https://example.org?x=1", "https://example.org#bad"} {
		handler := &Handler{}
		if handler.EnableEvidencePageOrigin(origin) == nil || handler.evidencePageOrigin != "" {
			t.Fatal("invalid source page origin accepted")
		}
	}
}
