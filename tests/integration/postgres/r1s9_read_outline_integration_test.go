package postgres_test

// R1.S9.s1.T1: the knowvault_read outline mode proved end to end against a
// real PostgreSQL evidence chain through the production workspaceapi MCP
// adapter and the production *evidence.Viewer, sitting next to
// TestKVA01WholeObjectReadOutcomeOne (r3a1_whole_object_read_integration_test.go),
// which proves the sibling cursor mode the same way.
//
// The surface under test is knowvault_read with outline=true over
// POST /api/v1/mcp. Outline mode reassembles the whole source version through
// internal/source/evidence.Viewer.ReadObject (the identical EvidenceWholeObject
// capability the cursor mode composes) and extracts the document's Markdown
// ATX headings from that real canonical text, so this suite seeds a
// multi-fragment worker-synced version whose headings genuinely land in
// different fragments, and proves:
//
//  1. the outline lists the seeded headings in document order, each with its
//     own canonical_address, and headings in different fragments resolve to
//     different addresses;
//  2. each heading's canonical_address round-trips through knowvault_read
//     (fragment mode) to the real fragment text containing that heading line;
//  3. a tampered address is refused with the typed, content-free -32005 and
//     returns no content;
//  4. an address requested under a real workspace the caller is not a member
//     of is refused with the existing content-free -32004 and leaks no text
//     and no requested-workspace echo.
//
// No production semantics, route, contract, migration or dependency changes.

import (
	"context"
	jsonv2 "encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
)

// kvR1S9OutlineResult is the closed structuredContent projection of the
// knowvault_read outline mode.
type kvR1S9OutlineResult struct {
	Headings []struct {
		Level            int    `json:"level"`
		Text             string `json:"text"`
		CanonicalAddress string `json:"canonical_address"`
		Gist             string `json:"gist"`
	} `json:"headings"`
	Truncated        bool           `json:"truncated"`
	FragmentCount    int64          `json:"fragment_count"`
	Address          map[string]any `json:"address"`
	CanonicalAddress string         `json:"canonical_address"`
}

// kvR1S9Outline issues one knowvault_read tools/call in outline mode and
// decodes its structured result.
func kvR1S9Outline(t *testing.T, handler *workspaceapi.Handler, token, csrf, arguments string) (string, kvA01MCPEnvelope, kvR1S9OutlineResult) {
	t.Helper()
	body, envelope := kvA01Call(t, handler, token, csrf, kvA01ToolCallBody("kvr1s9-outline", "knowvault_read", arguments))
	var result kvR1S9OutlineResult
	if envelope.Error == nil && len(envelope.Result.Structured) > 0 {
		if err := jsonv2.Unmarshal(envelope.Result.Structured, &result); err != nil {
			t.Fatalf("kv-r1s9 outline structuredContent decode: %v body=%s", err, body)
		}
	}
	return body, envelope, result
}

// TestKVR1S9ReadOutlineOverRealMultiFragmentDocument proves the outline
// controls on the real MCP surface against a real multi-fragment evidence
// version whose headings genuinely span more than one fragment.
func TestKVR1S9ReadOutlineOverRealMultiFragmentDocument(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	// A Markdown document larger than the 4096-byte fragment budget, with six
	// headings spread through it: the extractor never splits a line, so this
	// yields several contiguous line-range fragments inside one extraction, and
	// at least two of the headings land in different fragments.
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var document strings.Builder
	var headingTexts []string
	for index := 0; index < 300; index++ {
		if index%50 == 0 {
			heading := fmt.Sprintf("Section %02d", index/50)
			headingTexts = append(headingTexts, heading)
			fmt.Fprintf(&document, "# %s\ngist for %s\n", heading, heading)
			continue
		}
		fmt.Fprintf(&document, "line %04d: the quick brown fox jumps over the lazy dog\n", index)
	}
	writeS1dFile(t, filepath.Join(dir, "outline.md"), document.String())

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dWorkspaceBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer, configHash)
	seedKVA01ForeignWorkspace(t, ctx, admin, s1dOrg, kvA01ForeignWorkspace, s1dOwner)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	ingest := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, ingest, queue, workerAccess(t, s1dOrg), "kvr1s9-outline")

	objectID, versionID, extractionID := s1dActiveEvidence(t, ctx, admin)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) < 2 {
		t.Fatalf("fixture produced %d fragment(s); outline-across-fragments needs at least two", len(fragments))
	}

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	authority := newAuthorityRuntime(t, ctx)
	handler, token, csrf := kvA01Handler(t, s1dOrg, s1dViewer, viewer, authority)

	anchorID := fragments[0].id
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_kvr1s9_outline"}

	t.Run("outline lists the seeded headings across fragments in order", func(t *testing.T) {
		arguments := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"fragment_id":` + strconv.Quote(anchorID) + `,"outline":true}`
		body, envelope, outline := kvR1S9Outline(t, handler, token, csrf, arguments)
		if envelope.Error != nil {
			t.Fatalf("outline refused: %#v body=%s", envelope.Error, body)
		}
		if outline.Truncated {
			t.Fatalf("small seeded document reported truncated: %#v", outline)
		}
		if len(outline.Headings) != len(headingTexts) {
			t.Fatalf("outline returned %d heading(s), want %d: %#v", len(outline.Headings), len(headingTexts), outline.Headings)
		}
		seenAddresses := map[string]bool{}
		for i, want := range headingTexts {
			got := outline.Headings[i]
			if got.Level != 1 || got.Text != want {
				t.Fatalf("heading[%d]=%#v want level=1 text=%q", i, got, want)
			}
			if got.Gist != "gist for "+want {
				t.Fatalf("heading[%d].Gist=%q want %q", i, got.Gist, "gist for "+want)
			}
			if got.CanonicalAddress == "" {
				t.Fatalf("heading[%d] missing canonical_address", i)
			}
			parsed, parseErr := address.Parse(got.CanonicalAddress)
			if parseErr != nil || parsed.Source != objectID || parsed.Version != versionID {
				t.Fatalf("heading[%d] canonical_address=%q did not parse to the seeded object/version: err=%v parsed=%#v", i, got.CanonicalAddress, parseErr, parsed)
			}
			seenAddresses[got.CanonicalAddress] = true

			// Each heading's canonical_address round-trips through knowvault_read
			// (fragment mode) to the real fragment text that contains the
			// heading line.
			readArgs := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"address":` + strconv.Quote(got.CanonicalAddress) + `,"limit":65536}`
			readBody, readEnvelope := kvA01Call(t, handler, token, csrf, kvA01ToolCallBody("kvr1s9-heading-read", "knowvault_read", readArgs))
			if readEnvelope.Error != nil {
				t.Fatalf("heading[%d] address did not round-trip: %#v body=%s", i, readEnvelope.Error, readBody)
			}
			var page kvA01ReadResult
			if err := jsonv2.Unmarshal(readEnvelope.Result.Structured, &page); err != nil {
				t.Fatalf("heading[%d] read structuredContent decode: %v", i, err)
			}
			if !strings.Contains(page.Text, "# "+want) {
				t.Fatalf("heading[%d] address resolved to a fragment without its own heading line: text=%q", i, page.Text)
			}
		}
		if len(seenAddresses) < 2 {
			t.Fatalf("headings resolved to only %d distinct address(es); outline-across-fragments proof needs at least two", len(seenAddresses))
		}
		if outline.FragmentCount != int64(len(fragments)) {
			t.Fatalf("outline fragment_count=%d want %d", outline.FragmentCount, len(fragments))
		}
	})

	t.Run("tampered address is refused without content", func(t *testing.T) {
		matching := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"fragment_id":` + strconv.Quote(anchorID) + `,"outline":true}`
		_, envelope, outline := kvR1S9Outline(t, handler, token, csrf, matching)
		if envelope.Error != nil || len(outline.Headings) == 0 {
			t.Fatalf("could not obtain a genuine outline address to tamper: %#v", envelope.Error)
		}
		parsed, err := address.Parse(outline.Headings[0].CanonicalAddress)
		if err != nil {
			t.Fatal(err)
		}
		parsed.SpanHash = strings.Repeat("0", 16)
		if parsed.SpanHash == outline.Headings[0].CanonicalAddress {
			t.Fatal("tamper did not change the address")
		}
		arguments := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"address":` + strconv.Quote(parsed.String()) + `,"outline":true}`
		body, envelope, _ := kvR1S9Outline(t, handler, token, csrf, arguments)
		if envelope.Error == nil || envelope.Error.Code != -32005 || envelope.Error.Message != "evidence span hash mismatch" {
			t.Fatalf("tampered outline address not refused with -32005: %#v body=%s", envelope.Error, body)
		}
		if len(envelope.Result.Structured) != 0 || len(envelope.Result.Content) != 0 {
			t.Fatalf("tampered outline refusal leaked content: %s", body)
		}
	})

	t.Run("another workspace address is denied without content", func(t *testing.T) {
		arguments := `{"workspace_id":` + strconv.Quote(kvA01ForeignWorkspace) + `,"fragment_id":` + strconv.Quote(anchorID) + `,"outline":true}`
		body, envelope, outline := kvR1S9Outline(t, handler, token, csrf, arguments)
		if envelope.Error == nil || envelope.Error.Code != -32004 || envelope.Error.Message != "evidence not found" {
			t.Fatalf("cross-workspace outline read not the content-free not-found: %#v body=%s", envelope.Error, body)
		}
		if len(envelope.Result.Structured) != 0 || len(envelope.Result.Content) != 0 || len(outline.Headings) != 0 {
			t.Fatalf("cross-workspace outline denial leaked content: %s", body)
		}
		if strings.Contains(body, anchorID) || strings.Contains(body, kvA01ForeignWorkspace) {
			t.Fatalf("cross-workspace outline denial echoed the object or requested workspace: %s", body)
		}
		if _, readErr := viewer.ReadObject(ctx, viewerAccess, kvA01ForeignWorkspace, anchorID); readErr == nil {
			t.Fatal("direct viewer cross-workspace ReadObject unexpectedly succeeded")
		}
	})

	t.Run("outline is refused when combined with cursor or a nonzero offset", func(t *testing.T) {
		for name, arguments := range map[string]string{
			"with_cursor": `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"fragment_id":` + strconv.Quote(anchorID) + `,"outline":true,"cursor":""}`,
			"with_offset": `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"fragment_id":` + strconv.Quote(anchorID) + `,"outline":true,"offset":1}`,
		} {
			t.Run(name, func(t *testing.T) {
				body, envelope, _ := kvR1S9Outline(t, handler, token, csrf, arguments)
				if envelope.Error == nil || envelope.Error.Code != -32602 {
					t.Fatalf("outline combined with cursor/offset not refused: %#v body=%s", envelope.Error, body)
				}
			})
		}
	})
}
