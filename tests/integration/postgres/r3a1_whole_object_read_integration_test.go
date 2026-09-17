package postgres_test

// R3a-1 KV-A01 (Outcome 1): the whole-object read proved end to end against a
// real PostgreSQL evidence chain through the production workspaceapi MCP
// adapter and the production *evidence.Viewer.
//
// The surface under test is the canonical knowvault_read tool in whole-object
// cursor mode over POST /api/v1/mcp. The cursor switches the read from one
// fragment to the whole source version, whose ordinal-ordered canonical text is
// reassembled by internal/source/evidence.Viewer.ReadObject (the
// EvidenceWholeObject capability) and paged with internal/address.Read. Every
// existing unit test drives that mode through an in-memory fake; this suite
// drives the real shared viewer assembly against a
// worker-synced version that genuinely holds two or more evidence fragments, so
// the registered mutation probe on that line is killed by a real read rather
// than a fake.
//
// The four Outcome 1 controls asserted here:
//
//  1. the first page of a multi-fragment version reports an explicit has_more
//     marker plus next_cursor and the hash of the WHOLE original
//     (address.WholeHash), not of the page it carries;
//  2. concatenating every page's exact base64 bytes reproduces the seeded
//     original byte for byte and hashes to the reported whole_hash;
//  3. an address whose span hash does not match the resolved original is
//     refused with the typed, content-free -32005 and returns no content;
//  4. an address requested under a real workspace the caller is not a member of
//     is refused with the existing content-free -32004 and leaks no text and no
//     requested-workspace echo.
//
// No production semantics, route, contract, migration or dependency changes.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/address"
	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// kvA01WholeReadResult is the closed structuredContent projection of the
// knowvault_read whole-object cursor mode.
type kvA01WholeReadResult struct {
	FragmentID         string         `json:"fragment_id"`
	Text               string         `json:"text"`
	TextBase64         string         `json:"text_base64"`
	Offset             int64          `json:"offset"`
	Length             int64          `json:"length"`
	NextCursor         *string        `json:"next_cursor"`
	HasMore            bool           `json:"has_more"`
	Complete           bool           `json:"complete"`
	Limit              int64          `json:"limit"`
	TotalBytes         int64          `json:"total_bytes"`
	WholeHash          string         `json:"whole_hash"`
	TextRepresentation string         `json:"text_representation"`
	PageHash           string         `json:"page_hash"`
	Address            map[string]any `json:"address"`
	CanonicalAddress   string         `json:"canonical_address"`
	FragmentCount      int64          `json:"fragment_count"`
}

type kvA01GrepResult struct {
	Matches []struct {
		CanonicalAddress string `json:"canonical_address"`
		Offset           int64  `json:"offset"`
		Length           int64  `json:"length"`
		VersionID        string `json:"version_id"`
		ReadFragments    []struct {
			CanonicalAddress string `json:"canonical_address"`
			FragmentID       string `json:"fragment_id"`
			Length           int64  `json:"length"`
		} `json:"read_fragments"`
		ReadFragmentsTotal   int64 `json:"read_fragments_total"`
		ReadFragmentsHasMore bool  `json:"read_fragments_has_more"`
	} `json:"matches"`
}

// kvA01WholeRead issues one knowvault_read tools/call in whole-object cursor
// mode and decodes its structured read result.
func kvA01WholeRead(t *testing.T, handler *workspaceapi.Handler, token, csrf, arguments string) (string, kvA01MCPEnvelope, kvA01WholeReadResult) {
	t.Helper()
	body, envelope := kvA01Call(t, handler, token, csrf, kvA01ToolCallBody("kva01-whole-read", "knowvault_read", arguments))
	var result kvA01WholeReadResult
	if envelope.Error == nil && len(envelope.Result.Structured) > 0 {
		if err := jsonv2.Unmarshal(envelope.Result.Structured, &result); err != nil {
			t.Fatalf("kv-a01 whole-object structuredContent decode: %v body=%s", err, body)
		}
	}
	return body, envelope, result
}

// TestKVA01WholeObjectReadOutcomeOne proves the whole-object read controls on
// the real MCP surface against a real multi-fragment evidence version.
func TestKVA01WholeObjectReadOutcomeOne(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	// A multi-line document larger than the 4096-byte fragment budget: the
	// extractor never splits a line, so the file yields several contiguous
	// line-range fragments inside one extraction (one source version), which is
	// exactly what the whole-object assembly must stitch back together.
	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var document strings.Builder
	for index := 0; index < 300; index++ {
		fmt.Fprintf(&document, "line %04d: the quick brown fox jumps over the lazy dog\n", index)
	}
	writeS1dFile(t, filepath.Join(dir, "multi.txt"), document.String())

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	authorityFixture := seedS1dWorkspaceBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer, configHash)
	seedKVA01ForeignWorkspace(t, ctx, admin, s1dOrg, kvA01ForeignWorkspace, s1dOwner)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	ingest := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSync(t, ctx, ingest, queue, workerAccess(t, s1dOrg), "kva01-whole-object")

	objectID, versionID, extractionID := s1dActiveEvidence(t, ctx, admin)
	fragments := s1dFragments(t, ctx, admin, extractionID)
	if len(fragments) < 2 {
		t.Fatalf("fixture produced %d fragment(s); whole-object assembly needs at least two", len(fragments))
	}

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	authority := newAuthorityRuntime(t, ctx)
	handler, token, csrf := kvA01Handler(t, s1dOrg, s1dViewer, viewer, authority)

	// The oracle is the canonical seeded input, not concatenated fragment text:
	// line anchors omit their final LF, and treating concatenation as the input
	// previously hid a whole-text data-loss regression.
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_kva01_whole_object"}
	original, err := canon.Canonicalize([]byte(document.String()))
	if err != nil {
		t.Fatal(err)
	}
	for _, candidate := range fragments {
		fragment, readErr := viewer.Read(ctx, viewerAccess, s1dWorkspace, candidate.id)
		if readErr != nil {
			t.Fatalf("authorized viewer read of %s failed: %v", candidate.id, readErr)
		}
		if len(fragment.Text) == 0 || !bytes.Contains(original, fragment.Text) {
			t.Fatal("authorized fragment is not present in canonical seeded input")
		}
	}
	anchorID := fragments[0].id
	wholeHash := address.WholeHash(original)

	// The canonical whole-object address: source = the source object, object =
	// the anchor fragment, version = the immutable source_version_id, span = the
	// whole reassembled canonical text [0, rune count). It is the address the
	// production whole-object page mode emits and must accept.
	canonical, err := (address.Address{
		Source: objectID, Object: anchorID, Version: versionID,
		SpanKind: address.SpanKindText, CharStart: 0, CharEnd: utf8.RuneCount(original),
	}).WithSpanHash(original)
	if err != nil {
		t.Fatalf("build canonical whole-object address: %v", err)
	}

	t.Run("pages reassemble byte for byte to the whole-original hash", func(t *testing.T) {
		var assembled []byte
		cursor := ""
		pages := 0
		for {
			if pages > 1024 {
				t.Fatal("whole-object pagination did not terminate")
			}
			arguments := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"fragment_id":` + strconv.Quote(anchorID) +
				`,"cursor":` + strconv.Quote(cursor) + `,"limit":64,"include_text_base64":true}`
			body, envelope, page := kvA01WholeRead(t, handler, token, csrf, arguments)
			if envelope.Error != nil {
				t.Fatalf("whole-object page at cursor %q refused: %#v body=%s", cursor, envelope.Error, body)
			}
			if page.FragmentID != anchorID {
				t.Fatalf("page fragment_id=%q want %q", page.FragmentID, anchorID)
			}
			// Every page, not only the last, reports the hash of the WHOLE
			// original.
			if page.WholeHash != wholeHash {
				t.Fatalf("page whole_hash=%q want whole-original hash %q", page.WholeHash, wholeHash)
			}
			if page.TextRepresentation != string(evidence.CanonicalTextV1LayoutV2) {
				t.Fatalf("new TEXT extraction representation=%q", page.TextRepresentation)
			}
			if page.TotalBytes != int64(len(original)) {
				t.Fatalf("page total_bytes=%d want %d", page.TotalBytes, len(original))
			}
			if page.Offset != int64(len(assembled)) {
				t.Fatalf("page offset=%d want resume offset %d", page.Offset, len(assembled))
			}
			if page.Complete == page.HasMore {
				t.Fatalf("page complete=%v has_more=%v: completion and continuation must be exclusive", page.Complete, page.HasMore)
			}
			pageBytes, decodeErr := base64.StdEncoding.DecodeString(page.TextBase64)
			if decodeErr != nil {
				t.Fatalf("page text_base64 did not decode: %v", decodeErr)
			}
			if page.Text != string(pageBytes) {
				t.Fatalf("page text member does not equal the page bytes")
			}
			sum := sha256.Sum256(pageBytes)
			if page.PageHash != "sha256:"+hex.EncodeToString(sum[:]) {
				t.Fatalf("page_hash=%q does not name the returned page", page.PageHash)
			}
			assembled = append(assembled, pageBytes...)
			pages++
			if !page.HasMore {
				if page.NextCursor != nil {
					t.Fatalf("final page offered next_cursor=%q", *page.NextCursor)
				}
				break
			}
			if page.NextCursor == nil || *page.NextCursor == "" {
				t.Fatalf("non-final page carried no next_cursor: %#v", page)
			}
			cursor = *page.NextCursor
		}
		if pages < 2 {
			t.Fatalf("expected a multi-page whole-object read, got %d page(s)", pages)
		}
		if !bytes.Equal(assembled, original) {
			t.Fatalf("reassembled %d bytes != seeded original %d bytes", len(assembled), len(original))
		}
		if address.WholeHash(assembled) != wholeHash {
			t.Fatalf("reassembled hash does not equal the reported whole_hash")
		}
	})

	t.Run("tampered span hash is refused without content", func(t *testing.T) {
		// The matching canonical address is served first, so the refusal below
		// is a genuine tamper detection and not an accidentally malformed
		// address.
		matching := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"address":` + strconv.Quote(canonical.String()) + `,"cursor":""}`
		matchingBody, matchingEnvelope, matchingPage := kvA01WholeRead(t, handler, token, csrf, matching)
		if matchingEnvelope.Error != nil {
			t.Fatalf("matching whole-object address was refused: %#v body=%s", matchingEnvelope.Error, matchingBody)
		}
		if matchingPage.WholeHash != wholeHash || matchingPage.TotalBytes != int64(len(original)) {
			t.Fatalf("matching address served the wrong object: whole_hash=%q total_bytes=%d", matchingPage.WholeHash, matchingPage.TotalBytes)
		}

		tampered := canonical
		tampered.SpanHash = strings.Repeat("0", 16)
		arguments := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"address":` + strconv.Quote(tampered.String()) + `,"cursor":""}`
		body, envelope, _ := kvA01WholeRead(t, handler, token, csrf, arguments)
		if envelope.Error == nil || envelope.Error.Code != -32005 || envelope.Error.Message != "evidence span hash mismatch" {
			t.Fatalf("tampered whole-object address not refused with -32005: %#v body=%s", envelope.Error, body)
		}
		if len(envelope.Result.Structured) != 0 || len(envelope.Result.Content) != 0 {
			t.Fatalf("tampered refusal leaked content: %s", body)
		}
		if strings.Contains(body, anchorID) || strings.Contains(body, s1dWorkspace) {
			t.Fatalf("tampered refusal echoed the object or workspace: %s", body)
		}
	})

	t.Run("another workspace address is denied without content", func(t *testing.T) {
		// The same canonical address, requested under a real workspace the
		// caller is not a member of. It names real content in the caller's own
		// workspace, so the denial cannot be a mere unknown-object refusal.
		arguments := `{"workspace_id":` + strconv.Quote(kvA01ForeignWorkspace) + `,"address":` + strconv.Quote(canonical.String()) + `,"cursor":""}`
		body, envelope, page := kvA01WholeRead(t, handler, token, csrf, arguments)
		if envelope.Error == nil || envelope.Error.Code != -32004 || envelope.Error.Message != "evidence not found" {
			t.Fatalf("cross-workspace whole-object read not the content-free not-found: %#v body=%s", envelope.Error, body)
		}
		if len(envelope.Result.Structured) != 0 || len(envelope.Result.Content) != 0 || page.WholeHash != "" || len(page.Address) != 0 {
			t.Fatalf("cross-workspace whole-object denial leaked content or address: %s", body)
		}
		if strings.Contains(body, anchorID) || strings.Contains(body, kvA01ForeignWorkspace) {
			t.Fatalf("cross-workspace whole-object denial echoed the object or requested workspace: %s", body)
		}
		// The viewer denial is the same no-oracle ErrNotFound the fragment read
		// returns.
		if _, readErr := viewer.ReadObject(ctx, viewerAccess, kvA01ForeignWorkspace, anchorID); !errors.Is(readErr, evidence.ErrNotFound) {
			t.Fatalf("direct viewer cross-workspace ReadObject err=%v, want ErrNotFound", readErr)
		}
	})

	t.Run("addressed grep reads only its authorized object and the hit round-trips", func(t *testing.T) {
		arguments := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"pattern":"line 0001","address":` + strconv.Quote(canonical.String()) + `}`
		body, envelope := kvA01Call(t, handler, token, csrf, kvA01ToolCallBody("kva01-addressed-grep", "knowvault_grep", arguments))
		if envelope.Error != nil || envelope.Result.IsError {
			t.Fatalf("authorized addressed grep refused: %#v body=%s", envelope.Error, body)
		}
		var grep kvA01GrepResult
		if err := jsonv2.Unmarshal(envelope.Result.Structured, &grep); err != nil {
			t.Fatalf("decode addressed grep result: %v body=%s", err, body)
		}
		if len(grep.Matches) != 1 || grep.Matches[0].VersionID != versionID || grep.Matches[0].CanonicalAddress == "" {
			t.Fatalf("addressed grep result=%#v, want one hit in version %s", grep, versionID)
		}
		match := grep.Matches[0]
		readArgs := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"address":` + strconv.Quote(match.CanonicalAddress) +
			`,"offset":` + strconv.FormatInt(match.Offset, 10) + `,"limit":64}`
		readBody, readEnvelope, page := kvA01WholeRead(t, handler, token, csrf, readArgs)
		if readEnvelope.Error != nil || page.Offset != match.Offset || !strings.Contains(page.Text, "line 0001") {
			t.Fatalf("grep hit did not round-trip through a single direct read: err=%#v offset=%d page=%q body=%s", readEnvelope.Error, page.Offset, page.Text, readBody)
		}
		if len(match.ReadFragments) != 1 || match.ReadFragmentsTotal != 1 || match.ReadFragmentsHasMore {
			t.Fatalf("grep must expose the complete supporting fragment: %#v", match)
		}
		full := match.ReadFragments[0]
		expected, err := viewer.Read(ctx, viewerAccess, s1dWorkspace, full.FragmentID)
		if err != nil {
			t.Fatalf("independent supporting fragment read: %v", err)
		}
		parsed, err := address.Parse(full.CanonicalAddress)
		if err != nil || parsed.Source != objectID || parsed.Version != versionID || parsed.Object != full.FragmentID {
			t.Fatalf("supporting address identity drift: %#v err=%v", parsed, err)
		}
		fullArgs := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"address":` + strconv.Quote(full.CanonicalAddress) + `,"limit":65536}`
		fullBody, fullEnvelope, fullPage := kvA01WholeRead(t, handler, token, csrf, fullArgs)
		if fullEnvelope.Error != nil || fullPage.HasMore || fullPage.Offset != 0 || fullPage.Text != string(expected.Text) || full.Length != int64(len(expected.Text)) || fullPage.PageHash != address.WholeHash(expected.Text) {
			t.Fatalf("full supporting fragment did not round-trip byte for byte: err=%#v body=%s", fullEnvelope.Error, fullBody)
		}
		foreignArgs := `{"workspace_id":` + strconv.Quote(kvA01ForeignWorkspace) + `,"address":` + strconv.Quote(full.CanonicalAddress) + `}`
		foreignBody, foreignEnvelope, _ := kvA01WholeRead(t, handler, token, csrf, foreignArgs)
		if foreignEnvelope.Error == nil || foreignEnvelope.Error.Code != -32004 || len(foreignEnvelope.Result.Structured) != 0 || len(foreignEnvelope.Result.Content) != 0 || strings.Contains(foreignBody, full.FragmentID) {
			t.Fatalf("supporting address bypassed workspace authorization: %s", foreignBody)
		}
	})

	t.Run("addressed grep preserves real workspace and version authorization", func(t *testing.T) {
		foreignArgs := `{"workspace_id":` + strconv.Quote(kvA01ForeignWorkspace) + `,"pattern":"line 0001","address":` + strconv.Quote(canonical.String()) + `}`
		foreignBody, foreign := kvA01Call(t, handler, token, csrf, kvA01ToolCallBody("kva01-grep-foreign", "knowvault_grep", foreignArgs))
		if foreign.Error == nil || foreign.Error.Code != -32004 || len(foreign.Result.Structured) != 0 || len(foreign.Result.Content) != 0 {
			t.Fatalf("cross-workspace addressed grep was not content-free -32004: %#v body=%s", foreign.Error, foreignBody)
		}
		if strings.Contains(foreignBody, anchorID) || strings.Contains(foreignBody, kvA01ForeignWorkspace) {
			t.Fatalf("cross-workspace addressed grep echoed object/workspace: %s", foreignBody)
		}

		if _, err := admin.Exec(ctx, `UPDATE public.source_version_retention SET queryable=false
			WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID); err != nil {
			t.Fatalf("make exact source version non-queryable: %v", err)
		}
		defer func() {
			if _, err := admin.Exec(ctx, `UPDATE public.source_version_retention SET queryable=true
				WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID); err != nil {
				t.Errorf("restore source version queryability: %v", err)
			}
		}()
		inactiveArgs := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"pattern":"line 0001","address":` + strconv.Quote(canonical.String()) + `}`
		inactiveBody, inactive := kvA01Call(t, handler, token, csrf, kvA01ToolCallBody("kva01-grep-inactive-version", "knowvault_grep", inactiveArgs))
		if inactive.Error == nil || inactive.Error.Code != -32004 || len(inactive.Result.Structured) != 0 || len(inactive.Result.Content) != 0 {
			t.Fatalf("non-queryable version addressed grep was not content-free -32004: %#v body=%s", inactive.Error, inactiveBody)
		}
		if _, err := admin.Exec(ctx, `UPDATE public.source_version_retention SET queryable=true
			WHERE organization_id=$1 AND source_version_id=$2`, s1dOrg, versionID); err != nil {
			t.Fatalf("restore source version queryability: %v", err)
		}

		stale := canonical
		stale.Version = "version_stale"
		staleArgs := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"pattern":"line 0001","address":` + strconv.Quote(stale.String()) + `}`
		staleBody, staleEnvelope := kvA01Call(t, handler, token, csrf, kvA01ToolCallBody("kva01-grep-stale-version", "knowvault_grep", staleArgs))
		if staleEnvelope.Error == nil || staleEnvelope.Error.Code != -32602 || len(staleEnvelope.Result.Structured) != 0 || len(staleEnvelope.Result.Content) != 0 {
			t.Fatalf("stale-version addressed grep was not rejected content-free: %#v body=%s", staleEnvelope.Error, staleBody)
		}
	})

	t.Run("revoked source confirmation denies addressed grep", func(t *testing.T) {
		beforeArgs := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"pattern":"line 0001","address":` + strconv.Quote(canonical.String()) + `}`
		beforeBody, beforeEnvelope := kvA01Call(t, handler, token, csrf, kvA01ToolCallBody("kva01-grep-before-revoke", "knowvault_grep", beforeArgs))
		var before kvA01GrepResult
		if beforeEnvelope.Error != nil || jsonv2.Unmarshal(beforeEnvelope.Result.Structured, &before) != nil || len(before.Matches) != 1 || len(before.Matches[0].ReadFragments) != 1 {
			t.Fatalf("obtain public supporting address before revoke: %s", beforeBody)
		}
		savedAddress := before.Matches[0].ReadFragments[0].CanonicalAddress
		var confirmationID, confirmationHash string
		if err := admin.QueryRow(ctx, `SELECT confirmation_id, confirmation_hash
			FROM public.workspace_managed_grant_confirmation
			WHERE organization_id=$1 AND workspace_source_id=$2`, s1dOrg, authorityFixture.workspaceSourceID).
			Scan(&confirmationID, &confirmationHash); err != nil {
			t.Fatalf("read seeded source confirmation: %v", err)
		}
		authority := newAuthorityRuntime(t, ctx)
		if _, err := authority.RevokeManagedConfirmation(ctx, authorityAccess(authorityFixture, s1dOwner, "req_kva01_grep_revoke"), workspacerepository.RevokeConfirmationRequest{
			IdempotencyKey: authorityIdempotencyKey("kva01-grep-revoke"), OrganizationID: s1dOrg,
			WorkspaceID: s1dWorkspace, ConfirmationID: confirmationID, ConfirmationHash: confirmationHash,
			ExpectedPolicyRevision: authorityFixture.policyID,
		}); err != nil {
			t.Fatalf("revoke seeded source confirmation: %v", err)
		}
		arguments := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"pattern":"line 0001","address":` + strconv.Quote(canonical.String()) + `}`
		body, envelope := kvA01Call(t, handler, token, csrf, kvA01ToolCallBody("kva01-grep-revoked", "knowvault_grep", arguments))
		if envelope.Error == nil || envelope.Error.Code != -32004 || len(envelope.Result.Structured) != 0 || len(envelope.Result.Content) != 0 {
			t.Fatalf("revoked-source addressed grep was not content-free -32004: %#v body=%s", envelope.Error, body)
		}
		if _, readErr := viewer.ReadObject(ctx, viewerAccess, s1dWorkspace, anchorID); !errors.Is(readErr, evidence.ErrNotFound) {
			t.Fatalf("direct viewer ReadObject after confirmation revoke err=%v, want ErrNotFound", readErr)
		}
		readArgs := `{"workspace_id":` + strconv.Quote(s1dWorkspace) + `,"address":` + strconv.Quote(savedAddress) + `}`
		readBody, denied, _ := kvA01WholeRead(t, handler, token, csrf, readArgs)
		if denied.Error == nil || denied.Error.Code != -32004 || len(denied.Result.Structured) != 0 || len(denied.Result.Content) != 0 || strings.Contains(readBody, savedAddress) {
			t.Fatalf("saved supporting address bypassed source revocation: %s", readBody)
		}
	})
}
