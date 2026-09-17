package postgres_test

// R3a-1 KV-A02c-fidelity: the typed skip ledger's native-identity
// de-duplication and its fail-closed identity withholding, proved on a real
// PostgreSQL store.
//
// The R3a-1 KV-A02 inventory (internal/source/evidence.Viewer.ListObjects,
// surfaced by the MCP knowvault_list_objects tool and its REST parity route
// GET /api/v1/workspaces/{workspace_id}/tools/list-objects) reads the typed
// skip ledger public.source_object_skip. 000096 stores each skip's native
// object identity as an organization-scoped HMAC digest plus an encrypted
// artifact, and the read path decrypts that artifact and refuses any row whose
// stored digest does not verify (internal/source/evidence/viewer.go,
// readSkipExternalID). A digester-key rotation writes a second PK-distinct row
// for the same native object under a higher digest_key_version instead of
// updating the first, so the inventory must de-duplicate across digest key
// versions on the decrypted native identity, keeping the newest observation.
//
// Cross-key-version de-duplication was previously proved only as a pure Go
// unit test of selectSkipIdentities over synthetic rows (viewer_test.go). This
// control drives the real SQL query, the real tenant-fenced
// app.source_object_skip_read_external_id SECURITY DEFINER read, the real
// sealed artifacts and the real workspace authority gate:
//
//  1. one skip row is produced by the real folder sync path (digest_key_version
//     1, reason FOLDER_OBJECT_OVERSIZED); a second row for the same native
//     identity is seeded under digest_key_version 2 with its own sealed
//     artifact, its own sync run and a newer moment/reason. The viewer, the MCP
//     tool and the REST parity route must each return exactly one skip for that
//     native identity, carrying the newer reason and moment, and skipped_count
//     must equal the projected row count.
//  2. a ledger row whose stored digest does not verify against the decrypted
//     artifact is withheld fail closed: its native identity never appears in
//     the MCP body or the REST body.
//  3. a declined (tampered) newer row does not suppress the still-verifiable
//     older same-identity row: the inventory falls back to the older reason and
//     moment instead of leaking the newer row or dropping the identity.

import (
	"context"
	jsonv2 "encoding/json/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/ingestion"
	"knowvault.local/verified-workspace/internal/jobs"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/httpauth"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/source/canon"
	"knowvault.local/verified-workspace/internal/source/evidence"
	"knowvault.local/verified-workspace/internal/source/ids"
)

const (
	// r3a1SkipNativeID is the native identity the real sync quarantines and the
	// two digest key versions both name. internal/connector/folder reports the
	// connection-root-relative path (scope relative_root "projects/alpha" plus
	// "/" plus the file name), so the identity carries the projects/alpha prefix,
	// not a bare file name.
	r3a1SkipNativeID = "projects/alpha/oversized.txt"
	// r3a1SkipOlderReason is the connector's real quarantine code for the
	// oversized object (the row the real sync produces).
	r3a1SkipOlderReason = "FOLDER_OBJECT_OVERSIZED"
	// r3a1SkipNewerReason is the distinct closed reason the seeded rotated-key
	// row carries, so the "newest wins" projection is observable by reason.
	r3a1SkipNewerReason = "FOLDER_INVALID_UTF8"
)

var (
	r3a1OlderMoment = time.Date(2026, 9, 12, 10, 0, 0, 0, time.UTC)
	r3a1NewerMoment = time.Date(2026, 9, 12, 11, 0, 0, 0, time.UTC)
)

// r3a1ListProjection is the shared structured inventory projection the MCP
// knowvault_list_objects structuredContent and its REST list-objects body
// render, reduced to the members this control asserts.
type r3a1ListProjection struct {
	Objects      []map[string]any     `json:"objects"`
	Skipped      []r3a1SkipProjection `json:"skipped"`
	SkippedCount int                  `json:"skipped_count"`
	HasMore      bool                 `json:"has_more"`
}

// r3a1SkipProjection is one typed skip row of the inventory.
type r3a1SkipProjection struct {
	ExternalID string `json:"external_id"`
	ReasonCode string `json:"reason_code"`
	Moment     string `json:"moment"`
}

// r3a1SkipIdentity is the sealed plaintext of one skip identity, byte-compatible
// with internal/ingestion.skipIdentityArtifact and
// internal/source/evidence.skipIdentityEvidence.
type r3a1SkipIdentity struct {
	ExternalID string `json:"external_id"`
	Digest     string `json:"digest"`
}

// r3a1SeedSecondSyncRun inserts one SUCCEEDED partial FULL sync run for the seeded
// scope revision, reusing the real run's job row. It is the second sync run the
// rotated-key skip row is attributed to, so the ledger shape (one row per run)
// matches the production path that writes it.
func r3a1SeedSecondSyncRun(t *testing.T, ctx context.Context, admin *pgxpool.Pool, jobID string) string {
	t.Helper()
	runID := mustID(t, "syncrun")
	if _, err := admin.Exec(ctx, `INSERT INTO public.sync_run
		(organization_id, id, source_scope_id, source_scope_revision, job_id, mode, status,
		 objects_seen, objects_ingested, versions_created, evidence_published, quarantined, started_at, completed_at,
		 coverage_complete, error_code)
		SELECT $1,$2,$3,1,$4,'FULL','SUCCEEDED',1,0,0,0,1,
		       max(completed_at)+interval '1 microsecond', max(completed_at)+interval '1 microsecond',
		       false,'INGEST_PARTIAL_COVERAGE'
		FROM public.sync_run WHERE organization_id=$1 AND source_scope_id=$3`,
		s1dOrg, runID, s1dScopeID, jobID); err != nil {
		t.Fatalf("seed second sync run: %v", err)
	}
	return runID
}

// r3a1SeedSkipRow seals one identity artifact and inserts one typed skip row
// for the seeded scope revision under the given sync run. The stored digest is
// deliberately independent of the digest inside the sealed artifact, so a
// caller can seed a row whose stored digest does not verify (tamper control) as
// well as a consistent row.
func r3a1SeedSkipRow(t *testing.T, ctx context.Context, admin *pgxpool.Pool, codec *artifactcrypto.Codec,
	syncRunID, storedDigest string, keyVersion int64, reasonCode string, observedAt time.Time,
	identity r3a1SkipIdentity) string {
	t.Helper()
	artifactID := mustID(t, "art")
	plaintext, err := jsonv2.Marshal(identity)
	if err != nil {
		t.Fatalf("marshal skip identity: %v", err)
	}
	tx, err := admin.Begin(ctx)
	if err != nil {
		t.Fatalf("begin skip seed: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	sealArtifactTx(t, ctx, tx, codec, artifactcrypto.SourceObjectExternalID, s1dOrg,
		artifactID, artifactID, "source_object", "external_object_id_artifact_id",
		"SOURCE_OBJECT_ID", "EXTERNAL_OBJECT_ID", plaintext)
	if _, err := tx.Exec(ctx, `INSERT INTO public.source_object_skip
		(organization_id, sync_run_id, source_scope_id, source_scope_revision, external_id_digest,
		 digest_key_version, external_id_artifact_id, reason_code, observed_at)
		VALUES ($1,$2,$3,1,$4,$5,$6,$7,$8)`,
		s1dOrg, syncRunID, s1dScopeID, storedDigest, keyVersion, artifactID, reasonCode, observedAt); err != nil {
		t.Fatalf("seed skip row: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit skip seed: %v", err)
	}
	return artifactID
}

// r3a1DecodeListProjection decodes one transport's inventory body.
func r3a1DecodeListProjection(t *testing.T, raw []byte) r3a1ListProjection {
	t.Helper()
	var projection r3a1ListProjection
	if err := jsonv2.Unmarshal(raw, &projection); err != nil {
		t.Fatalf("decode list projection: %v body=%s", err, raw)
	}
	return projection
}

// r3a1MCPListObjects issues one authenticated MCP knowvault_list_objects call
// through the real workspaceapi handler and returns the raw body and the
// decoded projection.
func r3a1MCPListObjects(t *testing.T, handler *workspaceapi.Handler, token, csrf, id string) (string, r3a1ListProjection) {
	t.Helper()
	body, envelope := kvA01Call(t, handler, token, csrf, kvA01ToolCallBody(id, "knowvault_list_objects",
		`{"workspace_id":`+strconv.Quote(s1dWorkspace)+`}`))
	if envelope.Error != nil {
		t.Fatalf("knowvault_list_objects refused: %#v body=%s", envelope.Error, body)
	}
	return body, r3a1DecodeListProjection(t, envelope.Result.Structured)
}

// r3a1RESTListObjects issues one authenticated GET against the REST parity
// route and returns the raw body and the decoded projection.
func r3a1RESTListObjects(t *testing.T, handler *workspaceapi.Handler, token string) (string, r3a1ListProjection) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet,
		kvA01Origin+"/api/v1/workspaces/"+s1dWorkspace+"/tools/list-objects", nil)
	request.Header.Set("Cookie", httpauth.SessionCookieName+"="+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("REST list-objects status=%d body=%s", response.Code, response.Body.String())
	}
	return response.Body.String(), r3a1DecodeListProjection(t, response.Body.Bytes())
}

// r3a1AssertViewerOmission checks the authorized viewer projection holds exactly
// one omitted row for the shared native identity with the expected reason and moment.
func r3a1AssertViewerOmission(t *testing.T, label string, skips []evidence.ObjectInventorySkip, wantReason string, wantMoment time.Time) {
	t.Helper()
	if len(skips) != 1 {
		t.Fatalf("%s: viewer skips=%+v, want exactly 1", label, skips)
	}
	row := skips[0]
	if row.ExternalID != r3a1SkipNativeID {
		t.Fatalf("%s: viewer skip external_id=%q want %q", label, row.ExternalID, r3a1SkipNativeID)
	}
	if row.ReasonCode != wantReason {
		t.Fatalf("%s: viewer skip reason=%q want %q", label, row.ReasonCode, wantReason)
	}
	if !row.ObservedAt.UTC().Equal(wantMoment) {
		t.Fatalf("%s: viewer skip moment=%s want %s", label, row.ObservedAt.UTC(), wantMoment)
	}
}

// r3a1AssertProjectedOmission checks one MCP/REST projection holds exactly one
// omitted row for the shared native identity with the expected reason and moment,
// and that skipped_count equals the projected row count.
func r3a1AssertProjectedOmission(t *testing.T, label string, projection r3a1ListProjection, wantReason string, wantMoment time.Time) {
	t.Helper()
	if projection.SkippedCount != len(projection.Skipped) {
		t.Fatalf("%s: skipped_count=%d != projected rows=%d", label, projection.SkippedCount, len(projection.Skipped))
	}
	if len(projection.Skipped) != 1 {
		t.Fatalf("%s: skips=%+v, want exactly 1", label, projection.Skipped)
	}
	row := projection.Skipped[0]
	if row.ExternalID != r3a1SkipNativeID {
		t.Fatalf("%s: skip external_id=%q want %q", label, row.ExternalID, r3a1SkipNativeID)
	}
	if row.ReasonCode != wantReason {
		t.Fatalf("%s: skip reason=%q want %q", label, row.ReasonCode, wantReason)
	}
	if want := wantMoment.UTC().Format(time.RFC3339); row.Moment != want {
		t.Fatalf("%s: skip moment=%q want %q", label, row.Moment, want)
	}
}

// TestR3A1SkipIdentityDedupRealStore proves cross-key-version native-identity
// de-duplication and fail-closed identity withholding on real PostgreSQL.
func TestR3A1SkipIdentityDedupRealStore(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	codec := s1dCodec(t, s1dOrg)

	root := t.TempDir()
	dir := filepath.Join(root, "projects", "alpha")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	writeS1dFile(t, filepath.Join(dir, "notes.txt"), "readable line\n")
	// Larger than the seeded scope's max_file_bytes (1048576): the real folder
	// connector quarantines it with FOLDER_OBJECT_OVERSIZED during discovery.
	if err := os.WriteFile(filepath.Join(dir, filepath.Base(r3a1SkipNativeID)), []byte(strings.Repeat("a", 1100000)), 0o644); err != nil {
		t.Fatal(err)
	}

	seedS1dOrg(t, ctx, admin, s1dOrg, s1dOwner)
	configHash := seedS1dScope(t, ctx, admin, codec, s1dOrg, s1dOwner)
	seedS1dWorkspaceBinding(t, ctx, admin, s1dOrg, s1dWorkspace, s1dOwner, s1dViewer, configHash)

	workerStore := openStore(t, ctx, workerRole, "knowvault_worker")
	queue, err := jobs.New(workerStore)
	if err != nil {
		t.Fatal(err)
	}
	handler := ingestion.NewHandler(workerStore, queue, mustRepo(t), codec,
		ingestion.Digester{Key: s1dDigestKey, KeyVersion: 1}, s1dMounts{root: root}, s1dWorkerID, time.Now, ids.New)
	runSyncScope(t, ctx, handler, queue, workerAccess(t, s1dOrg), s1dScopeID, "r3a1-skip-dedup-k1")

	// The real sync writes the KV-A02b row shape: the digest is key-version 1 and
	// the native identity lives only in a sealed artifact. Pin its moment so the
	// newer seeded row wins deterministically.
	var runID, jobID string
	if err := admin.QueryRow(ctx, `SELECT id, job_id FROM public.sync_run
		WHERE organization_id=$1 AND source_scope_id=$2 ORDER BY started_at DESC, id DESC LIMIT 1`,
		s1dOrg, s1dScopeID).Scan(&runID, &jobID); err != nil {
		t.Fatalf("resolve real sync run: %v", err)
	}
	var k1Digest, k1Artifact, k1Reason string
	var k1KeyVersion int64
	if err := admin.QueryRow(ctx, `SELECT external_id_digest, digest_key_version, external_id_artifact_id, reason_code
		FROM public.source_object_skip
		WHERE organization_id=$1 AND sync_run_id=$2 AND digest_key_version=1`, s1dOrg, runID).
		Scan(&k1Digest, &k1KeyVersion, &k1Artifact, &k1Reason); err != nil {
		t.Fatalf("resolve real sync skip row: %v", err)
	}
	if k1KeyVersion != 1 || k1Artifact == "" || k1Reason != r3a1SkipOlderReason {
		t.Fatalf("real sync skip row is not the expected keyed/sealed row: digest=%q version=%d artifact=%q reason=%q",
			k1Digest, k1KeyVersion, k1Artifact, k1Reason)
	}
	if want := canon.HMACDigest(s1dDigestKey, 1, []byte(r3a1SkipNativeID)); k1Digest != want {
		t.Fatalf("real sync digest=%q want the key-version-1 native-id digest", k1Digest)
	}
	if _, err := admin.Exec(ctx, `UPDATE public.source_object_skip SET observed_at=$1
		WHERE organization_id=$2 AND sync_run_id=$3 AND digest_key_version=1`,
		r3a1OlderMoment, s1dOrg, runID); err != nil {
		t.Fatalf("pin real sync skip moment: %v", err)
	}

	// Seed the rotated-key row: the same native identity, key-version 2 digest,
	// its own sealed artifact, its own sync run and a newer moment/reason.
	run2ID := r3a1SeedSecondSyncRun(t, ctx, admin, jobID)
	k2Digest := canon.HMACDigest(s1dDigestKey, 2, []byte(r3a1SkipNativeID))
	r3a1SeedSkipRow(t, ctx, admin, codec, run2ID, k2Digest, 2, r3a1SkipNewerReason, r3a1NewerMoment,
		r3a1SkipIdentity{ExternalID: r3a1SkipNativeID, Digest: k2Digest})

	// Seed the tampered row: the sealed identity is "ghost.txt" but the stored
	// digest names "ghost-tampered", so the read path must withhold it.
	ghostStored := canon.HMACDigest(s1dDigestKey, 2, []byte("ghost-tampered"))
	r3a1SeedSkipRow(t, ctx, admin, codec, run2ID, ghostStored, 2, "FOLDER_NON_REGULAR",
		r3a1NewerMoment.Add(time.Hour), r3a1SkipIdentity{
			ExternalID: "ghost.txt",
			Digest:     canon.HMACDigest(s1dDigestKey, 2, []byte("ghost.txt")),
		})

	appStore := openStore(t, ctx, appRole, "knowvault_app")
	viewer, err := evidence.NewViewer(appStore, codec)
	if err != nil {
		t.Fatal(err)
	}
	viewerAccess := database.AccessContext{OrganizationID: s1dOrg, PrincipalID: s1dViewer, RequestID: "req_r3a1_skip_dedup"}
	mcpHandler, token, csrf := kvA01Handler(t, s1dOrg, s1dViewer, viewer, newAuthorityRuntime(t, ctx))

	t.Run("cross-key-version rows de-duplicate to the newer reason", func(t *testing.T) {
		page, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, false, 0, 100)
		if err != nil {
			t.Fatalf("viewer inventory: %v", err)
		}
		r3a1AssertViewerOmission(t, "viewer", page.Skipped, r3a1SkipNewerReason, r3a1NewerMoment)

		mcpBody, mcpProjection := r3a1MCPListObjects(t, mcpHandler, token, csrf, "r3a1-list-dedup")
		r3a1AssertProjectedOmission(t, "mcp", mcpProjection, r3a1SkipNewerReason, r3a1NewerMoment)

		restBody, restProjection := r3a1RESTListObjects(t, mcpHandler, token)
		r3a1AssertProjectedOmission(t, "rest", restProjection, r3a1SkipNewerReason, r3a1NewerMoment)

		if strings.Contains(mcpBody, "ghost.txt") || strings.Contains(restBody, "ghost.txt") {
			t.Fatalf("tampered identity leaked: mcp=%s rest=%s", mcpBody, restBody)
		}
	})

	t.Run("a declined row does not suppress a verifiable same-identity row", func(t *testing.T) {
		tampered := canon.HMACDigest(s1dDigestKey, 2, []byte("oversized-tampered"))
		if _, err := admin.Exec(ctx, `UPDATE public.source_object_skip SET external_id_digest=$1
			WHERE organization_id=$2 AND sync_run_id=$3 AND digest_key_version=2 AND external_id_digest=$4`,
			tampered, s1dOrg, run2ID, k2Digest); err != nil {
			t.Fatalf("tamper rotated-key skip digest: %v", err)
		}
		defer func() {
			if _, err := admin.Exec(ctx, `UPDATE public.source_object_skip SET external_id_digest=$1
				WHERE organization_id=$2 AND sync_run_id=$3 AND digest_key_version=2 AND external_id_digest=$4`,
				k2Digest, s1dOrg, run2ID, tampered); err != nil {
				t.Errorf("restore rotated-key skip digest: %v", err)
			}
		}()

		page, err := viewer.ListObjects(ctx, viewerAccess, s1dWorkspace, false, 0, 100)
		if err != nil {
			t.Fatalf("viewer inventory after tamper: %v", err)
		}
		r3a1AssertViewerOmission(t, "viewer", page.Skipped, r3a1SkipOlderReason, r3a1OlderMoment)

		mcpBody, mcpProjection := r3a1MCPListObjects(t, mcpHandler, token, csrf, "r3a1-list-declined")
		r3a1AssertProjectedOmission(t, "mcp", mcpProjection, r3a1SkipOlderReason, r3a1OlderMoment)

		restBody, restProjection := r3a1RESTListObjects(t, mcpHandler, token)
		r3a1AssertProjectedOmission(t, "rest", restProjection, r3a1SkipOlderReason, r3a1OlderMoment)

		if strings.Contains(mcpBody, r3a1SkipNewerReason) || strings.Contains(restBody, r3a1SkipNewerReason) {
			t.Fatalf("declined row's reason leaked: mcp=%s rest=%s", mcpBody, restBody)
		}
	})
}
