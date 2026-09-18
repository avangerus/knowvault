//go:build linux

// The e2e-harness is the orchestration process inside the R3 e2e container.
// It runs as root (the container runtime user), prepares the pinned mounts,
// drives the built product binaries (server, worker, operator) exactly as the
// deployment document prescribes, hosts the in-process static OIDC IdP and
// the TLS front, executes the full HTTP entry, and reports one
// "E2E CHECK <name> PASS|FAIL" line per charter clause plus a final
// "E2E RESULT PASS|FAIL" line. Every check is a real product-surface
// assertion; a failed check fails the harness exit code.
//
// This is test infrastructure. It is not a product surface, and the
// architecture checker does not scan tests/.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"knowvault.local/verified-workspace/internal/platform/runtimeidentity"
)

type config struct {
	caDir          string
	corpusDir      string
	searchCertDir  string
	searchEndpoint string
	searchAlias    string
	pgHost         string
	organizationID string
	providerID     string
	publicOrigin   string
	issuer         string
	clientID       string
	httpAddr       string
	adminURL       string
}

func loadConfig() (config, error) {
	cfg := config{
		caDir:          os.Getenv("E2E_CA_DIR"),
		corpusDir:      os.Getenv("E2E_CORPUS_DIR"),
		searchCertDir:  os.Getenv("E2E_SEARCH_CERT_DIR"),
		searchEndpoint: os.Getenv("E2E_SEARCH_ENDPOINT"),
		searchAlias:    os.Getenv("E2E_SEARCH_ALIAS"),
		pgHost:         os.Getenv("E2E_PG_HOST"),
		organizationID: os.Getenv("E2E_ORGANIZATION_ID"),
		providerID:     os.Getenv("E2E_PROVIDER_ID"),
		publicOrigin:   os.Getenv("E2E_PUBLIC_ORIGIN"),
		issuer:         os.Getenv("E2E_ISSUER"),
		clientID:       os.Getenv("E2E_CLIENT_ID"),
		httpAddr:       os.Getenv("E2E_HTTP_ADDR"),
	}
	cfg.adminURL = "postgres://postgres:postgres@" + cfg.pgHost + ":5432/knowvault?sslmode=verify-full"
	missing := make([]string, 0, 12)
	for name, value := range map[string]string{
		"E2E_CA_DIR": cfg.caDir, "E2E_CORPUS_DIR": cfg.corpusDir,
		"E2E_SEARCH_CERT_DIR": cfg.searchCertDir, "E2E_SEARCH_ENDPOINT": cfg.searchEndpoint,
		"E2E_SEARCH_ALIAS": cfg.searchAlias, "E2E_PG_HOST": cfg.pgHost,
		"E2E_ORGANIZATION_ID": cfg.organizationID, "E2E_PROVIDER_ID": cfg.providerID,
		"E2E_PUBLIC_ORIGIN": cfg.publicOrigin, "E2E_ISSUER": cfg.issuer,
		"E2E_CLIENT_ID": cfg.clientID, "E2E_HTTP_ADDR": cfg.httpAddr,
	} {
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return config{}, fmt.Errorf("missing environment: %s", strings.Join(missing, ", "))
	}
	return cfg, nil
}

type report struct {
	failed bool
}

func (r *report) check(name string, err error) {
	if err != nil {
		r.failed = true
		fmt.Printf("E2E CHECK %s FAIL %v\n", name, err)
		return
	}
	fmt.Printf("E2E CHECK %s PASS\n", name)
}

func (r *report) finish() {
	if r.failed {
		fmt.Println("E2E RESULT FAIL")
		os.Exit(1)
	}
	fmt.Println("E2E RESULT PASS")
}

// failHard reports one failed check and ends the harness immediately. It is
// used where every later check depends on the failed step, so a hard boundary
// keeps the failure log honest instead of a cascade of dependent errors.
func (r *report) failHard(name string, err error) {
	r.check(name, err)
	r.finish()
}

// loginAttemptDiagnostic dumps the durable OIDC state after a failed login so
// the failing branch is visible: PENDING means the callback failed before the
// claim, CLAIMED means the failure came after the claim, FAILED is an explicit
// repository denial. It also dumps every row the post-claim external-identity
// lookup joins and re-computes the subject digest through both key paths
// (harness manifest read and the production secretmount provider), so a
// mismatch between the seeded digest and the server-side digest is visible.
func loginAttemptDiagnostic(ctx context.Context, cfg config) string {
	pool, err := pgxpool.New(ctx, cfg.adminURL)
	if err != nil {
		return fmt.Sprintf("(admin pool: %v)", err)
	}
	defer pool.Close()
	var lines []string
	appendRows := func(title, sql string, args []any, scan func(pgx.Rows) (string, error)) {
		rows, err := pool.Query(ctx, sql, args...)
		if err != nil {
			lines = append(lines, fmt.Sprintf("%s: (query: %v)", title, err))
			return
		}
		defer rows.Close()
		count := 0
		for rows.Next() {
			line, err := scan(rows)
			if err != nil {
				lines = append(lines, fmt.Sprintf("%s: (scan: %v)", title, err))
				return
			}
			lines = append(lines, title+": "+line)
			count++
		}
		if err := rows.Err(); err != nil {
			lines = append(lines, fmt.Sprintf("%s: (rows: %v)", title, err))
			return
		}
		if count == 0 {
			lines = append(lines, title+": (no rows)")
		}
	}
	appendRows("attempt", "SELECT id, status, claimed_at IS NOT NULL, completed_at IS NOT NULL, expires_at FROM public.oidc_login_attempt WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 5",
		[]any{cfg.organizationID}, func(rows pgx.Rows) (string, error) {
			var id, status string
			var claimed, completed bool
			var expires time.Time
			if err := rows.Scan(&id, &status, &claimed, &completed, &expires); err != nil {
				return "", err
			}
			return fmt.Sprintf("%s status=%s claimed=%v completed=%v expires=%s",
				id, status, claimed, completed, expires.Format(time.RFC3339)), nil
		})
	appendRows("external_identity", "SELECT id, principal_id, provider_id, external_subject_digest, digest_key_version, status FROM public.external_identity WHERE organization_id = $1",
		[]any{cfg.organizationID}, func(rows pgx.Rows) (string, error) {
			var id, principalID, providerID, digest, status string
			var version uint32
			if err := rows.Scan(&id, &principalID, &providerID, &digest, &version, &status); err != nil {
				return "", err
			}
			return fmt.Sprintf("%s principal=%s provider=%s digest=%s version=%d status=%s",
				id, principalID, providerID, digest, version, status), nil
		})
	appendRows("principal", "SELECT id, type, status, session_revision FROM public.principal WHERE organization_id = $1",
		[]any{cfg.organizationID}, func(rows pgx.Rows) (string, error) {
			var id, principalType, status string
			var sessionRevision int64
			if err := rows.Scan(&id, &principalType, &status, &sessionRevision); err != nil {
				return "", err
			}
			return fmt.Sprintf("%s type=%s status=%s session_revision=%d", id, principalType, status, sessionRevision), nil
		})
	appendRows("oidc_provider", "SELECT id, status, current_revision, issuer_url FROM public.oidc_provider WHERE organization_id = $1",
		[]any{cfg.organizationID}, func(rows pgx.Rows) (string, error) {
			var id, status, issuer string
			var currentRevision int64
			if err := rows.Scan(&id, &status, &currentRevision, &issuer); err != nil {
				return "", err
			}
			return fmt.Sprintf("%s status=%s current_revision=%d issuer=%s", id, status, currentRevision, issuer), nil
		})
	appendRows("oidc_provider_revision", "SELECT provider_id, revision, client_id, client_secret_reference, redirect_uri FROM public.oidc_provider_revision WHERE organization_id = $1",
		[]any{cfg.organizationID}, func(rows pgx.Rows) (string, error) {
			var providerID, clientID, secretRef, redirectURI string
			var revision int64
			if err := rows.Scan(&providerID, &revision, &clientID, &secretRef, &redirectURI); err != nil {
				return "", err
			}
			return fmt.Sprintf("%s revision=%d client=%s secret_ref=%s redirect=%s", providerID, revision, clientID, secretRef, redirectURI), nil
		})
	lines = append(lines, fmt.Sprintf("digest-subject: %s", func() string {
		digest, version, err := subjectDigest(ownerSubject, cfg.organizationID, cfg.providerID)
		if err != nil {
			return fmt.Sprintf("(error: %v)", err)
		}
		return fmt.Sprintf("digest=%s version=%d", digest, version)
	}()))
	return strings.Join(lines, "\n")
}

// corpusCount is the number of corpus files the host test mounted; every
// phase-B counter is asserted against it.
func corpusCount(corpusDir string) (int64, error) {
	entries, err := os.ReadDir(corpusDir)
	if err != nil {
		return 0, fmt.Errorf("read corpus: %w", err)
	}
	var count int64
	for _, entry := range entries {
		if !entry.IsDir() {
			count++
		}
	}
	if count == 0 {
		return 0, fmt.Errorf("corpus is empty")
	}
	return count, nil
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "worker-exec" {
		os.Exit(workerExecMain())
	}
	cfg, err := loadConfig()
	if err != nil {
		fmt.Println("E2E RESULT FAIL")
		fmt.Fprintln(os.Stderr, "harness config:", err)
		os.Exit(1)
	}
	rep := &report{}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	if err := installTrust(ctx, cfg); err != nil {
		rep.failHard("trust-mount", err)
	}
	rep.check("trust-mount", nil)

	// The scratch runtime has no system trust store. Point the process-wide
	// certificate file at the e2e CA so both the pgx admin pool (verify-full)
	// and the harness HTTP client (TLS proxy, static IdP) validate against it.
	if err := os.Setenv("SSL_CERT_FILE", filepath.Join(cfg.caDir, "ca.pem")); err != nil {
		rep.failHard("ssl-cert-env", err)
	}
	rep.check("ssl-cert-env", nil)

	if err := waitPG(ctx, cfg); err != nil {
		rep.failHard("postgres-ready", err)
	}
	rep.check("postgres-ready", nil)

	if err := generatePasswords(ctx, cfg); err != nil {
		rep.failHard("passwords", err)
	}
	rep.check("passwords", nil)

	if err := runOperator(ctx, cfg, "bootstrap",
		"-migrations-dir", "/db/migrations",
		"-app-password-file", "/e2e/run/app.pw",
		"-worker-password-file", "/e2e/run/worker.pw",
		"-purger-password-file", "/e2e/run/purger.pw",
	); err != nil {
		rep.failHard("operator-bootstrap", err)
	}
	rep.check("operator-bootstrap", nil)

	// Execute the documented clean-install order through the built operator.
	// A separate bootstrap workspace leaves the R3 user-visible workspace to be
	// created later through the product surface, as the charter requires.
	if err := runOperator(ctx, cfg, "tenant-provision",
		"-organization", cfg.organizationID,
		"-organization-name", "E2E Organization",
		"-region", "ru",
		"-owner-principal", ownerPrincipalID,
		"-owner-display-name", "E2E Owner",
		"-workspace", "ws_e2e_bootstrap",
		"-workspace-name", "Bootstrap Workspace",
		"-workspace-description", "Operator clean-install proof",
	); err != nil {
		rep.failHard("operator-tenant-provision", err)
	}
	rep.check("operator-tenant-provision", nil)

	// The worker service identity is fixed composition state, not an owner
	// tenant; install it only after the operator has created the organization.
	if err := seedWorkerPrincipal(ctx, cfg); err != nil {
		rep.failHard("seed-worker-principal", err)
	}
	rep.check("seed-worker-principal", nil)

	if err := runOperator(ctx, cfg, "provider-register",
		"-organization", cfg.organizationID,
		"-provider", cfg.providerID,
		"-issuer", cfg.issuer,
		"-client-id", cfg.clientID,
		"-client-secret-reference", clientSecretReference,
		"-redirect-uri", cfg.publicOrigin+"/auth/callback",
		"-created-by", ownerPrincipalID,
	); err != nil {
		rep.failHard("operator-provider-register", err)
	}
	rep.check("operator-provider-register", nil)

	if err := runOperator(ctx, cfg, "secrets", "generate",
		"-out", "/run/knowvault/secrets",
		"-organization", cfg.organizationID,
		"-provider", cfg.providerID,
		"-database-url-file", "/e2e/run/db.url",
		"-client-reference", clientSecretReference,
		"-client-secret-file", "/e2e/run/oidc-client.secret",
	); err != nil {
		rep.failHard("operator-secrets-generate", err)
	}
	rep.check("operator-secrets-generate", nil)

	// The external identity digest is computed with the mount identity key,
	// so it must follow the mount generation (and the provider registration
	// it references).
	if err := seedExternalIdentity(ctx, cfg); err != nil {
		rep.failHard("seed-external-identity", err)
	}
	rep.check("seed-external-identity", nil)

	if err := runOperator(ctx, cfg, "secrets", "verify",
		"-mount", "/run/knowvault/secrets",
		"-organization", cfg.organizationID,
		"-provider", cfg.providerID,
	); err != nil {
		rep.failHard("operator-secrets-verify", err)
	}
	rep.check("operator-secrets-verify", nil)

	// The worker runs in its own container-equivalent filesystem with its own
	// secret mount (DEPLOYMENT.md §4): same key material as the server mount
	// via -keys-from, but its own sealed database URL for the worker role.
	if err := prepareWorkerChroot(ctx, cfg); err != nil {
		rep.failHard("worker-chroot", err)
	}
	rep.check("worker-chroot", nil)

	// Search is a required production capability. Provision the same
	// administrator-owned HTTPS/mTLS manifest into the server root and the
	// worker's separate chroot; neither component receives a search endpoint or
	// trust material through environment fallback.
	if err := prepareSearchMount(ctx, cfg, "/run/knowvault/search", runtimeidentity.Server); err != nil {
		rep.failHard("search-mount-server", err)
	}
	if err := prepareSearchMount(ctx, cfg, workerChrootDir+"/run/knowvault/search", runtimeidentity.Worker); err != nil {
		rep.failHard("search-mount-worker", err)
	}
	rep.check("search-mount", nil)

	if err := runOperator(ctx, cfg, "secrets", "generate",
		"-out", workerSecretsMount,
		"-consumer", "worker",
		"-organization", cfg.organizationID,
		"-provider", cfg.providerID,
		"-database-url-file", "/e2e/run/db_worker.url",
		"-client-reference", clientSecretReference,
		"-client-secret-file", "/e2e/run/oidc-client.secret",
		"-keys-from", "/run/knowvault/secrets",
	); err != nil {
		rep.failHard("operator-secrets-generate-worker", err)
	}
	rep.check("operator-secrets-generate-worker", nil)

	if err := runOperator(ctx, cfg, "secrets", "verify",
		"-mount", workerSecretsMount,
		"-consumer", "worker",
		"-organization", cfg.organizationID,
		"-provider", cfg.providerID,
	); err != nil {
		rep.failHard("operator-secrets-verify-worker", err)
	}
	rep.check("operator-secrets-verify-worker", nil)

	// Readiness is evaluated only after both component mounts exist. The
	// operator loads each mount through the product loader, opens each
	// verify-full DatabaseURL as its intended runtime role, and validates the
	// explicit purpose-separated trust root before Phase A starts.
	if err := runOperator(ctx, cfg, "readiness",
		"-server-mount", "/run/knowvault/secrets",
		"-worker-mount", workerSecretsMount,
		"-trust-mount", "/run/knowvault/trust",
		"-organization", cfg.organizationID,
		"-provider", cfg.providerID,
		"-migrations-dir", "/db/migrations",
	); err != nil {
		rep.failHard("operator-readiness", err)
	}
	rep.check("operator-readiness", nil)

	// --- Phase A: the workspace-managed source is connected and confirmed
	// through the product surfaces, and the activation is placed.

	// Fixture rows the product surface needs that are outside any product API:
	// the policy registry head the authority commands pin, and the verified
	// FOLDER capability profile the registration runtime requires.
	if err := seedPolicyRegistry(ctx, cfg); err != nil {
		rep.failHard("seed-policy-registry", err)
	}
	rep.check("seed-policy-registry", nil)

	if err := seedCapabilityProfile(ctx, cfg); err != nil {
		rep.failHard("seed-capability-profile", err)
	}
	rep.check("seed-capability-profile", nil)

	// The pinned source mount lives inside the worker chroot: manifest plus
	// corpus, owned root:65530 with the mode bits the worker mount loader
	// enforces.
	if err := prepareSourceMount(ctx, cfg, workerChrootDir+"/run/knowvault/sources"); err != nil {
		rep.failHard("source-mount", err)
	}
	rep.check("source-mount", nil)

	if _, err := startIDP(ctx, cfg); err != nil {
		rep.failHard("idp-start", err)
	}
	rep.check("idp-start", nil)

	if err := startProxy(ctx, cfg); err != nil {
		rep.failHard("proxy-start", err)
	}
	rep.check("proxy-start", nil)

	server, err := startServer(ctx, cfg)
	if err != nil {
		rep.failHard("server-start", err)
	}
	rep.check("server-start", nil)

	// The confirmation chain runs through the product repository over the
	// application role, exactly as the product server would drive it.
	store, closeStore, err := openProductStore(ctx)
	if err != nil {
		rep.failHard("product-store", err)
	}
	rep.check("product-store", nil)
	defer closeStore()

	client, err := newAPIClient(cfg)
	if err != nil {
		rep.failHard("api-client", err)
	}
	rep.check("api-client", nil)

	if err := client.login(ctx); err != nil {
		rep.failHard("login", fmt.Errorf("%w\nlogin attempts:\n%s\nserver log:\n%s", err, loginAttemptDiagnostic(ctx, cfg), server.logTail()))
	}
	rep.check("login", nil)

	if err := client.fetchCSRF(ctx); err != nil {
		rep.failHard("csrf", err)
	}
	rep.check("csrf", nil)

	// The system capability projection is unauthenticated but content-free.
	// Assert the real runtime snapshot before creating tenant data: the E2E
	// harness intentionally mounts no qualified embedding profile, so vector
	// retrieval must be explicit PARTIAL while the extractive planner remains
	// available and Enterprise release stays closed.
	capabilities, err := client.getSystemCapabilities(ctx)
	if err == nil {
		if capabilities.SchemaVersion != "system-capabilities-v1" || capabilities.Component != "knowvault-server" || capabilities.ReleaseEligible {
			err = fmt.Errorf("invalid system capability envelope: %+v", capabilities)
		} else {
			seen := make(map[string]systemCapability, len(capabilities.Capabilities))
			for _, capability := range capabilities.Capabilities {
				seen[capability.ID] = capability
			}
			for id, expected := range map[string]struct{ status, reason string }{
				"generic_planner":          {status: "READY"},
				"vector_retrieval":         {status: "PARTIAL", reason: "EMBEDDING_PROFILE_UNAVAILABLE"},
				"generative_model_gateway": {status: "BLOCKED", reason: "MODEL_PROFILE_UNAVAILABLE"},
				"enterprise_release_gate":  {status: "BLOCKED", reason: "EXTERNAL_QUALIFICATION_REQUIRED"},
			} {
				got, ok := seen[id]
				if !ok || got.Status != expected.status || got.ReasonCode != expected.reason {
					err = fmt.Errorf("system capability %s = %+v, want status=%s reason=%q", id, got, expected.status, expected.reason)
					break
				}
			}
		}
	}
	if err != nil {
		rep.failHard("system-capabilities", err)
	}
	rep.check("system-capabilities", nil)

	created, workspaceConfHash, err := client.createWorkspace(ctx)
	if err != nil {
		rep.failHard("workspace-create", err)
	}
	rep.check("workspace-create", nil)

	registered, err := client.registerSource(ctx)
	if err != nil {
		rep.failHard("source-register", err)
	}
	rep.check("source-register", nil)

	scopeHash, err := scopeConfigHash(ctx, cfg, registered.SourceScopeID)
	if err != nil {
		rep.failHard("scope-config-hash", err)
	}
	rep.check("scope-config-hash", nil)

	// The workspace-managed confirmation chain: bind the exact DRAFT scope,
	// issue the actor grant, confirm against the registry heads.
	if _, err := addSourceAndConfirm(ctx, cfg, store, created.ID, created.Revision, workspaceConfHash,
		registered.SourceScopeID, scopeHash); err != nil {
		rep.failHard("grant-confirm", err)
	}
	rep.check("grant-confirm", nil)

	// Trust verification (ADR-0087 §2): a CONNECTOR_ADMIN principal drives the
	// product command Store.VerifyConnectionTrust, the same repository method
	// the REST sources/connections/{id}:verify-trust action and the
	// knowvault_verify_connection_trust MCP tool call. The CONNECTOR_ADMIN role
	// itself is host-provisioned fixture state (no product surface grants
	// organization roles yet); the DRAFT->VERIFIED transition itself is not.
	if err := seedConnectorAdminPrincipal(ctx, cfg); err != nil {
		rep.failHard("connector-admin-seed", err)
	}
	rep.check("connector-admin-seed", nil)

	if err := verifyConnectionTrust(ctx, cfg, store, registered.ConnectionID); err != nil {
		rep.failHard("trust-projection-verify", err)
	}
	rep.check("trust-projection-verify", nil)

	worker, err := startWorker(ctx, cfg)
	if err != nil {
		rep.failHard("worker-start", fmt.Errorf("%w\n%s\n%s", err,
			workerRootDiagnostic(), workerDatabaseDiagnostic(ctx, cfg)))
	}
	rep.check("worker-start", nil)

	activated, err := client.activateSource(ctx, registered.SourceScopeID)
	if err != nil {
		rep.failHard("activate", err)
	}
	rep.check("activate", nil)

	// --- Phase B: the durable sync job runs, the worker dies mid-run, a new
	// worker reclaims it and the full corpus lands without duplicates.

	admin, err := pgxpool.New(ctx, cfg.adminURL)
	if err != nil {
		rep.failHard("phase-b-admin", err)
	}
	rep.check("phase-b-admin", nil)
	defer admin.Close()

	expected, err := corpusCount(cfg.corpusDir)
	if err != nil {
		rep.failHard("corpus-count", err)
	}
	rep.check("corpus-count", nil)

	if _, err := waitForSyncRunJournaled(ctx, admin, cfg, registered.SourceScopeID, "RUNNING", 30*time.Second); err != nil {
		// Capture the live worker evidence first: the session and commit
		// activity snapshot only means anything while the worker is still
		// running, and the worker has already had its full window above.
		liveEvidence := workerDatabaseDiagnostic(ctx, cfg)
		// SIGQUIT makes the Go runtime dump every goroutine stack to the worker
		// log; the dump shows whether the worker hangs inside a poll (and where)
		// or keeps polling and seeing no job.
		_ = worker.command.Process.Signal(syscall.SIGQUIT)
		time.Sleep(2 * time.Second)
		rep.failHard("sync-started", fmt.Errorf("%w\nworker log:\n%s\n%s\n%s", err,
			redactRunSecrets(worker.logFull()), jobQueueDump(ctx, admin, cfg), liveEvidence))
	}
	rep.check("sync-started", nil)

	// The kill must land after the worker durably committed at least one object
	// of the scope: a kill before the first commit would silently exercise only
	// the not-yet-ingested half of continuation. The committed version row is
	// the durable proof; ingest commits per object, so the running worker
	// reaches it within the window.
	committedDeadline := time.Now().Add(30 * time.Second)
	for {
		totalVersions, _, err := scopeCatalogTotals(ctx, admin, cfg, registered.SourceScopeID)
		if err == nil && totalVersions >= 1 {
			break
		}
		if time.Now().After(committedDeadline) {
			// Preserve the live worker and database evidence while the process is
			// still available. Without this diagnostic a failed first-commit
			// window is indistinguishable from a scheduler delay, a missing job
			// claim, or a worker-side ingest error.
			rep.failHard("sync-first-commit", fmt.Errorf("worker committed no version within 30s: %v\nworker log:\n%s\n%s\n%s",
				err, redactRunSecrets(worker.logFull()), jobQueueDump(ctx, admin, cfg), workerDatabaseDiagnostic(ctx, cfg)))
		}
		time.Sleep(50 * time.Millisecond)
	}
	rep.check("sync-first-commit", nil)

	// The kill must land mid-run: re-read the state and refuse to continue if
	// the sync already finished (a kill after completion would silently prove
	// nothing).
	state, err := latestSyncRun(ctx, admin, cfg, registered.SourceScopeID)
	if err == nil && state.Status != "RUNNING" {
		err = fmt.Errorf("sync finished before the kill window (status %s)", state.Status)
	}
	if err != nil {
		rep.failHard("sync-mid-run", err)
	}
	rep.check("sync-mid-run", nil)

	// SIGKILL: the worker process dies without any graceful handshake, the
	// failure mode the continuation clause must survive.
	if err := worker.kill(); err != nil {
		rep.failHard("worker-kill", err)
	}
	rep.check("worker-kill", nil)

	// The honest crash signature: the sync run stays RUNNING with no
	// completion, and the durable job remains held by the expired lease.
	state, err = latestSyncRun(ctx, admin, cfg, registered.SourceScopeID)
	if err == nil && state.Status != "RUNNING" {
		err = fmt.Errorf("sync run changed state across the kill (status %s)", state.Status)
	}
	if err != nil {
		rep.failHard("crash-signature", err)
	}
	rep.check("crash-signature", nil)

	// A new worker reclaims the abandoned job after the lease expires and
	// continues the sync from the durable state.
	worker, err = startWorker(ctx, cfg)
	if err != nil {
		rep.failHard("worker-restart", err)
	}
	rep.check("worker-restart", nil)

	finalState, err := waitForSyncRun(ctx, admin, cfg, registered.SourceScopeID, "SUCCEEDED", 150*time.Second)
	if err != nil {
		// Preserve the worker's bounded diagnostic and durable queue snapshot at
		// the terminal gate. A failed run can otherwise hide whether the
		// continuation stopped on ingestion, lease reclaim, or search outbox.
		rep.failHard("sync-completed", fmt.Errorf("%w\nworker log:\n%s\n%s\n%s",
			err, redactRunSecrets(worker.logFull()), jobQueueDump(ctx, admin, cfg), workerDatabaseDiagnostic(ctx, cfg)))
	}
	rep.check("sync-completed", nil)

	// The worker's ordered outbox applier must have projected at least one
	// encrypted Evidence fragment into the real HTTPS OpenSearch node before
	// this full-loop proof can pass. This retries while the worker drains the
	// final search events and exercises the exact mounted TLS client boundary.
	if err := waitForSearchProjection(ctx, cfg, 60*time.Second); err != nil {
		rep.failHard("search-projection", fmt.Errorf("%w\nworker log:\n%s\n%s\n%s",
			err, redactRunSecrets(worker.logFull()), jobQueueDump(ctx, admin, cfg), workerDatabaseDiagnostic(ctx, cfg)))
	}
	rep.check("search-projection", nil)

	// seen/ingested are per-run full-rescan counters: the final SUCCEEDED run
	// re-scanned the whole corpus, so they must equal the corpus there. The
	// creation totals come from the scope catalog, not from sync_run counters:
	// the product writes those only in the terminal SUCCEEDED update, so a
	// SIGKILLed first worker would leave its share unrecorded even though the
	// objects, versions and evidence it committed are durably in the catalog.
	// The catalog rows are the deterministic record no matter where the kill
	// landed.
	totalVersions, totalEvidence, err := scopeCatalogTotals(ctx, admin, cfg, registered.SourceScopeID)
	if err == nil {
		switch {
		case finalState.ObjectsSeen != expected || finalState.ObjectsIngested != expected || finalState.Quarantined != 0:
			err = fmt.Errorf("final run counters (seen=%d ingested=%d quarantined=%d), want seen=ingested=%d quarantined=0",
				finalState.ObjectsSeen, finalState.ObjectsIngested, finalState.Quarantined, expected)
		case totalVersions != expected || totalEvidence < 1:
			err = fmt.Errorf("scope totals (versions=%d evidence=%d), want versions=%d evidence>=1",
				totalVersions, totalEvidence, expected)
		}
	}
	if err != nil {
		rep.failHard("sync-counters", err)
	}
	rep.check("sync-counters", nil)

	// The continuation clause aggregates: the re-scan after the crash created
	// no duplicates in any of the three catalog relations.
	objects, memberships, versions, err := catalogCounts(ctx, admin, cfg)
	if err == nil && (objects != expected || memberships != expected || versions != expected) {
		err = fmt.Errorf("catalog counts (objects=%d memberships=%d versions=%d), want %d each",
			objects, memberships, versions, expected)
	}
	if err != nil {
		rep.failHard("no-duplicates", err)
	}
	rep.check("no-duplicates", nil)

	// An idempotent repeat activation with the same key returns the same
	// durable job without creating a second one.
	replayed, err := client.activateSource(ctx, registered.SourceScopeID)
	if err == nil && replayed.JobID != activated.JobID {
		err = fmt.Errorf("replay returned job %q, want %q", replayed.JobID, activated.JobID)
	}
	if err != nil {
		rep.failHard("activate-idempotent", err)
	}
	rep.check("activate-idempotent", nil)

	count, err := jobCount(ctx, admin, cfg, activated.JobID)
	if err == nil && count != 1 {
		err = fmt.Errorf("job %s has %d rows, want 1", activated.JobID, count)
	}
	if err != nil {
		rep.failHard("job-single", err)
	}
	rep.check("job-single", nil)

	// The result is visible through the product surface: the source status
	// reports a verified, enabled, successfully synchronized source.
	sources, err := client.listSources(ctx, created.ID)
	if err == nil {
		if len(sources) != 1 {
			err = fmt.Errorf("workspace reports %d sources, want 1", len(sources))
		} else {
			status := sources[0]
			if status.SourceScopeID != registered.SourceScopeID || !status.TrustVerified || !status.Enabled ||
				status.SyncStatus == nil || *status.SyncStatus != "SUCCEEDED" ||
				status.ObjectsSeen == nil || *status.ObjectsSeen != expected {
				err = fmt.Errorf("source status does not report the synchronized source: %+v", status)
			}
		}
	}
	if err != nil {
		rep.failHard("source-status", err)
	}
	rep.check("source-status", nil)

	// One evidence fragment of the synchronized scope is readable through the
	// fail-closed viewer route with its text and provenance intact.
	fragmentID, err := firstFragmentID(ctx, admin, cfg, registered.SourceScopeID)
	if err != nil {
		rep.failHard("fragment-lookup", err)
	}
	rep.check("fragment-lookup", nil)

	fragment, err := client.readEvidence(ctx, created.ID, fragmentID)
	if err == nil && (fragment.FragmentID != fragmentID || fragment.Text == "" ||
		fragment.Provenance.ConnectionID != registered.ConnectionID) {
		err = fmt.Errorf("evidence fragment %s is incomplete: %+v", fragmentID, fragment)
	}
	if err != nil {
		rep.failHard("evidence", err)
	}
	rep.check("evidence", nil)

	// REST and MCP must be two authenticated projections of the same durable
	// Question authority. Use one idempotency key so MCP must replay the REST
	// run; this proves parity for status, plan provenance, uncertainty/conflict
	// signals and the full citation shape even when the deployment has only a
	// partial (lexical/entity) retrieval capability.
	questionText := "What does the KnowVault pilot note 001 say?"
	parityKey := idemKey("question-parity")
	restQuestion, err := client.createQuestion(ctx, created.ID, questionText, parityKey)
	if err == nil {
		err = client.verifyPartialQuestion(ctx, created.ID, registered.ConnectionID, "FRESH", restQuestion)
	}
	if err != nil {
		rep.failHard("question-rest", err)
	}
	rep.check("question-rest", nil)
	mcpQuestion, mcpIsError, err := client.mcpQuestion(ctx, created.ID, questionText, parityKey)
	if err == nil && (mcpIsError || !sameQuestionProjection(restQuestion, mcpQuestion)) {
		err = fmt.Errorf("MCP projection drift or error bit mismatch: is_error=%v rest=%+v mcp=%+v", mcpIsError, restQuestion, mcpQuestion)
	}
	if err != nil {
		rep.failHard("question-mcp-parity", err)
	}
	rep.check("question-mcp-parity", nil)
	if restQuestion.ConversationID == "" || restQuestion.ConversationTurnID == "" {
		rep.failHard("question-conversation-created", fmt.Errorf("REST question did not return server-owned conversation binding: %+v", restQuestion))
	}
	rep.check("question-conversation-created", nil)
	// Continue the same conversation through both surfaces with a new
	// idempotency key. The projections must carry the same new turn while the
	// authority still evaluates only the new question text.
	continuationText := "What does the KnowVault pilot note 001 say in the follow-up?"
	continuationKey := idemKey("question-conversation-continuation")
	restContinuation, err := client.createQuestionInConversation(ctx, created.ID, restQuestion.ConversationID, continuationText, continuationKey)
	if err == nil {
		err = client.verifyPartialQuestion(ctx, created.ID, registered.ConnectionID, "FRESH", restContinuation)
	}
	if err == nil && (restContinuation.ConversationID != restQuestion.ConversationID || restContinuation.ConversationTurnID == "" || restContinuation.ConversationTurnID == restQuestion.ConversationTurnID) {
		err = fmt.Errorf("REST conversation continuation binding is invalid: first=%+v continuation=%+v", restQuestion, restContinuation)
	}
	if err != nil {
		rep.failHard("question-conversation-rest", err)
	}
	rep.check("question-conversation-rest", nil)
	mcpContinuation, mcpContinuationError, err := client.mcpQuestionInConversation(ctx, created.ID, restQuestion.ConversationID, continuationText, continuationKey)
	if err == nil && (mcpContinuationError || !sameQuestionProjection(restContinuation, mcpContinuation)) {
		err = fmt.Errorf("MCP conversation continuation drift or error bit mismatch: is_error=%v rest=%+v mcp=%+v", mcpContinuationError, restContinuation, mcpContinuation)
	}
	if err != nil {
		rep.failHard("question-conversation-mcp", err)
	}
	rep.check("question-conversation-mcp", nil)

	// Conversation lifecycle is a separate server-owned projection over the
	// same durable turns. List and get must expose both turns created above,
	// and MCP must return byte-equivalent decoded metadata and Question Run
	// projections. Archive is then exercised with a real idempotency receipt;
	// replaying that receipt through MCP must return the same archived view.
	conversations, err := client.listConversations(ctx, created.ID)
	var listed conversationProjection
	if err == nil {
		for _, candidate := range conversations {
			if candidate.ConversationID == restQuestion.ConversationID {
				listed = candidate
				break
			}
		}
		if listed.ConversationID == "" || len(listed.Turns) != 2 || listed.Turns[0].QuestionRun == nil || listed.Turns[1].QuestionRun == nil {
			err = fmt.Errorf("REST conversation list omitted the two authorized turns: %+v", conversations)
		}
	}
	if err != nil {
		rep.failHard("conversation-list-rest", err)
	}
	rep.check("conversation-list-rest", nil)
	mcpConversations, mcpConversationListError, err := client.mcpListConversations(ctx, created.ID)
	if err == nil && (mcpConversationListError || len(mcpConversations) != len(conversations)) {
		err = fmt.Errorf("MCP conversation list error/drift: is_error=%v rest=%d mcp=%d", mcpConversationListError, len(conversations), len(mcpConversations))
	}
	if err == nil {
		var mcpListed conversationProjection
		for _, candidate := range mcpConversations {
			if candidate.ConversationID == restQuestion.ConversationID {
				mcpListed = candidate
				break
			}
		}
		if !sameConversationProjection(listed, mcpListed) {
			err = fmt.Errorf("MCP conversation list projection drift: rest=%+v mcp=%+v", listed, mcpListed)
		}
	}
	if err != nil {
		rep.failHard("conversation-list-mcp-parity", err)
	}
	rep.check("conversation-list-mcp-parity", nil)
	restConversation, err := client.getConversation(ctx, created.ID, restQuestion.ConversationID)
	if err == nil && !sameConversationProjection(listed, restConversation) {
		err = fmt.Errorf("REST conversation get drifted from list projection: list=%+v get=%+v", listed, restConversation)
	}
	if err != nil {
		rep.failHard("conversation-get-rest", err)
	}
	rep.check("conversation-get-rest", nil)
	mcpConversation, mcpConversationGetError, err := client.mcpGetConversation(ctx, created.ID, restQuestion.ConversationID)
	if err == nil && (mcpConversationGetError || !sameConversationProjection(restConversation, mcpConversation)) {
		err = fmt.Errorf("MCP conversation get drift or error bit mismatch: is_error=%v rest=%+v mcp=%+v", mcpConversationGetError, restConversation, mcpConversation)
	}
	if err != nil {
		rep.failHard("conversation-get-mcp-parity", err)
	}
	rep.check("conversation-get-mcp-parity", nil)
	conversationArchiveKey := idemKey("conversation-archive")
	archivedConversation, err := client.archiveConversation(ctx, created.ID, restQuestion.ConversationID, conversationArchiveKey)
	if err == nil && (archivedConversation.ArchivedAt == nil || archivedConversation.ConversationID != restQuestion.ConversationID) {
		err = fmt.Errorf("REST archive did not return an archived conversation: %+v", archivedConversation)
	}
	if err != nil {
		rep.failHard("conversation-archive-rest", err)
	}
	rep.check("conversation-archive-rest", nil)
	replayedArchive, err := client.archiveConversation(ctx, created.ID, restQuestion.ConversationID, conversationArchiveKey)
	if err == nil && !sameConversationProjection(archivedConversation, replayedArchive) {
		err = fmt.Errorf("REST archive replay drifted: first=%+v replay=%+v", archivedConversation, replayedArchive)
	}
	if err != nil {
		rep.failHard("conversation-archive-idempotent", err)
	}
	rep.check("conversation-archive-idempotent", nil)
	mcpArchived, mcpArchiveError, err := client.mcpArchiveConversation(ctx, created.ID, restQuestion.ConversationID, conversationArchiveKey)
	if err == nil && (mcpArchiveError || !sameConversationProjection(archivedConversation, mcpArchived)) {
		err = fmt.Errorf("MCP archive replay drift or error bit mismatch: is_error=%v rest=%+v mcp=%+v", mcpArchiveError, archivedConversation, mcpArchived)
	}
	if err != nil {
		rep.failHard("conversation-archive-mcp-parity", err)
	}
	rep.check("conversation-archive-mcp-parity", nil)

	// An unsupported/ambiguous request must remain a typed UNKNOWN outcome on
	// both surfaces. The same replay check prevents either adapter from
	// manufacturing a fallback answer for an unresolved plan.
	unknownText := "???"
	unknownKey := idemKey("question-unknown-parity")
	restUnknown, err := client.createQuestion(ctx, created.ID, unknownText, unknownKey)
	if err == nil && (restUnknown.PlanningStatus != "UNKNOWN" || restUnknown.ResultStatus != "INSUFFICIENT_EVIDENCE" || len(restUnknown.Citations) != 0) {
		err = fmt.Errorf("REST unknown projection is not fail-closed: %+v", restUnknown)
	}
	if err != nil {
		rep.failHard("question-unknown-rest", err)
	}
	rep.check("question-unknown-rest", nil)
	mcpUnknown, mcpUnknownError, err := client.mcpQuestion(ctx, created.ID, unknownText, unknownKey)
	if err == nil && (!mcpUnknownError || !sameQuestionProjection(restUnknown, mcpUnknown)) {
		err = fmt.Errorf("MCP unknown projection drift or error bit mismatch: is_error=%v rest=%+v mcp=%+v", mcpUnknownError, restUnknown, mcpUnknown)
	}
	if err != nil {
		rep.failHard("question-unknown-mcp-parity", err)
	}
	rep.check("question-unknown-mcp-parity", nil)

	// A question that carries two equally strong generic operation signals must
	// remain a clarification outcome. This proves the planner's ambiguity
	// contract across REST and MCP without depending on a particular entity or
	// source branch.
	clarifyText := "What is the meaning and compare this process?"
	clarifyKey := idemKey("question-clarification-parity")
	restClarify, err := client.createQuestion(ctx, created.ID, clarifyText, clarifyKey)
	if err == nil && (restClarify.PlanningStatus != "CLARIFICATION_REQUIRED" || restClarify.ResultStatus != "INSUFFICIENT_EVIDENCE" || restClarify.Clarification == "" || len(restClarify.Citations) != 0) {
		err = fmt.Errorf("REST clarification projection is not fail-closed: %+v", restClarify)
	}
	if err != nil {
		rep.failHard("question-clarification-rest", err)
	}
	rep.check("question-clarification-rest", nil)
	mcpClarify, mcpClarifyError, err := client.mcpQuestion(ctx, created.ID, clarifyText, clarifyKey)
	if err == nil && (!mcpClarifyError || !sameQuestionProjection(restClarify, mcpClarify)) {
		err = fmt.Errorf("MCP clarification projection drift or error bit mismatch: is_error=%v rest=%+v mcp=%+v", mcpClarifyError, restClarify, mcpClarify)
	}
	if err != nil {
		rep.failHard("question-clarification-mcp-parity", err)
	}
	rep.check("question-clarification-mcp-parity", nil)

	// Freshness is a server-owned lifecycle input, not a renderer hint. Insert
	// a real RUNNING sync projection for the same scope, then prove that both
	// authenticated surfaces withhold totals from the incomplete stale corpus.
	// row uses the already-created durable job only as its immutable FK; no
	// fixture answer or alternate Question authority is involved.
	staleSyncRunID := "syncrun_01ARZ3NDEKTSV4RRFFQ69G5FBV"
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.sync_run
			(organization_id, id, source_scope_id, source_scope_revision, job_id, mode, status, cursor_before)
		VALUES ($1,$2,$3,$4,$5,'FULL','RUNNING','1')`, cfg.organizationID,
		staleSyncRunID, registered.SourceScopeID, registered.Revision, activated.JobID); err != nil {
		rep.failHard("question-stale-sync-seed", err)
	}
	rep.check("question-stale-sync-seed", nil)
	staleText := "How many KnowVault pilot notes are there?"
	staleKey := idemKey("question-stale-parity")
	restStale, err := client.createQuestion(ctx, created.ID, staleText, staleKey)
	if err == nil && (restStale.PlanningOperation != "AGGREGATE" || restStale.ResultStatus != "INSUFFICIENT_EVIDENCE" || restStale.CorpusStatus != "PARTIAL" || len(restStale.Citations) != 0 || restStale.Freshness.State != "STALE" || restStale.Freshness.CapturedAt == nil) {
		err = fmt.Errorf("REST stale projection is not fail-closed: %+v", restStale)
	}
	if err != nil {
		rep.failHard("question-stale-rest", err)
	}
	rep.check("question-stale-rest", nil)
	mcpStale, mcpStaleError, err := client.mcpQuestion(ctx, created.ID, staleText, staleKey)
	if err == nil && (!mcpStaleError || !sameQuestionProjection(restStale, mcpStale)) {
		err = fmt.Errorf("MCP stale projection drift or error bit mismatch: is_error=%v rest=%+v mcp=%+v", mcpStaleError, restStale, mcpStale)
	}
	if err != nil {
		rep.failHard("question-stale-mcp-parity", err)
	}
	rep.check("question-stale-mcp-parity", nil)
	// Saved prose remains readable during a sync; it must carry STALE and
	// PARTIAL metadata, with the same citation verification as fresh prose.
	staleLookupText := "What does the KnowVault pilot note 002 say?"
	staleLookupKey := idemKey("question-stale-lookup-parity")
	restStaleLookup, err := client.createQuestion(ctx, created.ID, staleLookupText, staleLookupKey)
	if err == nil {
		err = client.verifyPartialQuestion(ctx, created.ID, registered.ConnectionID, "STALE", restStaleLookup)
	}
	if err != nil {
		rep.failHard("question-stale-lookup-rest", err)
	}
	rep.check("question-stale-lookup-rest", nil)
	mcpStaleLookup, mcpStaleLookupError, err := client.mcpQuestion(ctx, created.ID, staleLookupText, staleLookupKey)
	if err == nil && (mcpStaleLookupError || !sameQuestionProjection(restStaleLookup, mcpStaleLookup)) {
		err = fmt.Errorf("MCP stale lookup drift or error bit mismatch")
	}
	if err != nil {
		rep.failHard("question-stale-lookup-mcp-parity", err)
	}
	rep.check("question-stale-lookup-mcp-parity", nil)
	// Close the synthetic-in-time (but real persisted) running observation so
	// the subsequent revocation check isolates membership denial from freshness.
	if _, err := admin.Exec(ctx, `
		UPDATE public.sync_run
		   SET status='SUCCEEDED', cursor_after='1', completed_at=now(),
		       objects_seen=$3, objects_ingested=$3, versions_created=$3,
		       evidence_published=$3, quarantined=0
		 WHERE organization_id=$1 AND id=$2 AND status='RUNNING'`, cfg.organizationID,
		staleSyncRunID, expected); err != nil {
		rep.failHard("question-stale-sync-close", err)
	}
	rep.check("question-stale-sync-close", nil)

	// Revocation is exercised at the source-membership root. Removing the
	// active membership hides Evidence, graph and search projections before the
	// next request; both surfaces must return the same content-free result and
	// neither may create a citation from an already-indexed document.
	if _, err := admin.Exec(ctx, `
		UPDATE public.source_object_scope
		   SET membership_state='REMOVED', removed_at=now()
		 WHERE organization_id=$1 AND source_scope_id=$2 AND source_scope_revision=$3
		   AND membership_state='ACTIVE'`, cfg.organizationID, registered.SourceScopeID, registered.Revision); err != nil {
		rep.failHard("question-revocation-seed", err)
	}
	rep.check("question-revocation-seed", nil)
	revokedText := "What does the revoked pilot note contain?"
	revokedKey := idemKey("question-revoked-parity")
	restRevoked, err := client.createQuestion(ctx, created.ID, revokedText, revokedKey)
	if err == nil && (restRevoked.ResultStatus != "INSUFFICIENT_EVIDENCE" || len(restRevoked.Citations) != 0) {
		err = fmt.Errorf("REST revoked projection disclosed evidence: %+v", restRevoked)
	}
	if err != nil {
		rep.failHard("question-revoked-rest", err)
	}
	rep.check("question-revoked-rest", nil)
	mcpRevoked, mcpRevokedError, err := client.mcpQuestion(ctx, created.ID, revokedText, revokedKey)
	if err == nil && (!mcpRevokedError || !sameQuestionProjection(restRevoked, mcpRevoked)) {
		err = fmt.Errorf("MCP revoked projection drift or error bit mismatch: is_error=%v rest=%+v mcp=%+v", mcpRevokedError, restRevoked, mcpRevoked)
	}
	if err != nil {
		rep.failHard("question-revoked-mcp-parity", err)
	}
	rep.check("question-revoked-mcp-parity", nil)

	// A workspace lifecycle denial must be equivalent at both authenticated
	// surfaces. Archive a freshly-created workspace through the real
	// conditional mutation route, then assert REST returns the content-free
	// FORBIDDEN envelope while MCP returns its typed JSON-RPC error. Neither
	// adapter may create a Question Run for an archived workspace.
	deniedWorkspace, deniedHash, err := client.createWorkspace(ctx)
	if err != nil {
		rep.failHard("question-denied-workspace-create", err)
	}
	rep.check("question-denied-workspace-create", nil)
	if deniedHash, err = client.workspaceConfigurationHash(ctx, deniedWorkspace.ID); err != nil {
		rep.failHard("question-denied-workspace-read", err)
	}
	rep.check("question-denied-workspace-read", nil)
	if err := client.archiveWorkspace(ctx, deniedWorkspace.ID, deniedHash, idemKey("question-denied-archive")); err != nil {
		rep.failHard("question-denied-workspace-archive", err)
	}
	rep.check("question-denied-workspace-archive", nil)
	deniedQuestion := "What does the archived workspace contain?"
	deniedREST, deniedRESTErr := client.createQuestion(ctx, deniedWorkspace.ID, deniedQuestion, idemKey("question-denied-rest"))
	if deniedRESTErr == nil || !strings.Contains(deniedRESTErr.Error(), "status 403 code=FORBIDDEN") || deniedREST.ID != "" {
		if deniedRESTErr == nil {
			deniedRESTErr = fmt.Errorf("REST accepted a question for archived workspace: %+v", deniedREST)
		}
		rep.failHard("question-denied-rest", deniedRESTErr)
	}
	rep.check("question-denied-rest", nil)
	_, _, deniedMCPError := client.mcpQuestion(ctx, deniedWorkspace.ID, deniedQuestion, idemKey("question-denied-mcp"))
	if deniedMCPError == nil || !strings.Contains(deniedMCPError.Error(), "code=-32000") {
		if deniedMCPError == nil {
			deniedMCPError = fmt.Errorf("MCP accepted a question for archived workspace")
		}
		rep.failHard("question-denied-mcp", deniedMCPError)
	}
	rep.check("question-denied-mcp", nil)

	// The audit journal is the projection an organization security auditor may
	// open over a workspace stream. The static IdP can authenticate only the
	// owner subject, so the harness grants that principal the SECURITY_AUDITOR
	// organization role for this e2e tenant, exactly the role the host demo
	// used. The assignment is bounded test fixture data inside the harness
	// database; it only adds the role the journal route's audit.read_metadata
	// gate requires and never weakens a product invariant or touches the
	// organization's sole OWNER role.
	if _, err := admin.Exec(ctx, `
		INSERT INTO public.organization_role_assignment
			(id, organization_id, principal_id, role, valid_from_revision, assigned_by)
		VALUES ('ora_e2e_owner_security_auditor', $1, $2, 'SECURITY_AUDITOR', 1, $2)
		ON CONFLICT (id) DO NOTHING`, cfg.organizationID, ownerPrincipalID); err != nil {
		rep.failHard("audit-role-seed", err)
	}
	rep.check("audit-role-seed", nil)

	// Read the journal twice through the product route as the auditor. Every
	// lawful journal read appends its own audit.viewed event to the chain, so
	// the second read returns the first read's event as the newest workspace
	// entry; verifyAuditHashChain then asserts that newest event's event_hash
	// is exactly the returned organization chain head, proving the journal
	// answered a non-empty, hash-anchored stream.
	if _, err := client.getAuditEvents(ctx, created.ID); err != nil {
		rep.failHard("audit-journal-hash-chain", fmt.Errorf("journal read: %w", err))
	}
	journal, err := client.getAuditEvents(ctx, created.ID)
	if err == nil {
		err = verifyAuditHashChain(journal)
	}
	if err != nil {
		rep.failHard("audit-journal-hash-chain", err)
	}
	rep.check("audit-journal-hash-chain", nil)

	rep.finish()
}
