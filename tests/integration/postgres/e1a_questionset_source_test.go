package postgres_test

// E-1a synthetic proving environment: the PostgreSQL source database, its
// least-privilege query role, the source service the chat tool runtime sees,
// and the real governed SQL execution path. Everything here is synthetic; no
// customer data, credential or address is involved.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"knowvault.local/verified-workspace/internal/audit"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/platform/workspaceapi"
	"knowvault.local/verified-workspace/internal/question"
	"knowvault.local/verified-workspace/internal/source/canon"
	sourcediscovery "knowvault.local/verified-workspace/internal/source/discovery"
	"knowvault.local/verified-workspace/internal/source/ids"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery/governedquery"
	"knowvault.local/verified-workspace/internal/source/registration"
	workspacerepository "knowvault.local/verified-workspace/internal/workspace/repository"
)

// e1aDocker runs one docker CLI command and fails the test on a non-zero exit.
func e1aDocker(t *testing.T, args ...string) string {
	t.Helper()
	command := exec.Command("docker", args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v\n%s", strings.Join(args, " "), err, string(output))
	}
	return strings.TrimSpace(string(output))
}

// e1aDockerQuiet runs one docker CLI command, ignoring its failure. It is used
// only for the best-effort removal of a container this harness owns.
func e1aDockerQuiet(args ...string) {
	_ = exec.Command("docker", args...).Run()
}

// e1aEnsureContainer removes any stale container of this name and starts the
// pinned PostgreSQL image on the card's published port. It returns a cleanup
// that removes exactly this harness's container.
func e1aEnsureContainer(t *testing.T, ctx context.Context, name string, port int, databaseName string) func() {
	t.Helper()
	e1aDockerQuiet("rm", "-f", "-v", name)
	e1aDocker(t, "run", "-d", "--name", name,
		"-e", "POSTGRES_DB="+databaseName,
		"-e", "POSTGRES_PASSWORD=postgres",
		"-p", fmt.Sprintf("%d:5432", port),
		"postgres:18.4")
	remove := func() { e1aDockerQuiet("rm", "-f", "-v", name) }
	t.Cleanup(remove)
	e1aWaitPostgres(t, ctx, fmt.Sprintf("postgres://postgres:postgres@localhost:%d/%s?sslmode=disable", port, databaseName))
	return remove
}

// e1aWaitPostgres blocks until the database accepts a connection.
func e1aWaitPostgres(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		connection, err := pgx.Connect(ctx, dsn)
		if err == nil {
			_ = connection.Close(ctx)
			return
		}
		lastErr = err
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("postgres at %s did not become ready: %v", dsn, lastErr)
}

// e1aGenerateSourceCerts writes a fresh CA and a server certificate for
// localhost into dir and returns the CA certificate pool.
func e1aGenerateSourceCerts(t *testing.T, dir string) *x509.CertPool {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "kv-card-e-1a-src-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM := func(name, kind string, der []byte) {
		path := filepath.Join(dir, name)
		block := pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: der})
		if err := os.WriteFile(path, block, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writePEM("ca.crt", "CERTIFICATE", caDER)
	writePEM("server.crt", "CERTIFICATE", serverDER)
	keyDER, err := x509.MarshalECPrivateKey(serverKey)
	if err != nil {
		t.Fatal(err)
	}
	writePEM("server.key", "EC PRIVATE KEY", keyDER)

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})) {
		t.Fatal("append generated CA")
	}
	return pool
}

// e1aEnableSourceTLS copies the generated certificates into the container,
// turns SSL on and restarts PostgreSQL so the governed query DSN can use
// sslmode=verify-full.
func e1aEnableSourceTLS(t *testing.T, ctx context.Context, container string, port int, databaseName, certDir string) {
	t.Helper()
	remoteRoot := "/var/lib/postgresql/kv-certs"
	e1aDocker(t, "exec", "-u", "root", container, "sh", "-c", "rm -rf "+remoteRoot+" && mkdir -p "+remoteRoot)
	e1aDocker(t, "cp", certDir+"/.", container+":"+remoteRoot)
	e1aDocker(t, "exec", "-u", "root", container, "sh", "-c",
		"chown -R postgres:postgres "+remoteRoot+" && chmod 700 "+remoteRoot+
			" && chmod 600 "+remoteRoot+"/server.key && chmod 644 "+remoteRoot+"/server.crt "+remoteRoot+"/ca.crt")
	e1aDocker(t, "exec", container, "psql", "-U", "postgres", "-d", databaseName, "-v", "ON_ERROR_STOP=1",
		"-c", "ALTER SYSTEM SET ssl='on'",
		"-c", "ALTER SYSTEM SET ssl_cert_file='"+remoteRoot+"/server.crt'",
		"-c", "ALTER SYSTEM SET ssl_key_file='"+remoteRoot+"/server.key'")
	e1aDocker(t, "restart", container)
	e1aWaitPostgres(t, ctx, fmt.Sprintf("postgres://postgres:postgres@localhost:%d/%s?sslmode=disable", port, databaseName))
}

// e1aSeedSourceDatabase creates the synthetic tables and data and the
// least-privilege query role named by the question set.
func e1aSeedSourceDatabase(t *testing.T, ctx context.Context, admin *pgx.Conn, statements []string) {
	t.Helper()
	for _, statement := range statements {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("source seed %q: %v", truncateSQL(statement), err)
		}
	}
}

func truncateSQL(statement string) string {
	if len(statement) <= 120 {
		return statement
	}
	return statement[:120] + "…"
}

// e1aSourceIdentity recomputes the pgdb identity exactly as the governed
// credential check does: host, port, database oid and database name.
func e1aSourceIdentity(t *testing.T, ctx context.Context, dsn string) string {
	t.Helper()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect for identity: %v", err)
	}
	defer connection.Close(ctx)
	var oid uint32
	var name string
	if err := connection.QueryRow(ctx, `SELECT database.oid, database.datname FROM pg_catalog.pg_database AS database WHERE database.datname = current_database()`).Scan(&oid, &name); err != nil {
		t.Fatalf("read source database identity: %v", err)
	}
	raw, err := canon.CanonicalJSON(struct {
		Host string `json:"host"`
		Port uint16 `json:"port"`
		OID  uint32 `json:"oid"`
		Name string `json:"name"`
	}{Host: connection.Config().Host, Port: uint16(connection.Config().Port), OID: oid, Name: name})
	if err != nil {
		t.Fatal(err)
	}
	return "pgdb:" + strings.TrimPrefix(canon.Hash(raw), "sha256:")
}

// e1aSourceService is the SourceService the chat tool runtime sees. Required
// methods delegate to the registration service and the workspace repository;
// the optional schema/SQL capabilities are the real governed execution path.
type e1aSourceService struct {
	registrations *registration.Service
	workspaces    *workspacerepository.Store
	reader        *sourcediscovery.Reader
	sql           *e1aSourceSQL
}

func (service e1aSourceService) Register(ctx context.Context, access database.AccessContext, request registration.RegisterRequest) (registration.RegisterResult, error) {
	return service.registrations.Register(ctx, access, request)
}

func (service e1aSourceService) Activate(ctx context.Context, access database.AccessContext, request registration.ActivateRequest) (registration.ActivateResult, error) {
	return service.registrations.Activate(ctx, access, request)
}

func (service e1aSourceService) Sync(ctx context.Context, access database.AccessContext, request registration.SyncRequest) (registration.SyncResult, error) {
	return service.registrations.Sync(ctx, access, request)
}

func (service e1aSourceService) ListSources(ctx context.Context, access database.AccessContext, workspaceID string) ([]workspacerepository.SourceStatus, error) {
	return service.workspaces.ListSources(ctx, access, workspaceID)
}

func (service e1aSourceService) ConfirmationContext(ctx context.Context, access database.AccessContext, workspaceID string) (workspacerepository.ConfirmationContext, error) {
	return service.workspaces.ConfirmationContext(ctx, access, workspaceID)
}

func (service e1aSourceService) UploadDocuments(ctx context.Context, access database.AccessContext, request registration.UploadDocumentsRequest) (registration.UploadDocumentsResult, error) {
	return service.registrations.UploadDocuments(ctx, access, request)
}

func (service e1aSourceService) GetDiscovery(ctx context.Context, access database.AccessContext, requestID string) (sourcediscovery.ReadResult, error) {
	if service.reader == nil {
		return sourcediscovery.ReadResult{}, errors.New("discovery reader not composed")
	}
	return service.reader.Get(ctx, access, requestID)
}

func (service e1aSourceService) ListSourceSchemas(ctx context.Context, access database.AccessContext, workspaceID string) ([]workspacerepository.SourceSchemaSource, error) {
	return service.workspaces.ListSourceSchemas(ctx, access, workspaceID)
}

func (service e1aSourceService) SourceSchema(ctx context.Context, access database.AccessContext, workspaceID, sourceID, table string, offset, limit int) (workspacerepository.SourceSchema, error) {
	return service.workspaces.SourceSchema(ctx, access, workspaceID, sourceID, table, offset, limit)
}

func (service e1aSourceService) SourceSQL(ctx context.Context, access database.AccessContext, workspaceID string, request workspaceapi.SourceSQLRequest) (workspaceapi.SourceSQLResult, error) {
	if service.sql == nil {
		return workspaceapi.SourceSQLResult{}, &workspaceapi.SourceSQLRefusal{Code: "DATABASE_REJECTED"}
	}
	return service.sql.SourceSQL(ctx, access, workspaceID, request)
}

func (service e1aSourceService) ReauthorizeSourceSQLAttempt(ctx context.Context, access database.AccessContext, workspaceID string, disclosure question.SourceSQLAttemptDisclosure) error {
	if service.sql == nil {
		return errors.New("SOURCE_SQL_REAUTHORIZATION_UNAVAILABLE")
	}
	return service.sql.ReauthorizeSourceSQLAttempt(ctx, access, workspaceID, disclosure)
}

// e1aSourceSQL is the harness's mirror of the production source SQL executor:
// authorization through the workspace repository, a reference-to-DSN map in
// place of the mounted secret provider, the one governedquery execution path
// and the mandatory content-free attempt audit.
type e1aSourceSQL struct {
	workspaces  *workspacerepository.Store
	auditor     *audit.Store
	credentials map[string]string
	roots       *x509.CertPool
}

func (executor *e1aSourceSQL) SourceSQL(ctx context.Context, access database.AccessContext, workspaceID string, request workspaceapi.SourceSQLRequest) (workspaceapi.SourceSQLResult, error) {
	if executor == nil || executor.workspaces == nil || executor.auditor == nil {
		return workspaceapi.SourceSQLResult{}, &workspaceapi.SourceSQLRefusal{Code: "DATABASE_REJECTED"}
	}
	target, err := executor.workspaces.SourceQuery(ctx, access, workspaceID, request.SourceID)
	if err != nil {
		return workspaceapi.SourceSQLResult{}, err
	}
	if target.ActivationStatus != "READY" || !target.TrustVerified {
		return workspaceapi.SourceSQLResult{}, workspacerepository.NewError(workspacerepository.CodeNotFound, nil)
	}
	attempt := governedquery.Attempt{}
	code := ""
	var result governedquery.QueryResult
	if target.QueryCredentialReference == "" {
		code = string(governedquery.CodeSourceSQLNotConfigured)
	} else if dsn, ok := executor.credentials[target.QueryCredentialReference]; !ok || dsn == "" {
		code = string(governedquery.CodeDatabaseRejected)
	} else {
		config := governedquery.Config{
			ConnectionID: target.SourceID, DatabaseIdentity: target.DatabaseIdentity, WorkspaceID: workspaceID,
			DSN: dsn, TrustRoots: executor.roots, Limits: e1aSourceSQLLimits(),
		}
		var execErr error
		result, attempt, execErr = governedquery.ExecuteScoped(ctx, config, governedquery.ScopedParams{
			SQLText: request.SQL, Purpose: request.Purpose,
			Schema: governedquery.ScopedSchema{Relations: e1aScopedRelations(target)},
		})
		code = e1aSourceSQLRefusalCode(execErr)
	}
	eventID, auditErr := executor.auditAttempt(ctx, access, workspaceID, target, request.Purpose, attempt, code)
	if auditErr != nil {
		return workspaceapi.SourceSQLResult{}, errors.New("SOURCE_SQL_AUDIT_UNAVAILABLE")
	}
	if code != "" {
		return workspaceapi.SourceSQLResult{}, &workspaceapi.SourceSQLRefusal{Code: code}
	}
	return workspaceapi.SourceSQLResult{
		Format: "postgres-text-table-v1", SourceID: target.SourceID, ExposedSchemaRevision: target.ScopeRevision,
		Columns: result.Columns, Rows: result.Rows, RowCount: result.RowCount,
		AttemptID: eventID, SQLHash: attempt.SQLHash, ResultDigest: attempt.ResultDigest,
		DatabaseIdentity:   target.DatabaseIdentity,
		ExecutionStartedAt: result.ExecutionStartedAt, ExecutionCompletedAt: result.ExecutionCompletedAt,
	}, nil
}

func (executor *e1aSourceSQL) ReauthorizeSourceSQLAttempt(ctx context.Context, access database.AccessContext, workspaceID string, disclosure question.SourceSQLAttemptDisclosure) error {
	if executor == nil || executor.workspaces == nil || executor.auditor == nil {
		return errors.New("SOURCE_SQL_REAUTHORIZATION_UNAVAILABLE")
	}
	target, err := executor.workspaces.SourceQuery(ctx, access, workspaceID, disclosure.ConnectionID)
	if err != nil {
		return err
	}
	if target.SourceID != disclosure.ConnectionID || target.ScopeRevision != disclosure.ExposedSchemaRevision ||
		target.DatabaseIdentity == "" || target.ActivationStatus != "READY" || !target.TrustVerified {
		return errors.New("SOURCE_SQL_REAUTHORIZATION_MISMATCH")
	}
	matched, matchErr := executor.auditor.GovernedQueryAttemptMatches(ctx, access, workspaceID,
		disclosure.AttemptID, disclosure.ConnectionID, disclosure.SQLHash, disclosure.ResultDigest)
	if matchErr != nil || !matched {
		return errors.New("SOURCE_SQL_REAUTHORIZATION_MISMATCH")
	}
	return nil
}

func (executor *e1aSourceSQL) auditAttempt(ctx context.Context, access database.AccessContext, workspaceID string,
	target workspacerepository.SourceQuerySource, purpose string, attempt governedquery.Attempt, refusalCode string) (string, error) {
	eventID, err := ids.New("gqat")
	if err != nil {
		return "", err
	}
	auditContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	workspace := workspaceID
	principal := access.PrincipalID
	sqlHash := attempt.SQLHash
	if sqlHash == "" {
		sqlHash = "sha256:" + strings.Repeat("0", 64)
	}
	outcome := string(attempt.Outcome)
	if outcome == "" {
		outcome = string(governedquery.OutcomeRejectedStatic)
	}
	revision := target.ScopeRevision
	if revision < 1 {
		revision = 1
	}
	connection := target.SourceID
	metadata := audit.Metadata{
		GovernedQueryConnectionID: &connection, GovernedQueryExposedSchemaRevision: &revision,
		GovernedQuerySQLHash: &sqlHash, GovernedQueryOutcome: &outcome,
	}
	if purpose != "" {
		metadata.GovernedQueryPurpose = &purpose
	}
	auditOutcome := audit.OutcomeFailed
	var errorCode *string
	if refusalCode == "" {
		auditOutcome = audit.OutcomeSuccess
		cost := int64(attempt.CostEstimate)
		rows := int64(attempt.RowCount)
		digest := attempt.ResultDigest
		metadata.GovernedQueryCostEstimate = &cost
		metadata.GovernedQueryRowCount = &rows
		metadata.GovernedQueryResultDigest = &digest
	} else {
		code := refusalCode
		errorCode = &code
	}
	_, err = executor.auditor.Append(auditContext, access, audit.EventInput{
		EventID: eventID, WorkspaceID: &workspace, ActorType: audit.ActorType(access.EffectiveActorKind()),
		ActorPrincipalID: &principal, Action: audit.ActionGovernedQueryAttempted,
		ResourceType: audit.ResourceGovernedQueryAttempt, ResourceID: sqlHash,
		RequestID: access.RequestID, Outcome: auditOutcome, ErrorCode: errorCode,
		Metadata: metadata, OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		return "", err
	}
	return eventID, nil
}

func e1aSourceSQLLimits() governedquery.Limits {
	return governedquery.Limits{StatementTimeout: 30 * time.Second, MaxRows: 1000, MaxResultBytes: 4 << 20, MaxCostEstimate: 1_000_000}
}

func e1aScopedRelations(target workspacerepository.SourceQuerySource) []governedquery.ScopedRelation {
	relations := make([]governedquery.ScopedRelation, 0, len(target.Relations))
	for _, relation := range target.Relations {
		relations = append(relations, governedquery.ScopedRelation{Schema: relation.Schema, Table: relation.Table, Columns: append([]string(nil), relation.Columns...)})
	}
	return relations
}

func e1aSourceSQLRefusalCode(err error) string {
	if err == nil {
		return ""
	}
	switch code := governedquery.CodeOf(err); code {
	case governedquery.CodeSQLRejectedStatic, governedquery.CodeRelationNotInSource, governedquery.CodeCostLimit,
		governedquery.CodeRowLimit, governedquery.CodeTimeout, governedquery.CodeDatabaseRejected,
		governedquery.CodeSourceSQLNotConfigured, governedquery.CodeSourceSQLRateLimited,
		governedquery.CodeSourceSQLConcurrencyLimited:
		return string(code)
	default:
		return string(governedquery.CodeDatabaseRejected)
	}
}

// e1aOpenSourceAdmin opens the synthetic source database as its administrator.
func e1aOpenSourceAdmin(t *testing.T, ctx context.Context, dsn string) *pgx.Conn {
	t.Helper()
	connection, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect source admin: %v", err)
	}
	t.Cleanup(func() { _ = connection.Close(context.Background()) })
	return connection
}
