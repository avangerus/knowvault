package repository

import (
	"context"
	jsonv2 "encoding/json/v2"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

type authorizedReaderConnector struct {
	calls      int
	connection string
	credential string
	projection postgresqlquery.Projection
	limits     postgresqlquery.Limits
	snapshot   postgresqlquery.Snapshot
	err        error
	mutate     bool
}

func (connector *authorizedReaderConnector) ReadProjection(_ context.Context, connection, credential string, projection postgresqlquery.Projection, limits postgresqlquery.Limits) (postgresqlquery.Snapshot, error) {
	connector.calls++
	connector.connection = connection
	connector.credential = credential
	connector.projection = PostgreSQLAuthorityResult{projection: projection}.Projection()
	connector.limits = limits
	if connector.mutate {
		projection.Columns[0].Name = "mutated"
		projection.Columns[0].Roles[0] = postgresqlquery.RoleTitle
		projection.Columns = append(projection.Columns, postgresqlquery.Column{Name: "forged"})
	}
	return connector.snapshot, connector.err
}

func TestPostgreSQLAuthorizedReaderStableAuthorityReadsExactlyOnce(t *testing.T) {
	authority := authorizedReaderAuthority()
	wantSnapshot := postgresqlquery.Snapshot{RowCount: 1, DecodedBytes: 17, CoverageComplete: true, SnapshotHash: "sha256:snapshot"}
	connector := &authorizedReaderConnector{snapshot: wantSnapshot, mutate: true}
	reader, resolveCalls := authorizedReaderWithSequence(connector, authority, authority)

	got, err := reader.Read(context.Background(), authorizedReaderAccess(), PostgreSQLAuthorityRequest{})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !reflect.DeepEqual(got, wantSnapshot) {
		t.Fatalf("snapshot = %#v, want %#v", got, wantSnapshot)
	}
	if connector.calls != 1 || connector.connection != authority.connectionID || connector.credential != authority.credentialReference {
		t.Fatalf("connector target/calls drifted: calls=%d connection=%q credential=%q", connector.calls, connector.connection, connector.credential)
	}
	if *resolveCalls != 2 {
		t.Fatalf("authority resolutions = %d, want 2", *resolveCalls)
	}
	if !reflect.DeepEqual(connector.projection, authority.result.projection) || connector.limits != authority.result.limits {
		t.Fatalf("connector did not receive authority-owned projection/limits")
	}
	if authority.result.projection.Columns[0].Name != "object_id" || authority.result.projection.Columns[0].Roles[0] != postgresqlquery.RoleIdentity || len(authority.result.projection.Columns) != 2 {
		t.Fatalf("connector mutated retained authority: %#v", authority.result.projection)
	}
	resultType := reflect.TypeOf(authority.result)
	for index := 0; index < resultType.NumField(); index++ {
		field := resultType.Field(index)
		if field.PkgPath == "" || strings.Contains(strings.ToLower(field.Name), "credential") || field.Name == "connectionRevision" {
			t.Fatalf("public result exposes execution target field: %s", field.Name)
		}
	}
	encoded, err := jsonv2.Marshal(authority.result)
	if err != nil || string(encoded) != "{}" {
		t.Fatalf("public result JSON = %q err=%v, want {}", encoded, err)
	}
}

func TestPostgreSQLAuthorizedReaderFailsClosedAroundRead(t *testing.T) {
	base := authorizedReaderAuthority()
	tests := []struct {
		name          string
		first         postgreSQLExecutionAuthority
		firstErr      error
		second        postgreSQLExecutionAuthority
		secondErr     error
		connectorErr  error
		wantCode      ErrorCode
		wantReadCalls int
	}{
		{name: "initial denial", firstErr: &Error{code: CodeNotFound}, wantCode: CodeNotFound},
		{name: "post read denial", first: base, secondErr: &Error{code: CodeNotFound}, wantCode: CodeNotFound, wantReadCalls: 1},
		{name: "leaky connector", first: base, connectorErr: errors.New("postgres://secret@db SELECT private"), wantCode: CodePersistence, wantReadCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connector := &authorizedReaderConnector{snapshot: postgresqlquery.Snapshot{RowCount: 9}, err: test.connectorErr}
			reader, resolveCalls := authorizedReaderWithOutcomes(connector, test.first, test.firstErr, test.second, test.secondErr)
			got, err := reader.Read(context.Background(), authorizedReaderAccess(), PostgreSQLAuthorityRequest{})
			assertAuthorizedReaderFailure(t, got, err, test.wantCode)
			if connector.calls != test.wantReadCalls {
				t.Fatalf("connector calls = %d, want %d", connector.calls, test.wantReadCalls)
			}
			wantResolveCalls := 1
			if test.wantReadCalls == 1 && test.connectorErr == nil {
				wantResolveCalls = 2
			}
			if *resolveCalls != wantResolveCalls {
				t.Fatalf("authority resolutions = %d, want %d", *resolveCalls, wantResolveCalls)
			}
		})
	}
}

func TestPostgreSQLAuthorizedReaderRejectsEveryAuthorityAndTargetDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*postgreSQLExecutionAuthority)
	}{
		{name: "projection", mutate: func(value *postgreSQLExecutionAuthority) { value.result.projection.RelationName = "other_view" }},
		{name: "nested projection roles", mutate: func(value *postgreSQLExecutionAuthority) {
			value.result.projection.Columns[0].Roles[0] = postgresqlquery.RoleTitle
		}},
		{name: "limits", mutate: func(value *postgreSQLExecutionAuthority) { value.result.limits.MaxRows++ }},
		{name: "workspace revision", mutate: func(value *postgreSQLExecutionAuthority) { value.result.workspaceRevision++ }},
		{name: "workspace hash", mutate: func(value *postgreSQLExecutionAuthority) { value.result.workspaceConfigHash = "sha256:other" }},
		{name: "source revision", mutate: func(value *postgreSQLExecutionAuthority) { value.result.sourceScopeRevision++ }},
		{name: "connection id", mutate: func(value *postgreSQLExecutionAuthority) { value.connectionID = "connection_other" }},
		{name: "connection revision", mutate: func(value *postgreSQLExecutionAuthority) { value.connectionRevision++ }},
		{name: "credential", mutate: func(value *postgreSQLExecutionAuthority) { value.credentialReference = "cred_other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := authorizedReaderAuthority()
			after := authorizedReaderAuthority()
			test.mutate(&after)
			connector := &authorizedReaderConnector{snapshot: postgresqlquery.Snapshot{RowCount: 4}}
			reader, resolveCalls := authorizedReaderWithSequence(connector, before, after)
			got, err := reader.Read(context.Background(), authorizedReaderAccess(), PostgreSQLAuthorityRequest{})
			assertAuthorizedReaderFailure(t, got, err, CodeNotFound)
			if connector.calls != 1 {
				t.Fatalf("connector calls = %d, want 1", connector.calls)
			}
			if *resolveCalls != 2 {
				t.Fatalf("authority resolutions = %d, want 2", *resolveCalls)
			}
		})
	}
}

func authorizedReaderWithSequence(connector PostgreSQLProjectionConnector, outcomes ...postgreSQLExecutionAuthority) (*PostgreSQLAuthorizedReader, *int) {
	index := 0
	reader := &PostgreSQLAuthorizedReader{
		connector: connector,
		resolve: func(context.Context, database.AccessContext, PostgreSQLAuthorityRequest) (postgreSQLExecutionAuthority, error) {
			if index >= len(outcomes) {
				return postgreSQLExecutionAuthority{}, &Error{code: CodePersistence}
			}
			outcome := outcomes[index]
			index++
			return outcome, nil
		},
	}
	return reader, &index
}

func authorizedReaderWithOutcomes(connector PostgreSQLProjectionConnector, first postgreSQLExecutionAuthority, firstErr error, second postgreSQLExecutionAuthority, secondErr error) (*PostgreSQLAuthorizedReader, *int) {
	index := 0
	reader := &PostgreSQLAuthorizedReader{
		connector: connector,
		resolve: func(context.Context, database.AccessContext, PostgreSQLAuthorityRequest) (postgreSQLExecutionAuthority, error) {
			index++
			if index == 1 {
				return first, firstErr
			}
			return second, secondErr
		},
	}
	return reader, &index
}

func authorizedReaderAuthority() postgreSQLExecutionAuthority {
	projection := postgresqlquery.Projection{
		ConnectionID:        "connection_001",
		DatabaseIdentity:    "database_001",
		LineageID:           "lineage_001",
		Revision:            3,
		ContractHash:        "sha256:" + strings.Repeat("a", 64),
		SchemaName:          "public",
		RelationName:        "business_view",
		RelationKind:        "VIEW",
		EmptySnapshotPolicy: "AUTHORITATIVE",
		Columns: []postgresqlquery.Column{
			{Ordinal: 1, Name: "object_id", TypeFingerprint: "int8", LogicalType: postgresqlquery.TypeInt, Roles: []postgresqlquery.Role{postgresqlquery.RoleIdentity}, MaxBytes: 32},
			{Ordinal: 2, Name: "description", TypeFingerprint: "text", LogicalType: postgresqlquery.TypeText, Roles: []postgresqlquery.Role{postgresqlquery.RoleEvidence}, Nullable: true, MaxBytes: 1024},
		},
	}
	limits := postgresqlquery.Limits{
		MaxRows: 100, MaxColumns: 2, MaxFieldBytes: 1024, MaxRowBytes: 4096,
		MaxTotalBytes: 1 << 20, StatementTimeout: time.Second, TransactionTimeout: 2 * time.Second,
	}
	return postgreSQLExecutionAuthority{
		result: PostgreSQLAuthorityResult{
			workspaceID: "workspace_001", workspaceRevision: 7, workspaceConfigHash: "sha256:workspace",
			workspaceSourceID: "binding_001", sourceScopeID: "scope_001", sourceScopeRevision: 3,
			scopeConfigHash: "sha256:scope", accessMode: authorityAccessModeManaged,
			projection: projection, limits: limits,
		},
		connectionID: projection.ConnectionID, connectionRevision: 5, credentialReference: "cred_01ARZ3NDEKTSV4RRFFQ69G5FAV",
	}
}

func authorizedReaderAccess() database.AccessContext {
	return database.AccessContext{OrganizationID: "organization_001", PrincipalID: "principal_001", RequestID: "request_001"}
}

func assertAuthorizedReaderFailure(t *testing.T, snapshot postgresqlquery.Snapshot, err error, wantCode ErrorCode) {
	t.Helper()
	if !reflect.DeepEqual(snapshot, postgresqlquery.Snapshot{}) {
		t.Fatalf("failure returned snapshot: %#v", snapshot)
	}
	if err == nil || CodeOf(err) != wantCode || err.Error() != string(wantCode) {
		t.Fatalf("error = %v code=%q, want %q", err, CodeOf(err), wantCode)
	}
	if errors.Unwrap(err) != nil {
		t.Fatalf("failure exposed wrapped cause: %v", errors.Unwrap(err))
	}
	for _, forbidden := range []string{"postgres://", "select ", "credential", "private"} {
		if strings.Contains(strings.ToLower(err.Error()), forbidden) {
			t.Fatalf("failure leaked %q: %q", forbidden, err.Error())
		}
	}
}
