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

	filteredCalls    int
	filteredTarget   string
	filteredCred     string
	filteredRequest  postgresqlquery.FilteredProjectionRequest
	filteredLimits   postgresqlquery.Limits
	filteredSnapshot postgresqlquery.Snapshot
	filteredErr      error
	filteredMutate   bool
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

func (connector *authorizedReaderConnector) ReadFilteredProjection(_ context.Context, connection, credential string, request postgresqlquery.FilteredProjectionRequest, limits postgresqlquery.Limits) (postgresqlquery.Snapshot, error) {
	connector.filteredCalls++
	connector.filteredTarget = connection
	connector.filteredCred = credential
	connector.filteredRequest = cloneAuthorizedReaderFilteredRequest(request)
	connector.filteredLimits = limits
	if connector.filteredMutate {
		request.Selection.OutputOrdinals[0] = 99
		request.Selection.IdentityOrdinals[0] = 99
		request.Equalities[0].Value.Text = "mutated"
		request.Equalities = append(request.Equalities, postgresqlquery.EqualityPredicate{Ordinal: 99})
		request.Period.Start = "mutated"
		request.Projection.Columns[0].Name = "mutated"
		request.Projection.Columns[0].Roles[0] = postgresqlquery.RoleTitle
		request.Projection.Columns = append(request.Projection.Columns, postgresqlquery.Column{Name: "forged"})
	}
	return connector.filteredSnapshot, connector.filteredErr
}

func cloneAuthorizedReaderFilteredRequest(request postgresqlquery.FilteredProjectionRequest) postgresqlquery.FilteredProjectionRequest {
	cloned := request
	if request.Selection.OutputOrdinals != nil {
		cloned.Selection.OutputOrdinals = append([]int(nil), request.Selection.OutputOrdinals...)
	}
	if request.Selection.IdentityOrdinals != nil {
		cloned.Selection.IdentityOrdinals = append([]int(nil), request.Selection.IdentityOrdinals...)
	}
	if request.Equalities != nil {
		cloned.Equalities = append([]postgresqlquery.EqualityPredicate(nil), request.Equalities...)
	}
	if request.Period != nil {
		period := *request.Period
		cloned.Period = &period
	}
	if request.Projection.Columns != nil {
		cloned.Projection.Columns = make([]postgresqlquery.Column, len(request.Projection.Columns))
		for index, column := range request.Projection.Columns {
			column.Roles = append([]postgresqlquery.Role(nil), column.Roles...)
			cloned.Projection.Columns[index] = column
		}
	}
	return cloned
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
		if field.PkgPath == "" || strings.Contains(strings.ToLower(field.Name), "credential") {
			t.Fatalf("public result exposes execution target field: %s", field.Name)
		}
	}
	if revision := authority.result.ConnectionRevision(); revision != authorizedReaderConnectionRevision {
		t.Fatalf("ConnectionRevision = %d, want %d", revision, authorizedReaderConnectionRevision)
	}
	if revision := (PostgreSQLAuthorityResult{}).ConnectionRevision(); revision != 0 {
		t.Fatalf("zero result ConnectionRevision = %d, want 0", revision)
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
		{name: "connection revision", mutate: func(value *postgreSQLExecutionAuthority) { value.result.connectionRevision++ }},
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

func TestPostgreSQLAuthorizedReaderReadFilteredBoundStableAuthorityReadsExactlyOnce(t *testing.T) {
	authority := authorizedReaderAuthority()
	wantSnapshot := postgresqlquery.Snapshot{RowCount: 1, DecodedBytes: 17, CoverageComplete: true, SnapshotHash: "sha256:snapshot"}
	connector := &authorizedReaderConnector{filteredSnapshot: wantSnapshot, filteredMutate: true}
	reader, resolveCalls := authorizedReaderWithSequence(connector, authority, authority)

	read := authorizedReaderFilteredRead()
	got, err := reader.ReadFilteredBound(context.Background(), authorizedReaderAccess(), PostgreSQLAuthorityRequest{}, authority.result, read)
	if err != nil {
		t.Fatalf("read filtered bound: %v", err)
	}
	if !reflect.DeepEqual(got, wantSnapshot) {
		t.Fatalf("snapshot = %#v, want %#v", got, wantSnapshot)
	}
	if connector.filteredCalls != 1 || connector.calls != 0 {
		t.Fatalf("connector calls: filtered=%d unfiltered=%d, want 1/0", connector.filteredCalls, connector.calls)
	}
	if connector.filteredTarget != authority.connectionID || connector.filteredCred != authority.credentialReference {
		t.Fatalf("connector target drifted: target=%q credential=%q", connector.filteredTarget, connector.filteredCred)
	}
	if *resolveCalls != 2 {
		t.Fatalf("authority resolutions = %d, want 2", *resolveCalls)
	}
	if !reflect.DeepEqual(connector.filteredRequest.Projection, authority.result.projection) || connector.filteredLimits != authority.result.limits {
		t.Fatalf("connector did not receive authority-owned projection/limits")
	}
	if !reflect.DeepEqual(connector.filteredRequest.Selection, read.Selection) ||
		!reflect.DeepEqual(connector.filteredRequest.Equalities, read.Equalities) ||
		!reflect.DeepEqual(connector.filteredRequest.Period, read.Period) {
		t.Fatalf("connector received wrong filtered semantics: %#v", connector.filteredRequest)
	}
	if connector.filteredRequest.Period == read.Period {
		t.Fatalf("connector shares the caller period pointer")
	}
	if len(read.Selection.OutputOrdinals) == 0 || len(connector.filteredRequest.Selection.OutputOrdinals) == 0 ||
		&connector.filteredRequest.Selection.OutputOrdinals[0] == &read.Selection.OutputOrdinals[0] {
		t.Fatalf("connector shares the caller selection slice")
	}
	if authority.result.projection.Columns[0].Name != "object_id" || authority.result.projection.Columns[0].Roles[0] != postgresqlquery.RoleIdentity || len(authority.result.projection.Columns) != 2 {
		t.Fatalf("connector mutated retained authority: %#v", authority.result.projection)
	}
	assertAuthorizedReaderFilteredReadUnmutated(t, read)
}

func TestPostgreSQLAuthorizedReaderReadFilteredBoundRefusesBeforeConnector(t *testing.T) {
	tests := []struct {
		name     string
		expected func(postgreSQLExecutionAuthority) PostgreSQLAuthorityResult
	}{
		{name: "zero expected", expected: func(postgreSQLExecutionAuthority) PostgreSQLAuthorityResult {
			return PostgreSQLAuthorityResult{}
		}},
		{name: "wrong organization", expected: func(authority postgreSQLExecutionAuthority) PostgreSQLAuthorityResult {
			authority.result.organizationID = "organization_other"
			return authority.result
		}},
		{name: "projection drift", expected: func(authority postgreSQLExecutionAuthority) PostgreSQLAuthorityResult {
			authority.result.projection.RelationName = "other_view"
			return authority.result
		}},
		{name: "limits drift", expected: func(authority postgreSQLExecutionAuthority) PostgreSQLAuthorityResult {
			authority.result.limits.MaxRows++
			return authority.result
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := authorizedReaderAuthority()
			connector := &authorizedReaderConnector{filteredSnapshot: postgresqlquery.Snapshot{RowCount: 4}}
			reader, resolveCalls := authorizedReaderWithSequence(connector, before)
			got, err := reader.ReadFilteredBound(context.Background(), authorizedReaderAccess(), PostgreSQLAuthorityRequest{}, test.expected(before), authorizedReaderFilteredRead())
			assertAuthorizedReaderFailure(t, got, err, CodeNotFound)
			if connector.filteredCalls != 0 || connector.calls != 0 {
				t.Fatalf("connector calls: filtered=%d unfiltered=%d, want 0/0", connector.filteredCalls, connector.calls)
			}
			if *resolveCalls != 1 {
				t.Fatalf("authority resolutions = %d, want 1", *resolveCalls)
			}
		})
	}
}

func TestPostgreSQLAuthorizedReaderReadFilteredBoundFailsClosed(t *testing.T) {
	base := authorizedReaderAuthority()
	tests := []struct {
		name            string
		first           postgreSQLExecutionAuthority
		firstErr        error
		second          postgreSQLExecutionAuthority
		secondErr       error
		connectorErr    error
		wantCode        ErrorCode
		wantFilterCalls int
	}{
		{name: "initial denial", firstErr: &Error{code: CodeNotFound}, wantCode: CodeNotFound},
		{name: "post read denial", first: base, secondErr: &Error{code: CodeNotFound}, wantCode: CodeNotFound, wantFilterCalls: 1},
		{name: "leaky connector", first: base, connectorErr: errors.New("postgres://secret@db SELECT private"), wantCode: CodePersistence, wantFilterCalls: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			connector := &authorizedReaderConnector{filteredSnapshot: postgresqlquery.Snapshot{RowCount: 9}, filteredErr: test.connectorErr}
			reader, resolveCalls := authorizedReaderWithOutcomes(connector, test.first, test.firstErr, test.second, test.secondErr)
			got, err := reader.ReadFilteredBound(context.Background(), authorizedReaderAccess(), PostgreSQLAuthorityRequest{}, base.result, authorizedReaderFilteredRead())
			assertAuthorizedReaderFailure(t, got, err, test.wantCode)
			if connector.filteredCalls != test.wantFilterCalls || connector.calls != 0 {
				t.Fatalf("connector calls: filtered=%d unfiltered=%d, want %d/0", connector.filteredCalls, connector.calls, test.wantFilterCalls)
			}
			wantResolveCalls := 1
			if test.wantFilterCalls == 1 && test.connectorErr == nil {
				wantResolveCalls = 2
			}
			if *resolveCalls != wantResolveCalls {
				t.Fatalf("authority resolutions = %d, want %d", *resolveCalls, wantResolveCalls)
			}
		})
	}
}

func TestPostgreSQLAuthorizedReaderReadFilteredBoundRejectsPostReadTargetDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*postgreSQLExecutionAuthority)
	}{
		{name: "connection", mutate: func(value *postgreSQLExecutionAuthority) { value.connectionID = "connection_other" }},
		{name: "credential", mutate: func(value *postgreSQLExecutionAuthority) { value.credentialReference = "cred_other" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			before := authorizedReaderAuthority()
			after := authorizedReaderAuthority()
			test.mutate(&after)
			connector := &authorizedReaderConnector{filteredSnapshot: postgresqlquery.Snapshot{RowCount: 4}}
			reader, resolveCalls := authorizedReaderWithSequence(connector, before, after)
			got, err := reader.ReadFilteredBound(context.Background(), authorizedReaderAccess(), PostgreSQLAuthorityRequest{}, before.result, authorizedReaderFilteredRead())
			assertAuthorizedReaderFailure(t, got, err, CodeNotFound)
			if connector.filteredCalls != 1 {
				t.Fatalf("connector calls = %d, want 1", connector.filteredCalls)
			}
			if *resolveCalls != 2 {
				t.Fatalf("authority resolutions = %d, want 2", *resolveCalls)
			}
		})
	}
}

func TestPostgreSQLAuthorizedReaderReadFilteredRequestIsSemanticOnly(t *testing.T) {
	requestType := reflect.TypeOf(PostgreSQLFilteredRead{})
	wantFields := []struct {
		name string
		typ  reflect.Type
	}{
		{name: "Selection", typ: reflect.TypeOf(postgresqlquery.ScalarReadSelection{})},
		{name: "Equalities", typ: reflect.TypeOf([]postgresqlquery.EqualityPredicate(nil))},
		{name: "Period", typ: reflect.TypeOf((*postgresqlquery.HalfOpenPeriod)(nil))},
	}
	if requestType.NumField() != len(wantFields) {
		t.Fatalf("PostgreSQLFilteredRead has %d fields, want %d", requestType.NumField(), len(wantFields))
	}
	for index, want := range wantFields {
		field := requestType.Field(index)
		if field.Name != want.name || field.PkgPath != "" || field.Type != want.typ {
			t.Fatalf("field %d = %s %s (exported=%t), want %s %s", index, field.Name, field.Type, field.PkgPath == "", want.name, want.typ)
		}
	}
	for _, forbidden := range []string{"projection", "sql", "schema", "relation", "connection", "credential", "limit", "target"} {
		for index := 0; index < requestType.NumField(); index++ {
			if strings.Contains(strings.ToLower(requestType.Field(index).Name), forbidden) {
				t.Fatalf("PostgreSQLFilteredRead field %q exposes physical target term %q", requestType.Field(index).Name, forbidden)
			}
		}
	}
}

func authorizedReaderFilteredRead() PostgreSQLFilteredRead {
	return PostgreSQLFilteredRead{
		Selection: postgresqlquery.ScalarReadSelection{
			OutputOrdinals:   []int{1, 2},
			IdentityOrdinals: []int{1},
			MeasureOrdinal:   2,
		},
		Equalities: []postgresqlquery.EqualityPredicate{
			{Ordinal: 2, Value: postgresqlquery.ScalarArgument{LogicalType: postgresqlquery.TypeText, Text: "assigned"}},
		},
		Period: &postgresqlquery.HalfOpenPeriod{Ordinal: 1, LogicalType: postgresqlquery.TypeDate, Start: "2026-09-10", EndExclusive: "2026-09-11"},
	}
}

func assertAuthorizedReaderFilteredReadUnmutated(t *testing.T, read PostgreSQLFilteredRead) {
	t.Helper()
	if !reflect.DeepEqual(read.Selection.OutputOrdinals, []int{1, 2}) ||
		!reflect.DeepEqual(read.Selection.IdentityOrdinals, []int{1}) ||
		read.Selection.MeasureOrdinal != 2 {
		t.Fatalf("caller selection mutated: %#v", read.Selection)
	}
	if len(read.Equalities) != 1 || read.Equalities[0].Value.Text != "assigned" {
		t.Fatalf("caller equalities mutated: %#v", read.Equalities)
	}
	if read.Period == nil || read.Period.Start != "2026-09-10" || read.Period.EndExclusive != "2026-09-11" {
		t.Fatalf("caller period mutated: %#v", read.Period)
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

// authorizedReaderConnectionRevision is the exact connection revision the
// fixture resolves, so the envelope comparison and the result accessor are
// both pinned to one value.
const authorizedReaderConnectionRevision int64 = 5

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
			organizationID: "organization_001",
			workspaceID:    "workspace_001", workspaceRevision: 7, workspaceConfigHash: "sha256:workspace",
			workspaceSourceID: "binding_001", sourceScopeID: "scope_001", sourceScopeRevision: 3,
			scopeConfigHash: "sha256:scope", accessMode: authorityAccessModeManaged,
			connectionRevision: authorizedReaderConnectionRevision,
			projection:         projection, limits: limits,
		},
		connectionID: projection.ConnectionID, credentialReference: "cred_01ARZ3NDEKTSV4RRFFQ69G5FAV",
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
