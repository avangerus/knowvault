package question

import (
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/modelgateway"
	"knowvault.local/verified-workspace/internal/workspacetools"
)

const livePersistenceRunID = "qrun_live_persist"

func livePersistenceFixture(t *testing.T) (liveDataProjection, governedQueryDependency, *ToolLoopRecord) {
	t.Helper()
	projection, payload, ok := projectLiveDataResult(liveDataResultFixture(), 8192)
	if !ok {
		t.Fatal("live fixture did not produce a validated projection")
	}
	dependency := governedQueryDependency{
		questionRunID: livePersistenceRunID, attemptID: projection.AttemptID,
		connectionID: "conn_private_secret", sqlHash: projection.SQLHash,
		exposedSchemaRevision: projection.ExposedSchemaRevision, resultDigest: projection.ResultDigest,
	}
	record := &ToolLoopRecord{Profile: modelgateway.ToolLoopProfile{MaxToolResultBytes: 8192}, Calls: []ToolCallRecord{{
		ID: "live-call-1", Name: liveDataToolName, Arguments: json.RawMessage(`{"question":"count records"}`),
		Outcome: "SUCCEEDED", Result: workspacetools.Result{Text: string(payload), Structured: payload},
	}}}
	return projection, dependency, record
}

func TestGovernedQueryDependencyCodecLegacyAndToolBinding(t *testing.T) {
	legacy, err := marshalStructuredAnswer(livePersistenceRunID, "answer-hash", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeStructuredAnswer(livePersistenceRunID, legacy)
	if err != nil || decoded.governedQueryDependency != nil {
		t.Fatalf("legacy artifact decode = %#v, %v", decoded, err)
	}

	_, dependency, record := livePersistenceFixture(t)
	raw, err := marshalStructuredAnswerWithDependencies(livePersistenceRunID, "answer-hash", nil, nil, nil, nil, &dependency, record)
	if err != nil {
		t.Fatalf("marshal paired successful live call: %v", err)
	}
	decoded, err = decodeStructuredAnswer(livePersistenceRunID, raw)
	if err != nil || decoded.governedQueryDependency == nil || decoded.governedQueryDependency.connectionID != dependency.connectionID {
		t.Fatalf("paired live artifact decode = %#v, %v", decoded, err)
	}
	if !strings.Contains(string(raw), "governed_query_dependency") || strings.Contains(string(raw), dependency.connectionID) || strings.Contains(string(raw), "SELECT private_sql_secret") {
		t.Fatalf("opaque dependency artifact leaked private source details: %s", raw)
	}
	if _, err := marshalStructuredAnswerWithDependencies(livePersistenceRunID, "answer-hash", nil, nil, nil, nil, nil, record); CodeOf(err) != CodeInvalid {
		t.Fatalf("successful live call without dependency error = %v", err)
	}
	if _, err := marshalStructuredAnswerWithDependencies(livePersistenceRunID, "answer-hash", nil, nil, nil, nil, &dependency); CodeOf(err) != CodeInvalid {
		t.Fatalf("dependency without a live call error = %v", err)
	}

	failed := &ToolLoopRecord{Calls: []ToolCallRecord{{Name: liveDataToolName, Outcome: "REFUSED", Result: workspacetools.Result{IsError: true}}}}
	if _, err := marshalStructuredAnswerWithDependencies(livePersistenceRunID, "answer-hash", nil, nil, nil, nil, nil, failed); err != nil {
		t.Fatalf("failed live call needs no dependency: %v", err)
	}
}

func TestGovernedQueryDependencyCodecRefusesMalformedArtifacts(t *testing.T) {
	_, dependency, record := livePersistenceFixture(t)
	validRaw, err := marshalStructuredAnswerWithDependencies(livePersistenceRunID, "answer-hash", nil, nil, nil, nil, &dependency, record)
	if err != nil {
		t.Fatal(err)
	}
	validEncoded, err := encodeGovernedQueryDependency(livePersistenceRunID, dependency)
	if err != nil {
		t.Fatal(err)
	}
	otherRunDependency := dependency
	otherRunDependency.questionRunID = "qrun_live_other"
	otherRunEncoded, err := encodeGovernedQueryDependency(otherRunDependency.questionRunID, otherRunDependency)
	if err != nil {
		t.Fatal(err)
	}
	var encodedString string
	if err := jsonv2.Unmarshal(validEncoded, &encodedString); err != nil {
		t.Fatal(err)
	}
	canonicalDependency, err := base64.StdEncoding.DecodeString(encodedString)
	if err != nil {
		t.Fatal(err)
	}
	var noncanonicalValue jsontext.Value
	noncanonicalBase64 := base64.StdEncoding.EncodeToString(append([]byte(" "), canonicalDependency...))
	noncanonicalValue, err = jsonv2.Marshal(noncanonicalBase64)
	if err != nil {
		t.Fatal(err)
	}

	baseWithoutDependency := removeGovernedDependencyMember(t, validRaw)
	baseWithoutLiveCall, err := marshalStructuredAnswer(livePersistenceRunID, "answer-hash", nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	malformedID := dependency
	malformedID.connectionID = "invalid connection"
	malformedIDEncoded, err := encodeInvalidGovernedDependencyForTest(malformedID)
	if err != nil {
		t.Fatal(err)
	}
	badAttemptDependency := dependency
	badAttemptDependency.attemptID = "gqat_../other"
	badAttemptEncoded, err := encodeInvalidGovernedDependencyForTest(badAttemptDependency)
	if err != nil {
		t.Fatal(err)
	}
	badHashDependency := dependency
	badHashDependency.sqlHash = "sha256:ABC"
	badHashEncoded, err := encodeInvalidGovernedDependencyForTest(badHashDependency)
	if err != nil {
		t.Fatal(err)
	}
	badDigestDependency := dependency
	badDigestDependency.resultDigest = "sha256:bad"
	badDigestEncoded, err := encodeInvalidGovernedDependencyForTest(badDigestDependency)
	if err != nil {
		t.Fatal(err)
	}
	badRevisionDependency := dependency
	badRevisionDependency.exposedSchemaRevision = 0
	badRevisionEncoded, err := encodeInvalidGovernedDependencyForTest(badRevisionDependency)
	if err != nil {
		t.Fatal(err)
	}
	badRunDependency := dependency
	badRunDependency.questionRunID = "not a run id"
	badRunEncoded, err := encodeInvalidGovernedDependencyForTest(badRunDependency)
	if err != nil {
		t.Fatal(err)
	}

	for _, example := range []struct {
		name string
		raw  []byte
	}{
		{name: "half dependency absent for successful call", raw: baseWithoutDependency},
		{name: "dependency without successful call", raw: addGovernedDependencyMember(t, baseWithoutLiveCall, validEncoded)},
		{name: "explicit null", raw: addGovernedDependencyMember(t, baseWithoutDependency, jsontext.Value(`null`))},
		{name: "malformed encoding", raw: addGovernedDependencyMember(t, baseWithoutDependency, jsontext.Value(`"not-base64"`))},
		{name: "noncanonical dependency JSON", raw: addGovernedDependencyMember(t, baseWithoutDependency, noncanonicalValue)},
		{name: "run mismatch", raw: addGovernedDependencyMember(t, baseWithoutDependency, otherRunEncoded)},
		{name: "invalid connection id", raw: addGovernedDependencyMember(t, baseWithoutDependency, malformedIDEncoded)},
		{name: "invalid attempt id", raw: addGovernedDependencyMember(t, baseWithoutDependency, badAttemptEncoded)},
		{name: "invalid SQL hash", raw: addGovernedDependencyMember(t, baseWithoutDependency, badHashEncoded)},
		{name: "invalid result digest", raw: addGovernedDependencyMember(t, baseWithoutDependency, badDigestEncoded)},
		{name: "invalid exposed schema revision", raw: addGovernedDependencyMember(t, baseWithoutDependency, badRevisionEncoded)},
		{name: "invalid dependency run id", raw: addGovernedDependencyMember(t, baseWithoutDependency, badRunEncoded)},
		{name: "unknown top-level member", raw: addUnknownStructuredMember(t, validRaw)},
		{name: "duplicate top-level member", raw: duplicateStructuredMember(t, validRaw)},
	} {
		t.Run(example.name, func(t *testing.T) {
			decoded, err := decodeStructuredAnswer(livePersistenceRunID, example.raw)
			if CodeOf(err) != CodeUnavailable || !reflect.DeepEqual(decoded, structuredAnswer{}) {
				t.Fatalf("malformed live artifact exposed data: answer=%#v err=%v", decoded, err)
			}
		})
	}
}

func TestGovernedQueryToolBindingRejectsTamperAndMultipleSuccesses(t *testing.T) {
	projection, dependency, record := livePersistenceFixture(t)
	if !validateGovernedQueryToolBinding(livePersistenceRunID, &dependency, record) {
		t.Fatal("exact successful live call did not bind")
	}

	second := record.Calls[0]
	recordWithTwo := &ToolLoopRecord{Calls: []ToolCallRecord{record.Calls[0], second}}
	if validateGovernedQueryToolBinding(livePersistenceRunID, &dependency, recordWithTwo) {
		t.Fatal("two successful live calls bound to one dependency")
	}

	changed := projection
	changed.Rows = [][]*string{{stringPointer("tampered"), stringPointer("1")}}
	changedRaw, err := json.Marshal(changed)
	if err != nil {
		t.Fatal(err)
	}
	tampered := &ToolLoopRecord{Calls: []ToolCallRecord{{
		ID: "live-call-1", Name: liveDataToolName, Outcome: "SUCCEEDED",
		Result: workspacetools.Result{Text: string(changedRaw), Structured: changedRaw},
	}}}
	if validateGovernedQueryToolBinding(livePersistenceRunID, &dependency, tampered) {
		t.Fatal("tampered table with the original result digest bound")
	}

	wrongDependency := dependency
	wrongDependency.attemptID = "gqat_01ARZ3NDEKTSV4RRFFQ69G5FAV_OTHER"
	if validateGovernedQueryToolBinding(livePersistenceRunID, &wrongDependency, record) {
		t.Fatal("dependency for a different attempt bound")
	}
}

func TestLiveTableAnswerResultCarriesReceiptWithoutRows(t *testing.T) {
	projection, dependency, _ := livePersistenceFixture(t)
	answer, err := liveDataAnswerResult(livePersistenceRunID, liveDataExecution{projection: projection, dependency: dependency})
	if err != nil {
		t.Fatal(err)
	}
	if answer.Kind != "LIVE_TABLE" || answer.Operation != "GOVERNED_READ" || answer.Snapshot.RowCount != 1 ||
		answer.Completeness != "COMPLETE" || answer.ExecutionID != projection.AttemptID ||
		answer.ResultDigest != projection.ResultDigest || answer.CanonicalDigest() != projection.ResultDigest || answer.ReceiptDigest == "" || answer.ObservationWindow == nil ||
		answer.ObservationWindow.Basis != "SERVER_GOVERNED_QUERY_EXECUTION" || len(answer.Keys) != 0 || answer.Value != "" {
		t.Fatalf("live table receipt = %#v", answer)
	}
	encoded, err := json.Marshal(answer)
	if err != nil || strings.Contains(string(encoded), "private_row_value") || strings.Contains(string(encoded), "conn_private_secret") {
		t.Fatalf("answer receipt included rows or connection id: %s, err=%v", encoded, err)
	}
	zeroResult := liveDataResultFixture()
	zeroResult.Rows, zeroResult.RowCount = nil, 0
	zeroResult.ResultDigest = "sha256:cb4866cde14981d9bcf537b509093aad146e66bfb2aa1df1c6a90f2a62d56ce6"
	zeroProjection, _, ok := projectLiveDataResult(zeroResult, 8192)
	if !ok {
		t.Fatal("zero-row complete table was refused")
	}
	zeroDependency := dependency
	zeroDependency.resultDigest = zeroProjection.ResultDigest
	zeroAnswer, err := liveDataAnswerResult(livePersistenceRunID, liveDataExecution{projection: zeroProjection, dependency: zeroDependency})
	if err != nil || zeroAnswer.Snapshot.RowCount != 0 || zeroAnswer.Completeness != "COMPLETE" {
		t.Fatalf("zero-row receipt = %#v, err=%v", zeroAnswer, err)
	}
}

func TestLiveDependencyStaysOutOfPublicReflectionAndJSON(t *testing.T) {
	for _, typeValue := range []reflect.Type{reflect.TypeOf(Run{}), reflect.TypeOf(ToolLoopRecord{}), reflect.TypeOf(AnswerResult{})} {
		for _, forbidden := range []string{"GovernedQueryDependency", "ConnectionID", "SQL"} {
			if _, ok := typeValue.FieldByName(forbidden); ok {
				t.Fatalf("public type %s exposes %s", typeValue, forbidden)
			}
		}
	}
	_, dependency, record := livePersistenceFixture(t)
	dependencyType := reflect.TypeOf(dependency)
	for index := 0; index < dependencyType.NumField(); index++ {
		if dependencyType.Field(index).PkgPath == "" {
			t.Fatalf("private dependency field %q is exported", dependencyType.Field(index).Name)
		}
	}
	dependencyJSON, err := json.Marshal(dependency)
	if err != nil || string(dependencyJSON) != "{}" {
		t.Fatalf("generic dependency JSON was not inert: %s, err=%v", dependencyJSON, err)
	}
	if _, err := marshalStructuredAnswerWithDependencies(livePersistenceRunID, "answer-hash", nil, nil, nil, nil, &dependency, record); err != nil {
		t.Fatal(err)
	}
	publicRun, err := json.Marshal(Run{ID: livePersistenceRunID, ToolLoop: record})
	if err != nil || strings.Contains(string(publicRun), dependency.connectionID) || strings.Contains(string(publicRun), "SELECT private_sql_secret") {
		t.Fatalf("public Run JSON leaked private live-query data: %s, err=%v", publicRun, err)
	}
}

func addGovernedDependencyMember(t *testing.T, raw []byte, value jsontext.Value) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["governed_query_dependency"] = append(json.RawMessage(nil), value...)
	result, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func removeGovernedDependencyMember(t *testing.T, raw []byte) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	delete(object, "governed_query_dependency")
	result, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func addUnknownStructuredMember(t *testing.T, raw []byte) []byte {
	t.Helper()
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		t.Fatal(err)
	}
	object["future_dependency"] = json.RawMessage(`true`)
	result, err := json.Marshal(object)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func duplicateStructuredMember(t *testing.T, raw []byte) []byte {
	t.Helper()
	trimmed := strings.TrimSuffix(strings.TrimSpace(string(raw)), "}")
	return []byte(trimmed + `,"governed_query_dependency":null}`)
}

func encodeInvalidGovernedDependencyForTest(dependency governedQueryDependency) (jsontext.Value, error) {
	wire := governedQueryDependencyWire{
		QuestionRunID: dependency.questionRunID, AttemptID: dependency.attemptID,
		ConnectionID: dependency.connectionID, SQLHash: dependency.sqlHash,
		ExposedSchemaRevision: dependency.exposedSchemaRevision, ResultDigest: dependency.resultDigest,
	}
	raw, err := jsonv2.Marshal(wire)
	if err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, err
	}
	raw, err = json.Marshal(object)
	if err != nil {
		return nil, err
	}
	canonical, err := jsonv2.Marshal(base64.StdEncoding.EncodeToString(raw))
	return jsontext.Value(canonical), err
}
