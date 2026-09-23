package question

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"math/big"
	"reflect"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/metriccompare"
	"knowvault.local/verified-workspace/internal/source/canon"
)

// The encrypted call record retains the original two-row observation while
// the model receives only the concise metric comparison.
func decodeTrustedMetricProjection(questionRunID string, raw json.RawMessage, evidence *liveDataProjection) (liveDataProjection, bool) {
	var result metricToolResult
	if err := jsonv2.Unmarshal(raw, &result, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil ||
		!validGovernedID(result.MetricID) || result.Unit == "" || len(result.Unit) > 128 ||
		result.Coverage != metriccompare.ObservedSnapshot || result.First.Date == result.Second.Date ||
		evidence == nil || result.AttemptID != evidence.AttemptID || result.ReceiptDigest != evidence.ReceiptDigest {
		return liveDataProjection{}, false
	}
	projectionBytes, err := json.Marshal(evidence)
	if err != nil {
		return liveDataProjection{}, false
	}
	projection, ok := decodeLiveDataProjection(projectionBytes)
	receiptDigest, receiptErr := liveDataReceiptDigest(questionRunID, projection)
	if !ok || receiptErr != nil || receiptDigest != result.ReceiptDigest {
		return liveDataProjection{}, false
	}
	if !ok || !comparisonMatchesRows(metriccompare.Comparison{
		First: metriccompare.DailyValue{Date: result.First.Date, SnapshotAt: result.First.SnapshotAt,
			Value: result.First.Value, ContributingRows: result.First.ContributingRows, DistinctSubjects: result.First.DistinctSubjects},
		Second: metriccompare.DailyValue{Date: result.Second.Date, SnapshotAt: result.Second.SnapshotAt,
			Value: result.Second.Value, ContributingRows: result.Second.ContributingRows, DistinctSubjects: result.Second.DistinctSubjects},
	}, projection) {
		return liveDataProjection{}, false
	}
	first, firstOK := new(big.Rat).SetString(result.First.Value)
	second, secondOK := new(big.Rat).SetString(result.Second.Value)
	delta, deltaOK := new(big.Rat).SetString(result.Delta)
	if !firstOK || !secondOK || !deltaOK || new(big.Rat).Sub(first, second).Cmp(delta) != 0 {
		return liveDataProjection{}, false
	}
	if second.Sign() == 0 {
		if result.PercentChange != "" {
			return liveDataProjection{}, false
		}
	} else {
		percent := new(big.Rat).Mul(delta, big.NewRat(100, 1))
		percent.Quo(percent, second)
		if percent.FloatString(2) != result.PercentChange {
			return liveDataProjection{}, false
		}
	}
	return projection, true
}

// governedQueryDependency is the private dependency of a validated live-table
// result. It is serialized only as an opaque member of encrypted
// AnswerStructured and is never projected onto Run or another public type.
type governedQueryDependency struct {
	questionRunID         string
	attemptID             string
	connectionID          string
	sqlHash               string
	exposedSchemaRevision int64
	resultDigest          string
}

type governedQueryDependencyWire struct {
	QuestionRunID         string `json:"question_run_id"`
	AttemptID             string `json:"attempt_id"`
	ConnectionID          string `json:"connection_id"`
	SQLHash               string `json:"sql_hash"`
	ExposedSchemaRevision int64  `json:"exposed_schema_revision"`
	ResultDigest          string `json:"result_digest"`
}

func (dependency governedQueryDependency) validForRun(questionRunID string) bool {
	return validOpaque(questionRunID) && dependency.questionRunID == questionRunID &&
		validOpaque(dependency.questionRunID) && validGovernedID(dependency.attemptID) &&
		strings.HasPrefix(dependency.attemptID, "gqat_") && validGovernedID(dependency.connectionID) &&
		validGovernedSHA256(dependency.sqlHash) && dependency.exposedSchemaRevision > 0 &&
		validGovernedSHA256(dependency.resultDigest)
}

func validGovernedID(value string) bool {
	if value == "" || len(value) > 200 || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("_-.:", character) {
			continue
		}
		return false
	}
	return true
}

func validGovernedSHA256(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// encodeGovernedQueryDependency emits one JSON string whose value is standard
// padded base64 of the canonical dependency JSON. The clear dependency fields
// never pass through the generic structured-answer marshaler.
func encodeGovernedQueryDependency(questionRunID string, dependency governedQueryDependency) (jsontext.Value, error) {
	if !dependency.validForRun(questionRunID) {
		return nil, &Error{code: CodeInvalid}
	}
	wire := governedQueryDependencyWire{
		QuestionRunID: dependency.questionRunID, AttemptID: dependency.attemptID,
		ConnectionID: dependency.connectionID, SQLHash: dependency.sqlHash,
		ExposedSchemaRevision: dependency.exposedSchemaRevision, ResultDigest: dependency.resultDigest,
	}
	raw, err := canon.CanonicalJSON(wire)
	if err != nil || len(raw) == 0 {
		return nil, &Error{code: CodeInvalid}
	}
	encoded, err := jsonv2.Marshal(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		return nil, &Error{code: CodeInvalid}
	}
	return jsontext.Value(encoded), nil
}

func encodeGovernedQueryDependencies(questionRunID string, dependencies []governedQueryDependency) (jsontext.Value, error) {
	if !validOpaque(questionRunID) || len(dependencies) == 0 || len(dependencies) > liveDataMaxSuccessfulCalls {
		return nil, &Error{code: CodeInvalid}
	}
	wire := make([]governedQueryDependencyWire, 0, len(dependencies))
	seen := make(map[string]struct{}, len(dependencies))
	for _, dependency := range dependencies {
		if !dependency.validForRun(questionRunID) {
			return nil, &Error{code: CodeInvalid}
		}
		if _, duplicate := seen[dependency.attemptID]; duplicate {
			return nil, &Error{code: CodeInvalid}
		}
		seen[dependency.attemptID] = struct{}{}
		wire = append(wire, governedQueryDependencyWire{
			QuestionRunID: dependency.questionRunID, AttemptID: dependency.attemptID,
			ConnectionID: dependency.connectionID, SQLHash: dependency.sqlHash,
			ExposedSchemaRevision: dependency.exposedSchemaRevision, ResultDigest: dependency.resultDigest,
		})
	}
	raw, err := canon.CanonicalJSON(wire)
	if err != nil || len(raw) == 0 {
		return nil, &Error{code: CodeInvalid}
	}
	encoded, err := jsonv2.Marshal(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		return nil, &Error{code: CodeInvalid}
	}
	return jsontext.Value(encoded), nil
}

func decodeGovernedQueryDependency(questionRunID string, encoded jsontext.Value) (*governedQueryDependency, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	var base64Value string
	if err := jsonv2.Unmarshal(encoded, &base64Value); err != nil || base64Value == "" {
		return nil, &Error{code: CodeUnavailable}
	}
	canonicalString, err := jsonv2.Marshal(base64Value)
	if err != nil || !bytes.Equal(canonicalString, encoded) {
		return nil, &Error{code: CodeUnavailable}
	}
	raw, err := base64.StdEncoding.DecodeString(base64Value)
	if err != nil || len(raw) == 0 || base64.StdEncoding.EncodeToString(raw) != base64Value {
		return nil, &Error{code: CodeUnavailable}
	}
	var wire governedQueryDependencyWire
	if err := jsonv2.Unmarshal(raw, &wire, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil {
		return nil, &Error{code: CodeUnavailable}
	}
	canonicalJSON, err := canon.CanonicalJSON(wire)
	if err != nil || !bytes.Equal(canonicalJSON, raw) {
		return nil, &Error{code: CodeUnavailable}
	}
	dependency := &governedQueryDependency{
		questionRunID: wire.QuestionRunID, attemptID: wire.AttemptID,
		connectionID: wire.ConnectionID, sqlHash: wire.SQLHash,
		exposedSchemaRevision: wire.ExposedSchemaRevision, resultDigest: wire.ResultDigest,
	}
	if !dependency.validForRun(questionRunID) {
		return nil, &Error{code: CodeUnavailable}
	}
	return dependency, nil
}

func decodeGovernedQueryDependencies(questionRunID string, encoded jsontext.Value) ([]governedQueryDependency, error) {
	if len(encoded) == 0 {
		return nil, nil
	}
	var base64Value string
	if err := jsonv2.Unmarshal(encoded, &base64Value); err != nil || base64Value == "" {
		return nil, &Error{code: CodeUnavailable}
	}
	canonicalString, err := jsonv2.Marshal(base64Value)
	if err != nil || !bytes.Equal(canonicalString, encoded) {
		return nil, &Error{code: CodeUnavailable}
	}
	raw, err := base64.StdEncoding.DecodeString(base64Value)
	if err != nil || len(raw) == 0 || base64.StdEncoding.EncodeToString(raw) != base64Value {
		return nil, &Error{code: CodeUnavailable}
	}
	if raw[0] == '{' {
		legacy, err := decodeGovernedQueryDependency(questionRunID, encoded)
		if err != nil {
			return nil, err
		}
		if legacy == nil {
			return nil, &Error{code: CodeUnavailable}
		}
		return []governedQueryDependency{*legacy}, nil
	}
	var wire []governedQueryDependencyWire
	if err := jsonv2.Unmarshal(raw, &wire, jsonv2.RejectUnknownMembers(true), jsontext.AllowDuplicateNames(false)); err != nil || len(wire) == 0 || len(wire) > liveDataMaxSuccessfulCalls {
		return nil, &Error{code: CodeUnavailable}
	}
	canonicalJSON, err := canon.CanonicalJSON(wire)
	if err != nil || !bytes.Equal(canonicalJSON, raw) {
		return nil, &Error{code: CodeUnavailable}
	}
	dependencies := make([]governedQueryDependency, 0, len(wire))
	seen := make(map[string]struct{}, len(wire))
	for _, item := range wire {
		dependency := governedQueryDependency{
			questionRunID: item.QuestionRunID, attemptID: item.AttemptID,
			connectionID: item.ConnectionID, sqlHash: item.SQLHash,
			exposedSchemaRevision: item.ExposedSchemaRevision, resultDigest: item.ResultDigest,
		}
		if !dependency.validForRun(questionRunID) {
			return nil, &Error{code: CodeUnavailable}
		}
		if _, duplicate := seen[dependency.attemptID]; duplicate {
			return nil, &Error{code: CodeUnavailable}
		}
		seen[dependency.attemptID] = struct{}{}
		dependencies = append(dependencies, dependency)
	}
	return dependencies, nil
}

// governedQueryToolExecutions binds every successful synthetic live tool call
// to its ordered private dependency. Failed calls carry no dependency.
func governedQueryToolExecutions(questionRunID string, dependencies []governedQueryDependency, record *ToolLoopRecord) ([]liveDataExecution, bool, bool) {
	projections := make([]liveDataProjection, 0, len(dependencies))
	if record != nil {
		for _, call := range record.Calls {
			if call.Name != liveDataToolName && call.Name != trustedMetricToolName {
				continue
			}
			if call.Outcome == "REFUSED" {
				if !call.Result.IsError || call.Evidence != nil {
					return nil, false, false
				}
				continue
			}
			if call.Outcome != "SUCCEEDED" || call.Result.IsError || len(call.Result.Structured) == 0 ||
				call.Result.Text != string(call.Result.Structured) || record.Profile.MaxToolResultBytes < 1 ||
				len(call.Result.Structured) > record.Profile.MaxToolResultBytes {
				return nil, false, false
			}
			var projection liveDataProjection
			var ok bool
			if call.Name == trustedMetricToolName {
				projection, ok = decodeTrustedMetricProjection(questionRunID, call.Result.Structured, call.Evidence)
			} else {
				if call.Evidence != nil {
					return nil, false, false
				}
				projection, ok = decodeLiveDataProjection(call.Result.Structured)
			}
			if !ok {
				return nil, false, false
			}
			projections = append(projections, projection)
			if len(projections) > liveDataMaxSuccessfulCalls {
				return nil, false, false
			}
		}
	}
	if len(projections) == 0 {
		return nil, false, len(dependencies) == 0
	}
	if len(projections) != len(dependencies) || len(dependencies) > liveDataMaxSuccessfulCalls {
		return nil, false, false
	}
	executions := make([]liveDataExecution, 0, len(projections))
	seen := make(map[string]struct{}, len(dependencies))
	for index, projection := range projections {
		dependency := dependencies[index]
		if !dependency.validForRun(questionRunID) || projection.AttemptID != dependency.attemptID ||
			projection.SQLHash != dependency.sqlHash || projection.ExposedSchemaRevision != dependency.exposedSchemaRevision ||
			projection.ResultDigest != dependency.resultDigest {
			return nil, false, false
		}
		if _, duplicate := seen[dependency.attemptID]; duplicate {
			return nil, false, false
		}
		seen[dependency.attemptID] = struct{}{}
		executions = append(executions, liveDataExecution{projection: projection, dependency: dependency})
	}
	return executions, true, true
}

// governedQueryToolProjection keeps the former singleton helper for callers
// and tests that still exercise one-result artifacts.
func governedQueryToolProjection(questionRunID string, dependency *governedQueryDependency, record *ToolLoopRecord) (liveDataProjection, bool, bool) {
	var dependencies []governedQueryDependency
	if dependency != nil {
		dependencies = []governedQueryDependency{*dependency}
	}
	executions, successful, valid := governedQueryToolExecutions(questionRunID, dependencies, record)
	if !valid || !successful || len(executions) == 0 {
		return liveDataProjection{}, successful, valid
	}
	return executions[0].projection, true, true
}

func validateGovernedQueryToolBinding(questionRunID string, dependency *governedQueryDependency, record *ToolLoopRecord) bool {
	_, _, valid := governedQueryToolProjection(questionRunID, dependency, record)
	return valid
}

func validateGovernedQueryAnswerResult(questionRunID string, dependency *governedQueryDependency, record *ToolLoopRecord, answerResult *AnswerResult) bool {
	var dependencies []governedQueryDependency
	if dependency != nil {
		dependencies = []governedQueryDependency{*dependency}
	}
	return validateGovernedQueryAnswerResults(questionRunID, dependencies, record, answerResult)
}

func validateGovernedQueryAnswerResults(questionRunID string, dependencies []governedQueryDependency, record *ToolLoopRecord, answerResult *AnswerResult) bool {
	executions, successful, valid := governedQueryToolExecutions(questionRunID, dependencies, record)
	if !valid {
		return false
	}
	if answerResult == nil {
		return true
	}
	if answerResult.Kind != "LIVE_TABLE" {
		return !successful && len(dependencies) == 0
	}
	if !successful || len(executions) == 0 {
		return false
	}
	expected, err := liveDataAnswerResults(questionRunID, executions)
	return err == nil && reflect.DeepEqual(expected, answerResult)
}

func governedQueryAnswerResultAllowedForStatus(status string, dependency *governedQueryDependency, answerResult *AnswerResult, toolLoop *ToolLoopRecord) bool {
	var dependencies []governedQueryDependency
	if dependency != nil {
		dependencies = []governedQueryDependency{*dependency}
	}
	return governedQueryAnswerResultsAllowedForStatus(status, dependencies, answerResult, toolLoop)
}

func governedQueryAnswerResultsAllowedForStatus(status string, dependencies []governedQueryDependency, answerResult *AnswerResult, toolLoop *ToolLoopRecord) bool {
	return len(dependencies) == 0 || answerResult != nil || status != "COMPLETED" ||
		(toolLoop != nil && toolLoop.StopReason == "CLARIFICATION")
}
