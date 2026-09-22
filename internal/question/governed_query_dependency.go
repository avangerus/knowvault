package question

import (
	"bytes"
	"encoding/base64"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/source/canon"
)

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

// validateGovernedQueryToolBinding requires every successful synthetic live
// tool call to have exactly one complete, digest-valid projection and exactly
// one private dependency bound to the same Question Run and result metadata.
// Failed live calls are allowed without a dependency.
func validateGovernedQueryToolBinding(questionRunID string, dependency *governedQueryDependency, record *ToolLoopRecord) bool {
	successes := 0
	var successful liveDataProjection
	if record != nil {
		for _, call := range record.Calls {
			if call.Name != liveDataToolName {
				continue
			}
			if call.Outcome == "REFUSED" {
				if !call.Result.IsError {
					return false
				}
				continue
			}
			if call.Outcome != "SUCCEEDED" || call.Result.IsError || len(call.Result.Structured) == 0 ||
				call.Result.Text != string(call.Result.Structured) || record.Profile.MaxToolResultBytes < 1 ||
				len(call.Result.Structured) > record.Profile.MaxToolResultBytes {
				return false
			}
			projection, ok := decodeLiveDataProjection(call.Result.Structured)
			if !ok {
				return false
			}
			successes++
			successful = projection
		}
	}
	if successes == 0 {
		return dependency == nil
	}
	if successes != 1 || dependency == nil || !dependency.validForRun(questionRunID) {
		return false
	}
	return successful.AttemptID == dependency.attemptID && successful.SQLHash == dependency.sqlHash &&
		successful.ExposedSchemaRevision == dependency.exposedSchemaRevision && successful.ResultDigest == dependency.resultDigest
}
