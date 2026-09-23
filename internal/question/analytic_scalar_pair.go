package question

import (
	"bytes"
	"encoding/base64"
	jsontext "encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"knowvault.local/verified-workspace/internal/analyticsource"
)

// analyticScalarPair is the one inseparable private value of a live scalar
// observation and its opaque dependency. It exists only as a whole: the
// observation DTO and the sealed dependency are produced together from the same
// sealed analyticsource.ScalarObservation, so a numeric fact can never be
// persisted beside the wrong dependency or with no dependency at all.
//
// The pair exposes no exported field, constructor, getter, method or decoder in
// this card; the two private fields are reachable only from this file, and the
// dependency never leaks through generic JSON.
type analyticScalarPair struct {
	observation analyticScalarObservation
	dependency  analyticsource.ScalarDependency
}

// newAnalyticScalarPairFrom is the one trusted constructor of the pair. It
// accepts only the concrete sealed analyticsource.ScalarObservation, never an
// interface, the detached value struct, model text or caller JSON, so a caller
// cannot manufacture the numeric fact or its dependency.
//
// It derives the Question DTO with newAnalyticScalarObservationFrom, derives the
// dependency with analyticsource.BindScalarDependency from the same sealed
// source, and re-proves the structural binding with
// analyticsource.VerifyScalarDependencyBinding over the DTO's own receipt schema
// and digest. Any refusal returns the exact zero pair plus the content-free
// CodeInvalid error: there is no partial value, fallback, DTO-only constructor,
// interface, getter or exported member.
func newAnalyticScalarPairFrom(
	questionRunID string,
	source analyticsource.ScalarObservation,
) (analyticScalarPair, error) {
	observation, err := newAnalyticScalarObservationFrom(source)
	if err != nil {
		return analyticScalarPair{}, &Error{code: CodeInvalid}
	}
	dependency, err := analyticsource.BindScalarDependency(questionRunID, source)
	if err != nil {
		return analyticScalarPair{}, &Error{code: CodeInvalid}
	}
	if err := analyticsource.VerifyScalarDependencyBinding(
		questionRunID,
		observation.ReceiptSchema,
		observation.ReceiptDigest,
		dependency,
	); err != nil {
		return analyticScalarPair{}, &Error{code: CodeInvalid}
	}
	return analyticScalarPair{observation: observation, dependency: dependency}, nil
}

// encodeAnalyticScalarPair is the artifact encoding boundary. It validates the
// retained observation and re-proves, for the supplied Question Run, that the
// opaque dependency is its exact structural partner; any refusal returns the
// exact zero observation, no artifact bytes and the content-free CodeInvalid.
//
// On acceptance it returns an owned copy of the validated observation and a
// jsontext.Value that is exactly one JSON string containing the standard padded
// base64 of the exact canonical bytes returned by
// analyticsource.EncodeScalarDependency. The dependency is never serialized
// through generic JSON (which would render the opaque empty object), its schema
// is never duplicated, and no decoded private field is exposed.
func encodeAnalyticScalarPair(
	questionRunID string,
	pair analyticScalarPair,
) (analyticScalarObservation, jsontext.Value, error) {
	if !pair.observation.valid() {
		return analyticScalarObservation{}, nil, &Error{code: CodeInvalid}
	}
	if err := analyticsource.VerifyScalarDependencyBinding(
		questionRunID,
		pair.observation.ReceiptSchema,
		pair.observation.ReceiptDigest,
		pair.dependency,
	); err != nil {
		return analyticScalarObservation{}, nil, &Error{code: CodeInvalid}
	}
	raw, err := analyticsource.EncodeScalarDependency(pair.dependency)
	if err != nil || len(raw) == 0 {
		return analyticScalarObservation{}, nil, &Error{code: CodeInvalid}
	}
	encoded, err := jsonv2.Marshal(base64.StdEncoding.EncodeToString(raw))
	if err != nil {
		return analyticScalarObservation{}, nil, &Error{code: CodeInvalid}
	}
	return pair.observation, jsontext.Value(encoded), nil
}

// decodeAnalyticScalarPair is the artifact decoding boundary. The sole legacy
// absence is the pair in which both halves are absent: a nil observation and an
// empty dependency value decode to (nil, nil). Any other missing half refuses,
// as does an explicit null, an empty string, non-string JSON, invalid or
// noncanonical base64, empty bytes, malformed or noncanonical dependency bytes,
// an invalid scalar, a cross-run binding or a cross-receipt binding.
//
// For a present pair it requires exactly one canonical JSON string, decodes
// standard padded base64, requires the bytes to be byte-for-byte the canonical
// base64 of the decoded bytes, then calls analyticsource.DecodeScalarDependency
// unchanged and re-proves the structural binding with the supplied Question Run
// and the decoded scalar's receipt schema and digest. Every refusal returns a
// nil pair plus the content-free CodeUnavailable error. On acceptance it returns
// a private owned pair. This proves structural pairing only and never current
// authorization.
func decodeAnalyticScalarPair(
	questionRunID string,
	observation *analyticScalarObservation,
	encodedDependency jsontext.Value,
) (*analyticScalarPair, error) {
	if observation == nil && len(encodedDependency) == 0 {
		return nil, nil
	}
	if observation == nil || len(encodedDependency) == 0 || !observation.valid() {
		return nil, &Error{code: CodeUnavailable}
	}

	var encoded string
	if err := jsonv2.Unmarshal(encodedDependency, &encoded); err != nil || encoded == "" {
		return nil, &Error{code: CodeUnavailable}
	}
	canonical, err := jsonv2.Marshal(encoded)
	if err != nil || !bytes.Equal(canonical, encodedDependency) {
		return nil, &Error{code: CodeUnavailable}
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || base64.StdEncoding.EncodeToString(raw) != encoded {
		return nil, &Error{code: CodeUnavailable}
	}
	dependency, err := analyticsource.DecodeScalarDependency(raw)
	if err != nil {
		return nil, &Error{code: CodeUnavailable}
	}
	if err := analyticsource.VerifyScalarDependencyBinding(
		questionRunID,
		observation.ReceiptSchema,
		observation.ReceiptDigest,
		dependency,
	); err != nil {
		return nil, &Error{code: CodeUnavailable}
	}
	owned := *observation
	return &analyticScalarPair{observation: owned, dependency: dependency}, nil
}
