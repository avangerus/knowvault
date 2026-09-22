package analyticsource

// ScalarObservation is the sealed, content-free result of one completed scalar
// read that may cross the analyticsource package boundary. Its only state is the
// private completion produced by CompleteScalarRead: the exact reducer proof and
// the private canonical LIVE_OBSERVATION receipt. No exported field, no
// constructor, no decoder and no accessor reach that state, and generic JSON
// renders the observation as the opaque empty object, so a holder can observe
// only the detached semantic projection ScalarObservationValues.
type ScalarObservation struct {
	completion scalarCompletion
}

// MarshalJSON renders the observation as an opaque empty JSON object so that no
// retained private envelope, binding, execution, access or reducer fact can leak
// through generic JSON logging.
func (ScalarObservation) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// ScalarObservationValues is the detached semantic read projection of one
// completed scalar read. Every field is an immutable scalar value, so a returned
// value is a copy that no later mutation can use to reach the sealed
// observation, and no caller-supplied value, provenance, snapshot, receipt or
// digest can enter it. It deliberately carries no subject count, no dependency
// id, no workspace, source, connection or database identity, no raw snapshot or
// snapshot hash, no row, no SQL, no physical schema, relation or column name, no
// credential and no receipt envelope: the retained receipt digest is the only
// receipt fact that crosses this projection.
type ScalarObservationValues struct {
	ReceiptSchema string
	ReceiptKind   string
	WindowBasis   string

	DatasetID      string
	ProfileVersion int64
	ProfileHash    string

	MetricID         string
	MetricReducer    string
	MetricUnit       string
	MetricNullPolicy string

	Value string

	PeriodTimeKind          string
	PeriodLogicalType       string
	PeriodStart             string
	PeriodEndExclusive      string
	PeriodReportingTimezone string
	PeriodSourceTimezone    string
	PeriodCalendar          string

	ContributingRows int64
	CoverageComplete bool

	ObservedStartedAt   string
	ObservedCompletedAt string

	ReceiptDigest string
}

// CompleteScalarRead completes one already-executed scalar read and publishes it
// as a sealed ScalarObservation. It accepts only the read: every semantic fact
// in the published projection is re-derived by the accepted private
// completeScalarRead from the read's own retained intent, binding, limits and
// window, so no caller can supply a value, provenance, snapshot, receipt or
// digest. Every refusal returns the exact zero ScalarObservation and the exact
// unwrapped, content-free errMismatch, so completion is neither an existence nor
// an authorization oracle.
func CompleteScalarRead(read ScalarRead) (ScalarObservation, error) {
	completion, err := completeScalarRead(read)
	if err != nil {
		return ScalarObservation{}, err
	}
	return ScalarObservation{completion: completion}, nil
}

// Values returns the detached semantic projection of one completed scalar read.
// It returns the exact zero ScalarObservationValues and false for zero or
// invalid sealed state: the retained canonical receipt must still recompute to
// its digest and still name the exact reducer proof. The returned value is
// rebuilt from the sealed state on every call, so mutating the returned value,
// the observation's zero value, a previously returned value or the original
// read after completion cannot alter a later projection.
func (observation ScalarObservation) Values() (ScalarObservationValues, bool) {
	completion := observation.completion
	receipt := completion.receipt
	if !receipt.valid() {
		return ScalarObservationValues{}, false
	}
	envelope := receipt.envelope
	if completion.sum.value == "" ||
		completion.sum.value != envelope.Result.Value ||
		completion.sum.contributingRows != envelope.Snapshot.ContributingRows ||
		completion.sum.snapshotHash != envelope.Snapshot.SnapshotHash ||
		!scalarSumHashPattern.MatchString(completion.sum.snapshotHash) {
		return ScalarObservationValues{}, false
	}
	return ScalarObservationValues{
		ReceiptSchema:           envelope.Schema,
		ReceiptKind:             envelope.Kind,
		WindowBasis:             envelope.WindowBasis,
		DatasetID:               envelope.Profile.DatasetID,
		ProfileVersion:          envelope.Profile.Version,
		ProfileHash:             envelope.Profile.ProfileHash,
		MetricID:                envelope.Metric.MeasureID,
		MetricReducer:           envelope.Metric.Reducer,
		MetricUnit:              envelope.Metric.Unit,
		MetricNullPolicy:        envelope.Metric.NullPolicy,
		Value:                   envelope.Result.Value,
		PeriodTimeKind:          envelope.Period.TimeKind,
		PeriodLogicalType:       envelope.Period.LogicalType,
		PeriodStart:             envelope.Period.Start,
		PeriodEndExclusive:      envelope.Period.EndExclusive,
		PeriodReportingTimezone: envelope.Period.ReportingTimezone,
		PeriodSourceTimezone:    envelope.Period.SourceTimezone,
		PeriodCalendar:          envelope.Period.Calendar,
		ContributingRows:        envelope.Snapshot.ContributingRows,
		CoverageComplete:        envelope.Snapshot.CoverageComplete,
		ObservedStartedAt:       envelope.Window.StartedAt,
		ObservedCompletedAt:     envelope.Window.CompletedAt,
		ReceiptDigest:           receipt.digest,
	}, true
}
