package analyticsource

import (
	"crypto/sha256"
	"encoding/hex"
	"slices"
	"time"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// The one versioned receipt schema, kind and window basis. The schema string is
// also the digest domain, so a receipt and its digest can never disagree about
// which envelope version they describe.
const (
	scalarReceiptSchema      = "knowvault.analyticsource.live-scalar-receipt.v1"
	scalarReceiptKind        = "LIVE_OBSERVATION"
	scalarReceiptWindowBasis = "CLIENT_READ_CALL"
	scalarReceiptDomain      = scalarReceiptSchema
)

// scalarCompletion is the private result of one completed scalar read: the exact
// reducer proof and the private versioned receipt that binds it to the same
// authorized snapshot. Both fields are unexported and the value is never
// serialized with raw facts, so a caller can observe only the generic zero
// comparison.
type scalarCompletion struct {
	sum     scalarSum
	receipt scalarReceipt
}

// MarshalJSON renders the completion as an opaque empty JSON object so that
// neither the reducer proof nor any retained receipt fact can leak through
// generic JSON logging.
func (scalarCompletion) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// scalarReceipt is one immutable, versioned LIVE_OBSERVATION receipt: a canonical
// envelope of retained semantic provenance and the domain-separated digest of
// that envelope. Every field is a value type, so the receipt owns its exact
// bytes and no later mutation of a read can alter it. It carries no subject
// count, no raw row, no SQL, no credential and no schema, relation or column
// name, and it exposes no constructor or accessor beyond the opaque JSON
// rendering.
type scalarReceipt struct {
	envelope scalarReceiptEnvelope
	digest   string
}

// MarshalJSON renders the receipt as an opaque empty JSON object so that no
// retained semantic fact can leak through generic JSON logging. The canonical
// envelope used for the digest is never a JSON method of this type.
func (scalarReceipt) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// scalarReceiptEnvelope is the canonical semantic projection of one completed
// scalar read. Its json tags are the exact digest input order; the envelope
// contains no digest member, so the digest domain-separates the canonical bytes
// of the whole envelope. It retains only neutral binding and execution facts:
// workspace, source-scope, connection and database identities and revisions,
// configuration and contract hashes, projection and exposure lineage,
// revisions and hashes, and the resolved read facts. It never names a physical
// schema, relation or column, and it never carries a credential or a row.
type scalarReceiptEnvelope struct {
	Schema      string                 `json:"schema"`
	Kind        string                 `json:"kind"`
	WindowBasis string                 `json:"window_basis"`
	Access      scalarReceiptAccess    `json:"access"`
	Workspace   scalarReceiptWorkspace `json:"workspace"`
	Catalog     scalarReceiptCatalog   `json:"catalog"`
	Profile     scalarReceiptProfile   `json:"profile"`
	Metric      scalarReceiptMetric    `json:"metric"`
	Source      scalarReceiptSource    `json:"source"`
	Limits      scalarReceiptLimits    `json:"limits"`
	Snapshot    scalarReceiptSnapshot  `json:"snapshot"`
	Result      scalarReceiptResult    `json:"result"`
	Period      scalarReceiptPeriod    `json:"period"`
	Window      scalarReceiptWindow    `json:"window"`
}

// scalarReceiptAccess is the exact caller access context of the read, with the
// effective actor kind normalized exactly as the access predicate sees it.
type scalarReceiptAccess struct {
	OrganizationID string `json:"organization_id"`
	PrincipalID    string `json:"principal_id"`
	RequestID      string `json:"request_id"`
	ActorKind      string `json:"actor_kind"`
}

// scalarReceiptWorkspace is the retained workspace binding identity.
type scalarReceiptWorkspace struct {
	WorkspaceID                string `json:"workspace_id"`
	WorkspaceRevision          int64  `json:"workspace_revision"`
	WorkspaceConfigurationHash string `json:"workspace_configuration_hash"`
	WorkspaceSourceID          string `json:"workspace_source_id"`
}

// scalarReceiptCatalog is the sealed catalog identity the intent was validated
// against.
type scalarReceiptCatalog struct {
	CatalogID       string `json:"catalog_id"`
	CatalogRevision int64  `json:"catalog_revision"`
	CatalogHash     string `json:"catalog_hash"`
}

// scalarReceiptProfile is the sealed dataset profile identity.
type scalarReceiptProfile struct {
	DatasetID   string `json:"dataset_id"`
	Version     int64  `json:"version"`
	ProfileHash string `json:"profile_hash"`
}

// scalarReceiptMetric is the exact approved measure the read reduced.
type scalarReceiptMetric struct {
	MeasureID  string `json:"measure_id"`
	Reducer    string `json:"reducer"`
	Unit       string `json:"unit"`
	NullPolicy string `json:"null_policy"`
}

// scalarReceiptSource is the retained source binding plus projection and
// exposure execution facts. Schema, relation and column names are deliberately
// absent.
type scalarReceiptSource struct {
	SourceScopeID                string `json:"source_scope_id"`
	SourceScopeRevision          int64  `json:"source_scope_revision"`
	SourceScopeConfigurationHash string `json:"source_scope_configuration_hash"`
	ConnectionID                 string `json:"connection_id"`
	ConnectionRevision           int64  `json:"connection_revision"`
	DatabaseIdentity             string `json:"database_identity"`
	ProjectionLineageID          string `json:"projection_lineage_id"`
	ProjectionRevision           int64  `json:"projection_revision"`
	ProjectionContractHash       string `json:"projection_contract_hash"`
	ExposedSchemaRevision        int64  `json:"exposed_schema_revision"`
	ExposedSchemaHash            string `json:"exposed_schema_hash"`
}

// scalarReceiptLimits is the exact server-owned connector limit set the read
// executed under. The two timeouts retain the exact signed 64-bit nanosecond
// integer of the postgresqlquery.Limits time.Duration, so no sub-millisecond
// rounding can hide a limit change.
type scalarReceiptLimits struct {
	MaxRows              int   `json:"max_rows"`
	MaxColumns           int   `json:"max_columns"`
	MaxFieldBytes        int   `json:"max_field_bytes"`
	MaxRowBytes          int   `json:"max_row_bytes"`
	MaxTotalBytes        int   `json:"max_total_bytes"`
	StatementTimeoutNS   int64 `json:"statement_timeout_ns"`
	TransactionTimeoutNS int64 `json:"transaction_timeout_ns"`
}

// scalarReceiptSnapshot is the exact complete snapshot proof: its validated
// hash, complete coverage, the matched row count and the contributing row count
// the reducer proved. There is deliberately no subject count.
type scalarReceiptSnapshot struct {
	SnapshotHash     string `json:"snapshot_hash"`
	CoverageComplete bool   `json:"coverage_complete"`
	MatchedRows      int64  `json:"matched_rows"`
	ContributingRows int64  `json:"contributing_rows"`
}

// scalarReceiptResult is the exact canonical decimal value of the SUM.
type scalarReceiptResult struct {
	Value string `json:"value"`
}

// scalarReceiptPeriod is the resolved half-open period together with the
// approved time policy it was resolved against.
type scalarReceiptPeriod struct {
	TimeKind          string `json:"time_kind"`
	LogicalType       string `json:"logical_type"`
	ReportingTimezone string `json:"reporting_timezone"`
	SourceTimezone    string `json:"source_timezone"`
	Calendar          string `json:"calendar"`
	Start             string `json:"start"`
	EndExclusive      string `json:"end_exclusive"`
}

// scalarReceiptWindow is the UTC CLIENT_READ_CALL window the executor observed.
type scalarReceiptWindow struct {
	StartedAt   string `json:"started_at"`
	CompletedAt string `json:"completed_at"`
}

// completeScalarRead re-proves one already executed scalar read and, only when
// every retained fact still coheres, publishes the exact reducer proof and one
// private canonical v1 LIVE_OBSERVATION receipt.
//
// It accepts only the read. It revalidates the retained binding, access context,
// server-owned limits and UTC read window, requiring the retained instants to be
// exactly the nonzero, ordered UTC Round(0) representation newScalarRead
// guarantees rather than any merely equivalent instant; it recompiles the retained sealed
// intent against the retained binding.profile and requires the compiled measure
// and identity snapshot ordinals to equal the read's ordinals exactly; it calls
// reduceScalarSum(read) itself; and it requires the reducer proof to still name
// the same snapshot hash and row count. No value, receipt context or snapshot is
// supplied by a caller.
//
// Every refusal returns the exact zero scalarCompletion and the exact unwrapped
// errMismatch, so completion is neither an existence nor an authorization
// oracle.
func completeScalarRead(read ScalarRead) (scalarCompletion, error) {
	if !read.context.binding.valid() || read.context.access.Validate() != nil ||
		read.context.limits.Validate() != nil {
		return scalarCompletion{}, errMismatch
	}
	if read.context.startedAt.IsZero() || read.context.completedAt.IsZero() ||
		read.context.completedAt.Before(read.context.startedAt) ||
		read.context.startedAt != read.context.startedAt.UTC().Round(0) ||
		read.context.completedAt != read.context.completedAt.UTC().Round(0) {
		return scalarCompletion{}, errMismatch
	}
	plan, err := compileScalarReadPlan(read.context.binding.profile, read.context.intent)
	if err != nil || plan.measureOrdinal != read.measureOrdinal ||
		!slices.Equal(plan.identityOrdinals, read.identityOrdinals) {
		return scalarCompletion{}, errMismatch
	}
	sum, err := reduceScalarSum(read)
	if err != nil || !scalarSumMatchesSnapshot(sum, read) {
		return scalarCompletion{}, errMismatch
	}
	receipt, err := newScalarReceipt(read, plan, sum)
	if err != nil {
		return scalarCompletion{}, errMismatch
	}
	return scalarCompletion{sum: sum, receipt: receipt}, nil
}

// scalarSumMatchesSnapshot reports whether one successful reducer proof still
// names the exact snapshot the read retained: the same validated snapshot hash
// and the same matched row count. It is the explicit sum/snapshot coherence
// gate completeScalarRead applies before a receipt can exist.
func scalarSumMatchesSnapshot(sum scalarSum, read ScalarRead) bool {
	return sum.snapshotHash == read.snapshot.SnapshotHash &&
		sum.contributingRows == int64(read.snapshot.RowCount)
}

// newScalarReceipt builds the canonical envelope from the read's own retained
// facts and returns its domain-separated receipt. It re-derives the metric, the
// catalog and dataset identities and the resolved period from the sealed intent
// and the retained profile, so no caller can name them. Every refusal returns
// the exact zero scalarReceipt and errMismatch.
func newScalarReceipt(read ScalarRead, plan scalarReadPlan, sum scalarSum) (scalarReceipt, error) {
	intent := read.context.intent
	binding := read.context.binding
	profile := binding.profile

	measure, measureOK := intent.Measure()
	measureID, idOK := measure.MeasureID()
	measureSpec, found := profile.Measure(measureID)
	catalogID, catalogOK := intent.CatalogID()
	catalogRevision, revisionOK := intent.CatalogRevision()
	catalogHash, hashOK := intent.CatalogHash()
	dataset, datasetOK := intent.Dataset()
	datasetID, datasetIDOK := dataset.DatasetID()
	version, versionOK := dataset.ProfileVersion()
	profileHash, profileHashOK := dataset.ExpectedProfileHash()
	period := plan.read.Period
	timePolicy := profile.Time().Values()
	if !measureOK || !idOK || !found || !catalogOK || !revisionOK || !hashOK || !datasetOK ||
		!datasetIDOK || !versionOK || !profileHashOK || period == nil {
		return scalarReceipt{}, errMismatch
	}
	measureValues := measureSpec.Values()

	envelope := scalarReceiptEnvelope{
		Schema:      scalarReceiptSchema,
		Kind:        scalarReceiptKind,
		WindowBasis: scalarReceiptWindowBasis,
		Access: scalarReceiptAccess{
			OrganizationID: read.context.access.OrganizationID,
			PrincipalID:    read.context.access.PrincipalID,
			RequestID:      read.context.access.RequestID,
			ActorKind:      string(read.context.access.EffectiveActorKind()),
		},
		Workspace: scalarReceiptWorkspace{
			WorkspaceID:                binding.binding.workspaceID,
			WorkspaceRevision:          binding.binding.workspaceRevision,
			WorkspaceConfigurationHash: binding.binding.workspaceConfigurationHash,
			WorkspaceSourceID:          binding.binding.workspaceSourceID,
		},
		Catalog: scalarReceiptCatalog{
			CatalogID: catalogID, CatalogRevision: catalogRevision, CatalogHash: catalogHash,
		},
		Profile: scalarReceiptProfile{
			DatasetID: datasetID, Version: version, ProfileHash: profileHash,
		},
		Metric: scalarReceiptMetric{
			MeasureID: measureID, Reducer: string(measureValues.Reducer),
			Unit: measureValues.Unit, NullPolicy: string(measureValues.NullPolicy),
		},
		Source: scalarReceiptSource{
			SourceScopeID:                binding.binding.sourceScopeID,
			SourceScopeRevision:          binding.binding.sourceScopeRevision,
			SourceScopeConfigurationHash: binding.binding.sourceScopeConfigurationHash,
			ConnectionID:                 binding.binding.connectionID,
			ConnectionRevision:           binding.binding.connectionRevision,
			DatabaseIdentity:             binding.binding.databaseIdentity,
			ProjectionLineageID:          binding.execution.projectionLineageID,
			ProjectionRevision:           binding.execution.projectionRevision,
			ProjectionContractHash:       binding.execution.projectionContractHash,
			ExposedSchemaRevision:        binding.execution.exposedSchemaRevision,
			ExposedSchemaHash:            binding.execution.exposedSchemaHash,
		},
		Limits: scalarReceiptLimits{
			MaxRows:              read.context.limits.MaxRows,
			MaxColumns:           read.context.limits.MaxColumns,
			MaxFieldBytes:        read.context.limits.MaxFieldBytes,
			MaxRowBytes:          read.context.limits.MaxRowBytes,
			MaxTotalBytes:        read.context.limits.MaxTotalBytes,
			StatementTimeoutNS:   int64(read.context.limits.StatementTimeout),
			TransactionTimeoutNS: int64(read.context.limits.TransactionTimeout),
		},
		Snapshot: scalarReceiptSnapshot{
			SnapshotHash:     read.snapshot.SnapshotHash,
			CoverageComplete: read.snapshot.CoverageComplete,
			MatchedRows:      int64(read.snapshot.RowCount),
			ContributingRows: sum.contributingRows,
		},
		Result: scalarReceiptResult{Value: sum.value},
		Period: scalarReceiptPeriod{
			TimeKind:          string(timePolicy.Kind),
			LogicalType:       string(period.LogicalType),
			ReportingTimezone: timePolicy.ReportingTimezone,
			SourceTimezone:    timePolicy.SourceTimezone,
			Calendar:          string(timePolicy.Calendar),
			Start:             period.Start,
			EndExclusive:      period.EndExclusive,
		},
		Window: scalarReceiptWindow{
			StartedAt:   read.context.startedAt.Format(time.RFC3339Nano),
			CompletedAt: read.context.completedAt.Format(time.RFC3339Nano),
		},
	}
	digest, err := scalarReceiptDigest(envelope)
	if err != nil {
		return scalarReceipt{}, errMismatch
	}
	receipt := scalarReceipt{envelope: envelope, digest: digest}
	if !receipt.valid() {
		return scalarReceipt{}, errMismatch
	}
	return receipt, nil
}

// scalarReceiptDigest returns the domain-separated SHA-256 of the canonical JCS
// bytes of one envelope. The domain bytes and a NUL separator precede the
// canonical bytes, so a receipt can never be confused with any other canonical
// digest in the repository. The envelope itself carries no digest member.
func scalarReceiptDigest(envelope scalarReceiptEnvelope) (string, error) {
	canonical, err := canon.CanonicalJSON(envelope)
	if err != nil {
		return "", errMismatch
	}
	hasher := sha256.New()
	hasher.Write([]byte(scalarReceiptDomain))
	hasher.Write([]byte{0})
	hasher.Write(canonical)
	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

// valid reports whether one receipt still names the exact v1 schema and
// recomputes to its retained digest. It is the one validation a holder can
// perform without any raw fact: same envelope means the same digest, and any
// semantic mutation of the envelope means a different one.
func (value scalarReceipt) valid() bool {
	if value.envelope.Schema != scalarReceiptSchema || !scalarSumHashPattern.MatchString(value.digest) {
		return false
	}
	digest, err := scalarReceiptDigest(value.envelope)
	return err == nil && digest == value.digest
}
