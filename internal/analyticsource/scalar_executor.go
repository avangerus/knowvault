package analyticsource

import (
	"context"
	"encoding/json/jsontext"
	"time"

	"knowvault.local/verified-workspace/internal/analytic"
	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/queryintent"
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/workspace/repository"
)

// ScalarExecutor orchestrates exactly one already-compiled authority-bound
// bounded scalar read. It retains the resolver that proves the mounted profile
// still matches current repository authority, the reader that brackets the one
// bound source read with its own current authority facts, and the clock that
// stamps the client read window. Retaining those dependencies grants nothing:
// the executor holds no credential, no SQL, no projection, no execution handle
// and no resolved authority between calls, and the clock is read only to bracket
// the one read call.
type ScalarExecutor struct {
	resolver *Resolver
	reader   *repository.PostgreSQLAuthorizedReader
	now      func() time.Time
}

// NewScalarExecutor binds one resolver, one authorized reader and the default
// wall clock to an executor. It performs no I/O and calls neither dependency.
// A nil resolver or a nil reader returns nil plus the exact unwrapped
// errMismatch, so no caller can hold an executor missing either half of the one
// bounded read. The clock is set privately to time.Now: it is not a caller seam,
// not a credential and not an authority fact.
func NewScalarExecutor(resolver *Resolver, reader *repository.PostgreSQLAuthorizedReader) (*ScalarExecutor, error) {
	if resolver == nil || reader == nil {
		return nil, errMismatch
	}
	return &ScalarExecutor{resolver: resolver, reader: reader, now: time.Now}, nil
}

// scalarReadContext is the private retained provenance of one already-executed
// bounded scalar read: the sealed intent and eligibility binding that authorized
// it, the exact caller access context, the server-owned connector limits, and the
// read window the executor itself observed.
//
// The window basis is CLIENT_READ_CALL. startedAt and completedAt bracket only
// the reader's own authority checks and its one connector call: they exclude the
// outer resolver calls and they are not a PostgreSQL transaction timestamp, a
// server clock claim, or a receipt. Every field is private and the value is
// never serialized on its own.
type scalarReadContext struct {
	intent      queryintent.ValidatedIntentV2
	binding     eligibilityBinding
	access      database.AccessContext
	limits      postgresqlquery.Limits
	startedAt   time.Time
	completedAt time.Time
}

// ScalarRead is the private result of one executed scalar read: the bounded
// snapshot the reader returned, the Snapshot positions of the measure and
// identity columns, and the retained honest read provenance. Every field is
// unexported, so a caller can observe only the generic zero comparison and the
// opaque MarshalJSON rendering: there is deliberately no constructor, decoder or
// accessor, and nothing here exposes raw rows, SQL, a physical name, projection,
// authority, credential, receipt or reducer result. The retained provenance is a
// copy: mutating the snapshot the reader returned after Execute cannot alter it.
type ScalarRead struct {
	snapshot         postgresqlquery.Snapshot
	measureOrdinal   int
	identityOrdinals []int
	context          scalarReadContext
}

// MarshalJSON renders the scalar read as an opaque empty JSON object so that no
// retained private snapshot, provenance, authority or credential value can leak
// through generic JSON logging.
func (ScalarRead) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// Execute runs the one authority-bound scalar read for one sealed intent. The
// sequence is fixed and fail closed: the receiver, the call context, the
// workspace identity, the caller access context, the private clock and the
// sealed intent are validated first; the resolver selection is derived from the
// sealed intent alone; the current repository authority and exposure facts are
// resolved exactly once and must be valid; the already-approved scalar plan is
// compiled from that resolved profile; the client read window is opened
// immediately before the one bounded filtered read and closed immediately after
// it; and the same resolver selection is resolved a second time exactly once,
// after the read, where it must still be valid and retain exactly the same
// binding. Only then is the snapshot, the read window and the semantic context
// published with detached Snapshot ordinals.
//
// Nothing is retried, cached or parallelized and no fallback exists. Every
// refusal — a malformed input, an invalid access context, a missing clock, a
// resolution failure, a plan failure, a zero or reversed read window, a
// repository read failure or a post-read binding drift — returns the exact zero
// ScalarRead and the exact unwrapped errMismatch, so Execute is neither an
// existence nor an authorization oracle and no repository cause or detail can
// cross this boundary.
func (executor *ScalarExecutor) Execute(
	ctx context.Context,
	access database.AccessContext,
	workspaceID string,
	intent queryintent.ValidatedIntentV2,
) (ScalarRead, error) {
	if executor == nil || executor.resolver == nil || executor.reader == nil || executor.now == nil || ctx == nil {
		return ScalarRead{}, errMismatch
	}
	if access.Validate() != nil {
		return ScalarRead{}, errMismatch
	}
	request, err := scalarExecutorResolveRequest(workspaceID, intent)
	if err != nil {
		return ScalarRead{}, errMismatch
	}
	before, err := executor.resolver.Resolve(ctx, access, request)
	if err != nil || !before.Valid() {
		return ScalarRead{}, errMismatch
	}
	plan, err := compileScalarReadPlan(before.binding.profile, intent)
	if err != nil {
		return ScalarRead{}, errMismatch
	}
	authority := repository.PostgreSQLAuthorityRequest{
		WorkspaceID:         before.binding.binding.workspaceID,
		WorkspaceSourceID:   before.binding.binding.workspaceSourceID,
		SourceScopeID:       before.binding.binding.sourceScopeID,
		ScopeConfigHash:     before.binding.binding.sourceScopeConfigurationHash,
		AccessMode:          repositoryManagedAccessMode,
		SourceScopeRevision: before.binding.binding.sourceScopeRevision,
	}
	started := executor.now()
	if started.IsZero() {
		return ScalarRead{}, errMismatch
	}
	snapshot, err := executor.reader.ReadFilteredBound(ctx, access, authority, before.authority, plan.read)
	completed := executor.now()
	if err != nil {
		return ScalarRead{}, errMismatch
	}
	if completed.IsZero() || completed.Before(started) {
		return ScalarRead{}, errMismatch
	}
	after, err := executor.resolver.Resolve(ctx, access, request)
	if err != nil || !after.Valid() || !after.binding.equal(before.binding) {
		return ScalarRead{}, errMismatch
	}
	return newScalarRead(intent, before.binding, access, before.authority.Limits(), started, completed,
		snapshot, plan.measureOrdinal, plan.identityOrdinals)
}

// newScalarRead is the one private construction and validation boundary for one
// executed scalar read. It requires a valid sealed intent, a valid eligibility
// binding, a valid caller access context, valid server-owned limits, two nonzero
// instants that do not run backwards under their monotonic reading and whose UTC
// wall times also do not run backwards, a complete nonempty snapshot, a positive
// measure Snapshot ordinal and at least one identity Snapshot ordinal. It
// normalizes both retained times to UTC Round(0), so no caller time zone or
// monotonic reading survives, deep-copies the complete snapshot and detaches the
// ordinals, so no later mutation of the connector's result can alter the
// published ScalarRead. Every refusal returns the exact zero ScalarRead and the
// exact unwrapped errMismatch.
func newScalarRead(
	intent queryintent.ValidatedIntentV2,
	binding eligibilityBinding,
	access database.AccessContext,
	limits postgresqlquery.Limits,
	startedAt time.Time,
	completedAt time.Time,
	snapshot postgresqlquery.Snapshot,
	measureOrdinal int,
	identityOrdinals []int,
) (ScalarRead, error) {
	if !intent.Valid() || !binding.valid() || access.Validate() != nil || limits.Validate() != nil {
		return ScalarRead{}, errMismatch
	}
	// Validate the exact received instants first, while any monotonic reading is
	// still attached: a nonzero zero check and a monotonic ordering check that
	// are not observable once Round(0) strips the monotonic clock.
	if startedAt.IsZero() || completedAt.IsZero() || completedAt.Before(startedAt) {
		return ScalarRead{}, errMismatch
	}
	startedAt = startedAt.UTC().Round(0)
	completedAt = completedAt.UTC().Round(0)
	// Round(0) keeps the wall reading and drops the monotonic reading, so the
	// persisted window is re-checked: a client wall clock that ran backwards
	// must never be retained as an ordered read window.
	if completedAt.Before(startedAt) {
		return ScalarRead{}, errMismatch
	}
	if !snapshot.CoverageComplete || snapshot.RowCount <= 0 || len(snapshot.Rows) == 0 ||
		snapshot.RowCount != len(snapshot.Rows) {
		return ScalarRead{}, errMismatch
	}
	if measureOrdinal <= 0 || len(identityOrdinals) == 0 {
		return ScalarRead{}, errMismatch
	}
	return ScalarRead{
		snapshot:         detachedScalarSnapshot(snapshot),
		measureOrdinal:   measureOrdinal,
		identityOrdinals: detachedScalarOrdinals(identityOrdinals),
		context: scalarReadContext{
			intent:      intent,
			binding:     binding,
			access:      access,
			limits:      limits,
			startedAt:   startedAt,
			completedAt: completedAt,
		},
	}, nil
}

// scalarExecutorResolveRequest derives the one resolver selection from the
// sealed intent alone. The workspace identity is the argument the caller named;
// the catalog id, revision and hash and the dataset id, version and hash come
// only from the sealed intent, and the profile key is rebuilt from the sealed
// dataset identity. A malformed workspace, an invalid or forged intent and any
// refused accessor return the exact zero ResolveRequest and the exact unwrapped
// errMismatch; no value is trimmed, case folded, repaired or defaulted.
func scalarExecutorResolveRequest(workspaceID string, intent queryintent.ValidatedIntentV2) (ResolveRequest, error) {
	if !validBindingIdentity(workspaceID) || !intent.Valid() {
		return ResolveRequest{}, errMismatch
	}
	catalogID, catalogOK := intent.CatalogID()
	catalogRevision, revisionOK := intent.CatalogRevision()
	catalogHash, hashOK := intent.CatalogHash()
	dataset, datasetOK := intent.Dataset()
	datasetID, idOK := dataset.DatasetID()
	version, versionOK := dataset.ProfileVersion()
	profileHash, profileHashOK := dataset.ExpectedProfileHash()
	if !catalogOK || !revisionOK || !hashOK || !datasetOK || !idOK || !versionOK || !profileHashOK {
		return ResolveRequest{}, errMismatch
	}
	profileKey, err := analytic.NewProfileKey(datasetID, version)
	if err != nil {
		return ResolveRequest{}, errMismatch
	}
	return ResolveRequest{
		WorkspaceID:     workspaceID,
		CatalogID:       catalogID,
		CatalogRevision: catalogRevision,
		CatalogHash:     catalogHash,
		ProfileKey:      profileKey,
		ProfileHash:     profileHash,
	}, nil
}

// detachedScalarSnapshot returns a deep copy of one bounded snapshot: the Rows
// slice, every row's Values slice, every row's Canonical bytes, and every
// byte-backed ValueEntry.Value ([]byte and jsontext.Value) are freshly
// allocated, so the connector or a caller mutating the original snapshot after
// publication cannot alter the retained ScalarRead. Nil and empty slices stay
// distinct exactly as received.
func detachedScalarSnapshot(snapshot postgresqlquery.Snapshot) postgresqlquery.Snapshot {
	detached := snapshot
	detached.Rows = detachedScalarRows(snapshot.Rows)
	return detached
}

// detachedScalarRows returns a freshly allocated copy of one snapshot's rows and
// their byte-backed members, preserving a nil slice as nil and an empty slice as
// a non-nil empty slice.
func detachedScalarRows(rows []postgresqlquery.Row) []postgresqlquery.Row {
	if rows == nil {
		return nil
	}
	detached := make([]postgresqlquery.Row, len(rows))
	for index, row := range rows {
		copied := row
		copied.Values = detachedScalarValues(row.Values)
		copied.Canonical = detachedScalarBytes(row.Canonical)
		detached[index] = copied
	}
	return detached
}

// detachedScalarValues returns a freshly allocated copy of one row's typed
// entries with every byte-backed Value copied, preserving a nil slice as nil and
// an empty slice as a non-nil empty slice.
func detachedScalarValues(entries []postgresqlquery.ValueEntry) []postgresqlquery.ValueEntry {
	if entries == nil {
		return nil
	}
	detached := make([]postgresqlquery.ValueEntry, len(entries))
	for index, entry := range entries {
		copied := entry
		copied.Value = detachedScalarValue(entry.Value)
		detached[index] = copied
	}
	return detached
}

// detachedScalarValue copies one byte-backed ValueEntry.Value: a []byte or a
// jsontext.Value is freshly allocated while every immutable scalar, string and
// nil value is retained unchanged, so the retained form is exactly the form the
// reader produced.
func detachedScalarValue(value any) any {
	switch typed := value.(type) {
	case []byte:
		return detachedScalarBytes(typed)
	case jsontext.Value:
		return jsontext.Value(detachedScalarBytes(typed))
	default:
		return value
	}
}

// detachedScalarBytes returns a freshly allocated copy of one byte slice,
// preserving a nil slice as nil and an empty slice as a non-nil empty slice.
func detachedScalarBytes(value []byte) []byte {
	if value == nil {
		return nil
	}
	detached := make([]byte, len(value))
	copy(detached, value)
	return detached
}

// detachedScalarOrdinals returns a freshly allocated copy of the plan's
// Snapshot ordinals, preserving the nil/empty distinction, so no caller can
// reach the retained plan through the returned ScalarRead.
func detachedScalarOrdinals(ordinals []int) []int {
	if ordinals == nil {
		return nil
	}
	detached := make([]int, len(ordinals))
	copy(detached, ordinals)
	return detached
}
