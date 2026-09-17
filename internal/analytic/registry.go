package analytic

// This file owns the server-side analytic tool boundary.  A planner selects a
// typed operation, but it never selects an implementation, a database target,
// or SQL text.  The registry is the only authority that maps a tool id to an
// installed adapter and applies its immutable resource budget.

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"sync"
	"time"

	"knowvault.local/verified-workspace/internal/planner"
	"knowvault.local/verified-workspace/internal/source/canon"
)

const (
	// EvidenceReducerTool is the first server-owned analytic binding.  A future
	// PostgreSQL projection adapter gets its own versioned id; it must not alter
	// this binding or turn the reducer into a SQL execution surface.
	EvidenceReducerTool = "analytic.evidence-reducer-v1"
	toolBindingVersion  = "1"

	defaultMaxRows    = 256
	defaultMaxCells   = maximumCells
	defaultMaxBuckets = maximumBuckets
)

var toolIDPattern = regexp.MustCompile(`^analytic\.[a-z0-9][a-z0-9.-]{0,95}-v[1-9][0-9]{0,3}$`)

const (
	CodeToolNotFound    ErrorCode = "ANALYTIC_TOOL_NOT_FOUND"
	CodeToolLimit       ErrorCode = "ANALYTIC_TOOL_LIMIT"
	CodeToolTimeout     ErrorCode = "ANALYTIC_TOOL_TIMEOUT"
	CodeToolResultError ErrorCode = "ANALYTIC_TOOL_RESULT_INVALID"
)

// Limits is a binding-owned budget.  Callers cannot widen it in an
// Invocation; changing a budget creates a different BindingHash and therefore
// a different server-owned tool contract.
type Limits struct {
	MaxRows    int           `json:"max_rows"`
	MaxCells   int           `json:"max_cells"`
	MaxBuckets int           `json:"max_buckets"`
	Timeout    time.Duration `json:"timeout_ns"`
}

// DefaultLimits is the budget for the in-process Evidence reducer.  A source
// adapter may expose a smaller budget, but no binding can exceed the hard
// reducer bucket/cell caps without introducing a separately reviewed adapter.
func DefaultLimits() Limits {
	return Limits{MaxRows: defaultMaxRows, MaxCells: defaultMaxCells, MaxBuckets: defaultMaxBuckets, Timeout: 2 * time.Second}
}

func (limits Limits) validate() error {
	if limits.MaxRows < 1 || limits.MaxRows > 100000 ||
		limits.MaxCells < 1 || limits.MaxCells > 100000 ||
		limits.MaxBuckets < 1 || limits.MaxBuckets > maximumBuckets ||
		limits.Timeout < time.Millisecond || limits.Timeout > 5*time.Minute {
		return &Error{code: CodeInvalidRequest, cause: errors.New("invalid analytic tool limits")}
	}
	return nil
}

// Binding is created only during trusted server composition.  Adapter and
// Limits are intentionally not exported through Registry; consumers can only
// invoke the immutable binding by its allowlisted id.
type Binding struct {
	ID      string
	Version string
	Adapter Adapter
	Limits  Limits

	bindingHash string
}

// NewBinding validates and seals one server-owned tool binding.  The binding
// hash covers the id, version and all budgets, so a persisted receipt can
// detect a changed implementation contract.
func NewBinding(id, version string, adapter Adapter, limits Limits) (Binding, error) {
	if !toolIDPattern.MatchString(id) {
		return Binding{}, &Error{code: CodeInvalidRequest, cause: errors.New("invalid analytic tool id")}
	}
	if !validOpaque(version) {
		return Binding{}, &Error{code: CodeInvalidRequest, cause: errors.New("invalid analytic tool version")}
	}
	if adapter == nil {
		return Binding{}, &Error{code: CodeInvalidRequest, cause: errors.New("nil analytic adapter")}
	}
	if err := limits.validate(); err != nil {
		return Binding{}, err
	}
	raw, err := canon.CanonicalJSON(struct {
		ID      string `json:"id"`
		Version string `json:"version"`
		Limits  struct {
			MaxRows    int   `json:"max_rows"`
			MaxCells   int   `json:"max_cells"`
			MaxBuckets int   `json:"max_buckets"`
			TimeoutNS  int64 `json:"timeout_ns"`
		} `json:"limits"`
	}{id, version, struct {
		MaxRows    int   `json:"max_rows"`
		MaxCells   int   `json:"max_cells"`
		MaxBuckets int   `json:"max_buckets"`
		TimeoutNS  int64 `json:"timeout_ns"`
	}{limits.MaxRows, limits.MaxCells, limits.MaxBuckets, int64(limits.Timeout)}})
	if err != nil {
		return Binding{}, &Error{code: CodeInvalidRequest, cause: err}
	}
	return Binding{ID: id, Version: version, Adapter: adapter, Limits: limits, bindingHash: canon.Hash(raw)}, nil
}

func (binding Binding) Hash() string { return binding.bindingHash }

// Invocation binds a typed planner result to one allowlisted tool.  There is
// no SQL, relation name, credential, citation or model output in this shape.
// Cells must already have passed the source authorization gate.
type Invocation struct {
	WorkspaceID string
	ToolID      string
	Plan        planner.Plan
	Cells       []Cell
}

// Receipt is the transport-neutral provenance record returned for every
// attempted invocation after a binding has been resolved.  The caller may
// persist this exact record in a durable Question Run/tool-run repository; its
// hash makes later mutation detectable.  This in-process package deliberately
// does not write a database or invent a persistence path.
type Receipt struct {
	WorkspaceID string
	ToolID      string
	BindingHash string
	PlanHash    string
	ResultHash  string
	EvidenceIDs []string
	Rows        int
	Cells       int
	Buckets     int
	Status      string
	FailureCode string
	StartedAt   time.Time
	CompletedAt time.Time
	ReceiptHash string
}

type Registry struct {
	bindings map[string]Binding
	now      func() time.Time
}

// NewRegistry seals an allowlist.  Duplicate ids, nil adapters and invalid
// budgets fail server startup rather than becoming a runtime fallback.
func NewRegistry(bindings ...Binding) (*Registry, error) {
	if len(bindings) == 0 {
		return nil, &Error{code: CodeInvalidRequest, cause: errors.New("analytic registry is empty")}
	}
	registry := &Registry{bindings: make(map[string]Binding, len(bindings)), now: time.Now}
	for _, binding := range bindings {
		// Always recompute the seal, even for a value built inside this package.
		// This prevents a future test/helper or internal caller from smuggling a
		// stale binding hash into the registry.
		sealed, err := NewBinding(binding.ID, binding.Version, binding.Adapter, binding.Limits)
		if err != nil {
			return nil, err
		}
		binding = sealed
		if _, exists := registry.bindings[binding.ID]; exists {
			return nil, &Error{code: CodeInvalidRequest, cause: errors.New("duplicate analytic tool id")}
		}
		registry.bindings[binding.ID] = binding
	}
	return registry, nil
}

// DefaultRegistry returns the single in-process binding used by Question Run.
// The registry and its map are never exposed for mutation.
func DefaultRegistry() *Registry {
	defaultRegistryOnce.Do(func() {
		registry, err := NewRegistry(mustBinding(EvidenceReducerTool, toolBindingVersion, NewEvidenceAdapter(), DefaultLimits()))
		if err != nil {
			panic(err)
		}
		defaultRegistryValue = registry
	})
	return defaultRegistryValue
}

var (
	defaultRegistryOnce  sync.Once
	defaultRegistryValue *Registry
)

func mustBinding(id, version string, adapter Adapter, limits Limits) Binding {
	binding, err := NewBinding(id, version, adapter, limits)
	if err != nil {
		panic(err)
	}
	return binding
}

type adapterResult struct {
	result Result
	err    error
}

// Invoke validates the immutable plan, checks the row/cell budget before
// dispatch, and validates every result Evidence reference before returning it.
// The adapter runs behind a bounded context and a buffered completion channel;
// an adapter that ignores cancellation cannot hold the request path forever.
func (registry *Registry) Invoke(ctx context.Context, invocation Invocation) (Result, Receipt, error) {
	if registry == nil || ctx == nil || !validOpaque(invocation.WorkspaceID) || invocation.Plan.Validate() != nil ||
		invocation.Plan.Status != planner.Ready || invocation.Plan.Operation != planner.Aggregate ||
		invocation.Plan.Aggregate == nil {
		return Result{}, Receipt{}, &Error{code: CodeInvalidRequest}
	}
	binding, found := registry.bindings[invocation.ToolID]
	if !found {
		return Result{}, Receipt{}, &Error{code: CodeToolNotFound}
	}
	started := registry.now().UTC()
	receipt := Receipt{
		WorkspaceID: invocation.WorkspaceID, ToolID: binding.ID, BindingHash: binding.bindingHash,
		PlanHash: invocation.Plan.PlanHash, Status: "RUNNING", StartedAt: started,
	}
	finish := func(result Result, err error, status string) (Result, Receipt, error) {
		receipt.Status = status
		receipt.CompletedAt = registry.now().UTC()
		if err != nil {
			receipt.FailureCode = string(CodeOf(err))
			_ = sealReceipt(&receipt)
			return Result{}, receipt, err
		}
		receipt.Rows = countRows(invocation.Cells)
		receipt.Cells = len(invocation.Cells)
		receipt.Buckets = len(result.Buckets)
		receipt.EvidenceIDs = resultEvidenceIDs(result)
		raw, hashErr := canon.CanonicalJSON(result)
		if hashErr != nil {
			failure := &Error{code: CodeToolResultError, cause: hashErr}
			receipt.FailureCode = string(CodeOf(failure))
			_ = sealReceipt(&receipt)
			return Result{}, receipt, failure
		}
		receipt.ResultHash = canon.Hash(raw)
		if hashErr = sealReceipt(&receipt); hashErr != nil {
			failure := &Error{code: CodeToolResultError, cause: hashErr}
			return Result{}, receipt, failure
		}
		return result, receipt, nil
	}

	if err := validateInvocationCells(invocation.Cells, binding.Limits); err != nil {
		return finish(Result{}, err, "FAILED")
	}
	cells := append([]Cell(nil), invocation.Cells...)
	request := Request{WorkspaceID: invocation.WorkspaceID, PlanHash: invocation.Plan.PlanHash, Spec: *invocation.Plan.Aggregate, Filters: append([]planner.Filter(nil), invocation.Plan.Filters...), Cells: cells}
	toolCtx, cancel := context.WithTimeout(ctx, binding.Limits.Timeout)
	defer cancel()
	completed := make(chan adapterResult, 1)
	go func() {
		result, err := binding.Adapter.Aggregate(toolCtx, request)
		completed <- adapterResult{result: result, err: err}
	}()
	select {
	case <-toolCtx.Done():
		status := "FAILED"
		if errors.Is(toolCtx.Err(), context.DeadlineExceeded) {
			return finish(Result{}, &Error{code: CodeToolTimeout, cause: toolCtx.Err()}, status)
		}
		return finish(Result{}, &Error{code: CodeToolTimeout, cause: toolCtx.Err()}, status)
	case outcome := <-completed:
		if outcome.err != nil {
			return finish(Result{}, outcome.err, "FAILED")
		}
		if err := validateResult(outcome.result, request, binding.Limits); err != nil {
			return finish(Result{}, err, "FAILED")
		}
		return finish(outcome.result, nil, "SUCCEEDED")
	}
}

func validateInvocationCells(cells []Cell, limits Limits) error {
	if len(cells) == 0 || len(cells) > limits.MaxCells {
		return &Error{code: CodeToolLimit}
	}
	rows := make(map[string]struct{}, len(cells))
	for _, cell := range cells {
		if !validCell(cell) {
			return &Error{code: CodeInvalidRequest}
		}
		rows[cell.RowKey] = struct{}{}
	}
	if len(rows) > limits.MaxRows {
		return &Error{code: CodeToolLimit}
	}
	return nil
}

func validateResult(result Result, request Request, limits Limits) error {
	if !validOpaque(result.Function) || result.Function != request.Spec.Function ||
		result.Order != request.Spec.Order || len(result.Buckets) == 0 || len(result.Buckets) > limits.MaxBuckets {
		return &Error{code: CodeToolResultError}
	}
	if result.Metric != "" && !validOpaque(result.Metric) || len(result.GroupBy) != len(request.Spec.GroupBy) {
		return &Error{code: CodeToolResultError}
	}
	for _, group := range result.GroupBy {
		if !validOpaque(group) {
			return &Error{code: CodeToolResultError}
		}
	}
	known := make(map[string]Evidence, len(request.Cells))
	for _, cell := range request.Cells {
		known[cell.Evidence.ID] = cell.Evidence
	}
	for _, bucket := range result.Buckets {
		if !validOpaque(bucket.Key) || !decimalPattern.MatchString(bucket.Value) || bucket.Count < 1 || len(bucket.Evidence) == 0 {
			return &Error{code: CodeToolResultError}
		}
		// Every rendered aggregate value must carry at least one exact
		// Evidence reference. A grouped label is itself part of the answer, so
		// it needs a separate group witness; an ungrouped bucket must not smuggle
		// one in because there is no label to authorize.
		if len(request.Spec.GroupBy) > 0 {
			if len(bucket.GroupEvidence) != len(result.GroupBy) || len(bucket.GroupValues) != len(result.GroupBy) {
				return &Error{code: CodeToolResultError}
			}
			if bucket.Key != compositeGroupLabel(bucket.GroupValues) {
				return &Error{code: CodeToolResultError}
			}
		} else if bucket.Key != "__all__" || len(bucket.GroupEvidence) > 0 || len(bucket.GroupValues) > 0 {
			return &Error{code: CodeToolResultError}
		}
		for _, value := range bucket.GroupValues {
			if !validOpaque(value) {
				return &Error{code: CodeToolResultError}
			}
		}
		seenRefs := make(map[string]struct{}, len(bucket.Evidence)+len(bucket.GroupEvidence))
		for _, ref := range bucket.Evidence {
			if !validEvidenceRef(ref, known) {
				return &Error{code: CodeToolResultError}
			}
			if _, duplicate := seenRefs[ref.ID]; duplicate {
				return &Error{code: CodeToolResultError}
			}
			seenRefs[ref.ID] = struct{}{}
		}
		filterRefs := make(map[string]struct{}, len(bucket.FilterEvidence))
		for _, ref := range bucket.FilterEvidence {
			if !validEvidenceRef(ref, known) {
				return &Error{code: CodeToolResultError}
			}
			// A predicate can legitimately target the same cell used as a
			// group witness or numeric witness. It still needs an exact ref, but
			// duplicate rendering is suppressed by the answer authority.
			if _, duplicate := filterRefs[ref.ID]; duplicate {
				return &Error{code: CodeToolResultError}
			}
			filterRefs[ref.ID] = struct{}{}
		}
		for _, ref := range bucket.GroupEvidence {
			if !validEvidenceRef(ref, known) {
				return &Error{code: CodeToolResultError}
			}
			if _, duplicate := seenRefs[ref.ID]; duplicate {
				return &Error{code: CodeToolResultError}
			}
			seenRefs[ref.ID] = struct{}{}
		}
	}
	return nil
}

func validEvidenceRef(ref EvidenceRef, known map[string]Evidence) bool {
	evidence, ok := known[ref.ID]
	return ok && evidenceRef(evidence) == ref
}

func resultEvidenceIDs(result Result) []string {
	seen := make(map[string]struct{})
	for _, bucket := range result.Buckets {
		for _, ref := range bucket.Evidence {
			seen[ref.ID] = struct{}{}
		}
		for _, ref := range bucket.FilterEvidence {
			seen[ref.ID] = struct{}{}
		}
		for _, ref := range bucket.GroupEvidence {
			seen[ref.ID] = struct{}{}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func countRows(cells []Cell) int {
	rows := make(map[string]struct{}, len(cells))
	for _, cell := range cells {
		rows[cell.RowKey] = struct{}{}
	}
	return len(rows)
}

func sealReceipt(receipt *Receipt) error {
	if receipt == nil {
		return errors.New("nil analytic receipt")
	}
	projection := struct {
		WorkspaceID string    `json:"workspace_id"`
		ToolID      string    `json:"tool_id"`
		BindingHash string    `json:"binding_hash"`
		PlanHash    string    `json:"plan_hash"`
		ResultHash  string    `json:"result_hash,omitempty"`
		EvidenceIDs []string  `json:"evidence_ids,omitempty"`
		Rows        int       `json:"rows"`
		Cells       int       `json:"cells"`
		Buckets     int       `json:"buckets"`
		Status      string    `json:"status"`
		FailureCode string    `json:"failure_code,omitempty"`
		StartedAt   time.Time `json:"started_at"`
		CompletedAt time.Time `json:"completed_at"`
	}{receipt.WorkspaceID, receipt.ToolID, receipt.BindingHash, receipt.PlanHash, receipt.ResultHash, append([]string(nil), receipt.EvidenceIDs...), receipt.Rows, receipt.Cells, receipt.Buckets, receipt.Status, receipt.FailureCode, receipt.StartedAt, receipt.CompletedAt}
	raw, err := canon.CanonicalJSON(projection)
	if err != nil {
		return err
	}
	receipt.ReceiptHash = canon.Hash(raw)
	return nil
}
