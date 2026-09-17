// Package ingestion is the worker-side folder-to-Evidence pipeline for P2/I1/S1d.
// A SOURCE_SCOPE_SYNC job resolves an activated SourceScopeRevision into a folder
// Scope, discovers and reads objects, and creates the catalog / version /
// extraction / Evidence rows the connector deliberately does not — all fenced by
// the job lease. Sensitive identities, locators, titles, Evidence text and
// anchors pass only through activated encrypted-artifact owner branches.
package ingestion

import (
	"context"
	"errors"
	"fmt"

	"knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
)

// errWorkerGateDenied is returned when the read gate is asked for by a session
// that is not the worker role or has no tenant context. It is not a not-found:
// the worker branches have no public surface, so this denial never becomes an
// existence oracle.
var errWorkerGateDenied = errors.New("ingestion: worker role gate denied")

// workerAuthorize is the read gate for the worker's own artifact branches. The
// worker operates under its trusted job lease and organization context, and the
// SECURITY DEFINER read/bind functions filter by app.current_organization_id(),
// but the access point still re-checks its own preconditions: the session must
// be the dedicated worker role (never the web/API runtime role) and a tenant
// context must be set. The Evidence viewer's workspace/confirmation
// authorization lives in the read path, not here.
func workerAuthorize(ctx context.Context, transaction database.Transaction, _ database.AccessContext, _ string) error {
	var allowed bool
	if err := transaction.QueryRow(ctx,
		`SELECT session_user = 'knowvault_worker' AND app.current_organization_id() IS NOT NULL`).Scan(&allowed); err != nil {
		return err
	}
	if !allowed {
		return errWorkerGateDenied
	}
	return nil
}

// BuildRepository wires the S1d owner branches the worker uses: the three
// source_object identity branches, the three evidence_fragment branches, and the
// read-only scope-config and trust-profile branches it decrypts to resolve a
// Scope. No other branch is activated.
func BuildRepository() (*repository.Repository, error) {
	type spec struct {
		field  artifactcrypto.OwnerField
		bindFn string
		readFn string
	}
	specs := []spec{
		{artifactcrypto.SourceObjectCanonicalLocator, "app.source_object_bind_canonical_locator", "app.source_object_read_canonical_locator"},
		{artifactcrypto.SourceObjectExternalID, "app.source_object_bind_external_object_id", "app.source_object_read_external_object_id"},
		{artifactcrypto.SourceObjectTitle, "app.source_object_bind_title", "app.source_object_read_title"},
		{artifactcrypto.EvidenceNormalizedText, "app.evidence_fragment_bind_normalized_text", "app.evidence_fragment_read_normalized_text"},
		{artifactcrypto.EvidenceAnchor, "app.evidence_fragment_bind_anchor", "app.evidence_fragment_read_anchor"},
		{artifactcrypto.EvidenceMetadata, "app.evidence_fragment_bind_metadata", "app.evidence_fragment_read_metadata"},
		// Read-only: the worker only decrypts these; the bind name is a valid,
		// distinct placeholder that is never invoked (the control plane creates
		// them). NewBinding requires bind and read names to differ.
		{artifactcrypto.SourceScopeConfig, "app.source_scope_config_bind_unused", "app.source_scope_config_read"},
		{artifactcrypto.SourceConnectionTrustConfig, "app.source_trust_config_bind_unused", "app.source_trust_config_read"},
	}
	bindings := make([]repository.Binding, 0, len(specs))
	for _, s := range specs {
		binding, err := repository.NewBinding(s.field, s.bindFn, s.readFn, workerAuthorize)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	return repository.New(bindings...)
}

// errPipeline is a content-free wrapper so a per-object failure carries a safe
// diagnostic code and never a path or byte.
type errPipeline struct {
	code string
	err  error
}

func (e *errPipeline) Error() string { return e.code }
func (e *errPipeline) Unwrap() error { return e.err }

func failure(code string, err error) error { return &errPipeline{code: code, err: err} }

// CodeOf extracts the safe diagnostic code from a pipeline error.
func CodeOf(err error) string {
	var pipeline *errPipeline
	if errors.As(err, &pipeline) {
		return pipeline.code
	}
	return "INGEST_INTERNAL"
}

// DiagnosticClass returns a content-free class for operational logs. Pipeline
// errors intentionally expose only their stable code through Error() so paths,
// payloads and SQL text cannot leak into worker logs. Operators still need to
// distinguish a database contract failure from a context/transport failure;
// this helper records only the SQLSTATE or wrapped Go error type, never the
// underlying message.
func DiagnosticClass(err error) string {
	if err == nil {
		return ""
	}
	if state := database.SQLStateCode(err); state != "" {
		if constraint := database.SQLConstraintName(err); constraint != "" {
			return "SQLSTATE_" + state + "_CONSTRAINT_" + constraint
		}
		return "SQLSTATE_" + state
	}
	if errors.Is(err, context.Canceled) {
		return "CONTEXT_CANCELED"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "CONTEXT_DEADLINE_EXCEEDED"
	}
	if class := wrappedPipelineClass(err); class != "" {
		return class
	}
	return "ERROR_TYPE_" + fmt.Sprintf("%T", err)
}

// wrappedPipelineClass reports the innermost content-free pipeline code of a
// nested failure. An outer code such as INGEST_ADAPTER_UNAVAILABLE is a
// category, not a diagnosis: the resolution step that actually refused
// (a missing source-trust bundle, an unresolvable credential reference, a
// canonical-bytes mismatch) already carries its own content-free code, and
// without it an operator cannot tell those apart from a log line. Only codes
// and Go type names are reported, exactly like the rest of DiagnosticClass.
func wrappedPipelineClass(err error) string {
	codes := make([]string, 0, 4)
	var deepest error
	for current := err; current != nil; current = errors.Unwrap(current) {
		if pipeline, ok := current.(*errPipeline); ok {
			codes = append(codes, pipeline.code)
			continue
		}
		deepest = current
	}
	if len(codes) < 2 && deepest == nil {
		return ""
	}
	innermost := ""
	if len(codes) > 1 {
		innermost = codes[len(codes)-1]
	}
	if deepest == nil {
		return "CAUSE_" + innermost
	}
	// The deepest non-typed cause is reported by Go TYPE only -- never by
	// message -- so a dial failure, a certificate rejection and a protocol
	// error stay distinguishable in a worker log without any endpoint,
	// credential or payload leaving the process.
	if innermost == "" {
		return ""
	}
	return "CAUSE_" + innermost + "_TYPE_" + fmt.Sprintf("%T", deepest)
}
