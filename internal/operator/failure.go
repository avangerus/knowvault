// Package operator implements the single static knowvault-operator deployment
// binary (ADR-0069). It owns bootstrap, role creation, versioned migrations,
// authentication-provider registration, key/secret manifests and mount
// verification, and reuses product packages instead of re-implementing domain
// rules. Every unavailable dependency produces a typed operator-visible
// failure conforming to architecture/contracts/operator-failure.schema.json;
// there is no silent fallback (OPS-010).
package operator

import "encoding/json"

// FailureCode is the closed operator-failure code set. The code-to-action and
// code-to-metric bindings are fixed by the protected schema; constructors below
// are the only producers.
type FailureCode string

const (
	FailureDependencyUnavailable FailureCode = "DEPENDENCY_UNAVAILABLE"
	FailureMountInvalid          FailureCode = "MOUNT_INVALID"
	FailureMigrationIncompatible FailureCode = "MIGRATION_INCOMPATIBLE"
)

// Failure is the machine-readable record emitted for every typed operator
// failure. Its shape is pinned by architecture/contracts/operator-failure.
// schema.json (schema_version, code, action, retryable, metric_name,
// fallback_allowed=false; the allOf bindings force the action/metric pair to
// match the code).
type Failure struct {
	SchemaVersion   string      `json:"schema_version"`
	Code            FailureCode `json:"code"`
	Action          string      `json:"action"`
	Retryable       bool        `json:"retryable"`
	MetricName      string      `json:"metric_name"`
	FallbackAllowed bool        `json:"fallback_allowed"`
	// Detail is a human-readable cause; it is deliberately excluded from the
	// schema so no secret or parser detail can creep into the typed contract.
	Detail string `json:"detail"`
}

// DependencyUnavailable reports a transient dependency outage (database,
// identity provider, mount root not yet present). Retryable by definition.
func DependencyUnavailable(detail string) *Failure {
	return &Failure{
		SchemaVersion: "operator-failure-v1", Code: FailureDependencyUnavailable,
		Action: "RETRY_AFTER_DEPENDENCY_RECOVERY", Retryable: true,
		MetricName: "operator_dependency_failures_total", FallbackAllowed: false, Detail: detail,
	}
}

// MountInvalid reports a present-but-invalid secret mount. The operator never
// repairs a mount silently; the deployment must be fixed and restarted.
func MountInvalid(detail string) *Failure {
	return &Failure{
		SchemaVersion: "operator-failure-v1", Code: FailureMountInvalid,
		Action: "FIX_MOUNT_AND_RESTART", Retryable: false,
		MetricName: "operator_mount_failures_total", FallbackAllowed: false, Detail: detail,
	}
}

// MigrationIncompatible reports an applied-migration or registered-state
// conflict with the requested deployment (checksum mismatch, accounting shape
// drift, role or provider configuration conflict). The operator never
// rewrites applied history.
func MigrationIncompatible(detail string) *Failure {
	return &Failure{
		SchemaVersion: "operator-failure-v1", Code: FailureMigrationIncompatible,
		Action: "ROLL_BACK_OR_RUN_COMPATIBLE_MIGRATION", Retryable: false,
		MetricName: "operator_migration_failures_total", FallbackAllowed: false, Detail: detail,
	}
}

// IsFailure reports whether err carries an operator Failure.
func IsFailure(err error) (*Failure, bool) {
	failure, ok := err.(*Failure)
	return failure, ok
}

func (value *Failure) Error() string {
	raw, _ := json.Marshal(value)
	return string(raw)
}

// Marshal renders the schema-conforming failure record. The Detail field is
// excluded from the wire record: it is operator-terminal guidance only.
func (value *Failure) Marshal() []byte {
	raw, err := json.Marshal(struct {
		SchemaVersion   string      `json:"schema_version"`
		Code            FailureCode `json:"code"`
		Action          string      `json:"action"`
		Retryable       bool        `json:"retryable"`
		MetricName      string      `json:"metric_name"`
		FallbackAllowed bool        `json:"fallback_allowed"`
	}{
		SchemaVersion: value.SchemaVersion, Code: value.Code, Action: value.Action,
		Retryable: value.Retryable, MetricName: value.MetricName, FallbackAllowed: value.FallbackAllowed,
	})
	if err != nil {
		return []byte(`{"schema_version":"operator-failure-v1","code":"DEPENDENCY_UNAVAILABLE","action":"RETRY_AFTER_DEPENDENCY_RECOVERY","retryable":true,"metric_name":"operator_dependency_failures_total","fallback_allowed":false}`)
	}
	return raw
}
