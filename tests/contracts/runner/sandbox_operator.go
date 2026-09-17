package contracts

import (
	"regexp"
	"time"
)

var sandboxProfileRevisionRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)

func validateSandboxParserRequestV1(request map[string]any) error {
	key := stringValue(request["parser_type"]) + "/" + stringValue(request["operation"]) + "/" + stringValue(request["media_family"]) + "/" + stringValue(request["output_contract"])
	switch key {
	case "OFFICE/OBSERVE_STRUCTURE/DOCX/document-parser-result-v1", "OFFICE/OBSERVE_STRUCTURE/PPTX/document-parser-result-v1", "OFFICE/OBSERVE_STRUCTURE/XLSX/document-parser-result-v1", "PDF/OBSERVE_PDF_TEXT/PDF/pdf-parser-result-v1", "PDF/RENDER_PDF_PAGES/PDF/pdf-render-result-v1", "OCR/OBSERVE_OCR_TOKENS/PNG/ocr-result-v1", "OCR/OBSERVE_OCR_TOKENS/JPEG/ocr-result-v1":
		if stringValue(request["schema_version"]) == "sandbox-parser-request-v1" && sandboxProfileRevisionRe.MatchString(stringValue(request["sandbox_profile_revision"])) && sandboxProfileRevisionRe.MatchString(stringValue(request["observation_profile_revision"])) && intValue(request["max_input_bytes"]) > 0 && intValue(request["max_output_bytes"]) > 0 && intValue(request["max_units"]) > 0 && intValue(request["max_pages"]) > 0 && intValue(request["max_decoded_pixels"]) > 0 {
			if (stringValue(request["operation"]) == "OBSERVE_STRUCTURE" || stringValue(request["operation"]) == "OBSERVE_PDF_TEXT") && (stringValue(request["renderer_profile_revision"]) != "" || stringValue(request["ocr_profile_revision"]) != "") {
				break
			}
			if stringValue(request["operation"]) == "RENDER_PDF_PAGES" && !sandboxProfileRevisionRe.MatchString(stringValue(request["renderer_profile_revision"])) {
				break
			}
			if stringValue(request["operation"]) == "RENDER_PDF_PAGES" && stringValue(request["ocr_profile_revision"]) != "" {
				break
			}
			if stringValue(request["operation"]) == "OBSERVE_OCR_TOKENS" && !sandboxProfileRevisionRe.MatchString(stringValue(request["ocr_profile_revision"])) {
				break
			}
			if stringValue(request["operation"]) == "OBSERVE_OCR_TOKENS" && stringValue(request["renderer_profile_revision"]) != "" {
				break
			}
			return nil
		}
	}
	return fail("SANDBOX_PARSER_REQUEST_TUPLE_INVALID")
}

var operatorFailureActions = map[string]string{
	"DEPENDENCY_UNAVAILABLE":        "RETRY_AFTER_DEPENDENCY_RECOVERY",
	"MOUNT_INVALID":                 "FIX_MOUNT_AND_RESTART",
	"MIGRATION_INCOMPATIBLE":        "ROLL_BACK_OR_RUN_COMPATIBLE_MIGRATION",
	"RESTORE_NEGATIVE_CHECK_FAILED": "STOP_AND_RESTORE_FROM_VERIFIED_BACKUP",
}

var operatorFailureMetrics = map[string]string{
	"DEPENDENCY_UNAVAILABLE":        "operator_dependency_failures_total",
	"MOUNT_INVALID":                 "operator_mount_failures_total",
	"MIGRATION_INCOMPATIBLE":        "operator_migration_failures_total",
	"RESTORE_NEGATIVE_CHECK_FAILED": "operator_restore_negative_check_failures_total",
}

var operatorDependencyNames = map[string]bool{
	"POSTGRESQL":         true,
	"OPENSEARCH":         true,
	"KEY_PROVIDER":       true,
	"MIGRATION_STATE":    true,
	"SANDBOX_DISPATCHER": true,
}

func validateSandboxJob(job map[string]any) error {
	submitted, submittedErr := time.Parse(time.RFC3339, stringValue(job["submitted_at"]))
	deadline, deadlineErr := time.Parse(time.RFC3339, stringValue(job["deadline_at"]))
	if submittedErr != nil || deadlineErr != nil || !deadline.After(submitted) {
		return fail("SANDBOX_DEADLINE_INVALID")
	}
	return nil
}

func validateSandboxLease(lease map[string]any) error {
	issued, issuedErr := time.Parse(time.RFC3339, stringValue(lease["issued_at"]))
	expires, expiresErr := time.Parse(time.RFC3339, stringValue(lease["expires_at"]))
	registration := object(lease["registration"])
	if issuedErr != nil || expiresErr != nil || !expires.After(issued) {
		return fail("SANDBOX_LEASE_INTERVAL_INVALID")
	}
	if stringValue(registration["parser_type"]) != stringValue(lease["parser_type"]) {
		return fail("SANDBOX_LEASE_PARSER_MISMATCH")
	}
	if !boolValue(registration["single_socket"]) {
		return fail("SANDBOX_LEASE_SINGLE_SOCKET_REQUIRED")
	}
	return nil
}

func validateSandboxOutcome(outcome map[string]any) error {
	handoff := object(outcome["handoff"])
	state := stringValue(handoff["transfer_state"])
	status := stringValue(outcome["status"])
	identity := stringValue(outcome["extraction_identity"])
	switch state {
	case "CONFIRMED":
		if status != "SUCCEEDED" || identity == "" {
			return fail("SANDBOX_OUTCOME_STATE_INVALID")
		}
	case "RETRY":
		if status != "FAILED" || outcome["extraction_identity"] != nil {
			return fail("SANDBOX_OUTCOME_STATE_INVALID")
		}
	case "QUARANTINED":
		if status != "QUARANTINED" || outcome["extraction_identity"] != nil {
			return fail("SANDBOX_OUTCOME_STATE_INVALID")
		}
	default:
		return fail("SANDBOX_OUTCOME_STATE_INVALID")
	}
	return nil
}

func validateSandboxLimitConfirmation(confirmation, context map[string]any) error {
	trusted := object(context["trusted_kernel_observation"])
	if stringValue(confirmation["observation_method"]) != "KERNEL_CGROUP_NAMESPACE" {
		return fail("SANDBOX_KERNEL_OBSERVATION_REQUIRED")
	}
	if trusted == nil || stringValue(trusted["observation_method"]) != "KERNEL_CGROUP_NAMESPACE" {
		return fail("SANDBOX_KERNEL_OBSERVATION_REQUIRED")
	}
	if stringValue(confirmation["observation_method"]) != stringValue(trusted["observation_method"]) ||
		stringValue(confirmation["lease_id"]) != stringValue(trusted["lease_id"]) ||
		stringValue(confirmation["job_id"]) != stringValue(trusted["job_id"]) ||
		stringValue(confirmation["worker_id"]) != stringValue(trusted["worker_id"]) ||
		stringValue(confirmation["observed_at"]) != stringValue(trusted["observed_at"]) ||
		stringValue(confirmation["extraction_identity"]) != stringValue(trusted["extraction_identity"]) ||
		!canonicalObjectsEqual(object(confirmation["limits"]), object(trusted["limits"])) {
		return fail("SANDBOX_KERNEL_OBSERVATION_MISMATCH")
	}
	expectedLimitsHash, err := hashCanonical(trusted["limits"])
	if err != nil || stringValue(trusted["limits_hash"]) != expectedLimitsHash || !boolValue(confirmation["confirmed"]) {
		return fail("SANDBOX_KERNEL_OBSERVATION_INVALID")
	}
	return nil
}

func validateOperatorFailure(failure map[string]any) error {
	code := stringValue(failure["code"])
	if stringValue(failure["action"]) != operatorFailureActions[code] || stringValue(failure["metric_name"]) != operatorFailureMetrics[code] {
		return fail("OPERATOR_ACTION_MAPPING_INVALID", code)
	}
	if boolValue(failure["fallback_allowed"]) {
		return fail("OPERATOR_FALLBACK_FORBIDDEN")
	}
	return nil
}

func validateOperatorReadiness(readiness map[string]any) error {
	ready := true
	for _, rawDependency := range array(readiness["dependencies"]) {
		dependency := object(rawDependency)
		name := stringValue(dependency["name"])
		if !operatorDependencyNames[name] {
			return fail("OPERATOR_DEPENDENCY_UNKNOWN", name)
		}
		if stringValue(dependency["status"]) != "READY" {
			ready = false
		}
	}
	if boolValue(readiness["readiness"]) != ready {
		return fail("OPERATOR_READINESS_MISMATCH")
	}
	return nil
}
