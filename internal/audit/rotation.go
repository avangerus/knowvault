package audit

// The deployment secret rotation audit contract (ADR-0070).
//
// Both actions share one resource type and one resource-ID rule: the audit
// resource_id is always the requested active key reference — content-free —
// on every terminal outcome, exactly like the authority contract names the
// receipt id even on DENIED. The rotation domain and the key version travel
// only inside metadata, and only on SUCCESS: a DENIED or FAILED begin/complete
// has no proven pair to name.
const (
	ActionKeyRotationBegin    Action = "key.rotation.begin"
	ActionKeyRotationComplete Action = "key.rotation.complete"
)

const ResourceCryptoKey ResourceType = "CRYPTO_KEY"

// The closed terminal error surface of the rotation boundary. Begin/complete
// are coordinator-driven; a refusal maps to DENIED and a failed precondition
// (zero-wrappers/zero-remaining, unknown pair) to FAILED.
const (
	ErrorRotationDenied = "ROTATION_DENIED"
	ErrorRotationFailed = "ROTATION_FAILED"
)

const (
	rotationDomainKEK    = "KEK"
	rotationDomainDigest = "DIGEST"
)

// isRotationAction reports whether the action belongs to the rotation
// contract. The action/resource pair is one-to-one, mirroring the authority
// rule: neither may ever appear without the other.
func isRotationAction(action Action) bool {
	return action == ActionKeyRotationBegin || action == ActionKeyRotationComplete
}

// hasRotationMetadata reports whether any rotation-only field is set. The
// rotation vocabulary is reserved: a non-rotation event may never carry it.
func hasRotationMetadata(metadata Metadata) bool {
	return metadata.RotationDomain != nil || metadata.KeyReference != nil || metadata.KeyVersion != nil
}

// validRotationMetadataFields checks field-level shape only. Which fields may
// be present at all is decided by validRotationProjection.
func validRotationMetadataFields(metadata Metadata) bool {
	if metadata.RotationDomain != nil &&
		*metadata.RotationDomain != rotationDomainKEK && *metadata.RotationDomain != rotationDomainDigest {
		return false
	}
	if metadata.KeyReference != nil && !validID(*metadata.KeyReference) {
		return false
	}
	if metadata.KeyVersion != nil && (*metadata.KeyVersion < 1 || *metadata.KeyVersion > maxSafeInt64) {
		return false
	}
	return true
}

// validRotationProjection is the Go half of the rotation audit contract. It is
// the exact mirror of the database gates installed by migration 000019
// (audit_event resource-type inventory and audit_metadata_is_allowed): the two
// validators must stay consistent, so both encode the same closed
// action/resource pairing, the same outcome-to-error-code mapping and the same
// metadata sets.
func validRotationProjection(input EventInput) bool {
	known := isRotationAction(input.Action)
	if known != (input.ResourceType == ResourceCryptoKey) {
		return false
	}
	if !known {
		return true
	}

	// The rotation coordinator is a system actor: no principal, no workspace,
	// no policy, no evidence references.
	if input.ActorType != ActorSystem || input.ActorPrincipalID != nil ||
		input.OnBehalfOfPrincipalID != nil || input.WorkspaceID != nil ||
		input.PolicyDecisionID != nil || len(input.ReferencedEvidenceIDs) != 0 {
		return false
	}

	switch input.Outcome {
	case OutcomeSuccess:
		if input.ErrorCode != nil {
			return false
		}
	case OutcomeDenied:
		if input.ErrorCode == nil || *input.ErrorCode != ErrorRotationDenied {
			return false
		}
	case OutcomeFailed:
		if input.ErrorCode == nil || *input.ErrorCode != ErrorRotationFailed {
			return false
		}
	default:
		return false
	}

	metadata := input.Metadata
	if metadata.RotationDomain == nil || *metadata.RotationDomain != rotationDomainKEK &&
		*metadata.RotationDomain != rotationDomainDigest {
		return false
	}
	if input.Outcome != OutcomeSuccess {
		// A refusal names no pair: exactly the domain, nothing else.
		if !metadataKeySetIsExact(metadata, []string{"rotation_domain"}) {
			return false
		}
		return true
	}
	// On SUCCESS the resource_id is the active reference and the metadata
	// carries the exact domain/reference/version triple.
	if !metadataKeySetIsExact(metadata, []string{"rotation_domain", "key_reference", "key_version"}) ||
		metadata.KeyReference == nil || metadata.KeyVersion == nil ||
		input.ResourceID != *metadata.KeyReference {
		return false
	}
	return true
}
