package analyticsource

import (
	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
	"knowvault.local/verified-workspace/internal/workspace/repository"
)

// Resolution carries one already-sealed eligibility binding together with the
// exact resolved authority result that binding was sealed from, as an opaque
// value. Both fields are private, so a caller can observe only Valid and the
// generic JSON rendering: there is deliberately no constructor, decoder,
// accessor or String/GoString, and nothing here can build, format or serialize
// a value that claims more than the caller already holds.
//
// Valid reports only whether the retained binding still reproduces its own seal
// and whether the retained authority result still reports the exact workspace,
// source, common binding and source-projection facts that binding was sealed
// from. It is not an authority, execution or disclosure predicate: it proves
// neither current workspace authority, nor catalog activity, nor current
// exposure, nor current source authorization.
type Resolution struct {
	binding   eligibilityBinding
	authority repository.PostgreSQLAuthorityResult
}

// Valid reports whether the retained private binding is well formed, still
// equals the approved projection it was sealed from, still reproduces its own
// seal, and is still reproduced by the retained private authority result. The
// zero value is invalid.
func (value Resolution) Valid() bool {
	return value.binding.valid() && compatibleResolutionAuthority(value.authority, value.binding)
}

// MarshalJSON renders the resolution as an opaque empty JSON object so that no
// retained private eligibility or authority value can leak through generic JSON
// logging.
func (Resolution) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// resolutionAuthorityView is the private read-only view of one already-resolved
// authority result a retained Resolution re-proves its binding against. It is
// the repository source view plus the server-owned connector limits, so
// repository.PostgreSQLAuthorityResult and the same-package fake source view
// both satisfy it without a new production seam or a caller-supplied decoder.
type resolutionAuthorityView interface {
	repositorySourceView
	Limits() postgresqlquery.Limits
}

// compatibleResolutionAuthority reports whether one retained authority result
// still reproduces the exact facts the retained binding was sealed from: a valid
// source projection, valid server-owned limits, the one managed access mode,
// full column compatibility with the sealed profile, the exact common binding
// tuple, and the exact source-projection lineage, revision and contract hash.
//
// It is pure, reads no repository, and compares no exposure fact: binding.valid
// already owns the retained sealed exposure/profile state, and fresh exposure
// authority stays with the resolver. A zero, tampered or drifted authority
// result refuses.
func compatibleResolutionAuthority(authority resolutionAuthorityView, binding eligibilityBinding) bool {
	if authority == nil || !binding.valid() {
		return false
	}
	projection := authority.Projection()
	if err := projection.Validate(); err != nil {
		return false
	}
	if err := authority.Limits().Validate(); err != nil {
		return false
	}
	if authority.AccessMode() != repositoryManagedAccessMode {
		return false
	}
	if err := repositoryColumnCompatibility(binding.profile, projection); err != nil {
		return false
	}
	facts, ok := repositorySourceFacts(authority, projection)
	if !ok {
		return false
	}
	return facts.binding == binding.binding &&
		facts.projectionLineageID == binding.execution.projectionLineageID &&
		facts.projectionRevision == binding.execution.projectionRevision &&
		facts.projectionContractHash == binding.execution.projectionContractHash
}
