package analyticsource

import (
	"crypto/sha256"
	"encoding/binary"

	"knowvault.local/verified-workspace/internal/analytic"
)

// eligibilityBindingDomain separates this seal input from every other digest in
// the repository.
const eligibilityBindingDomain = "knowvault.analyticsource.eligibility-binding.v1"

// eligibilityBinding records that one sealed dataset profile matched exact
// source-authority and governed-exposure facts. It retains the common binding
// tuple both trusted sides reported and an accidental-mutation seal over that
// tuple, and is an integrity and comparison anchor for a future trusted
// resolver.
//
// It is never an authorization decision, execution handle, receipt, credential,
// evidence page, or proof of current access, and it re-proves neither original
// provenance, catalog activity, profile membership, current exposure, nor
// current source authorization.
type eligibilityBinding struct {
	profile analytic.DatasetProfile
	binding bindingFacts
	seal    [32]byte
}

// newEligibilityBinding matches trusted source and exposure facts against one
// sealed profile and retains the common binding tuple the match proved. The
// profile is reconstructed as an owned immutable value, so later caller mutation
// of the input or of any returned DTO cannot reach the stored copy. Every
// refusal returns the zero eligibilityBinding and errMismatch.
func newEligibilityBinding(profile analytic.DatasetProfile, source sourceFacts, exposure exposureFacts) (eligibilityBinding, error) {
	if !profile.Valid() {
		return eligibilityBinding{}, errMismatch
	}
	owned, err := analytic.NewDatasetProfile(profile.Spec())
	if err != nil {
		return eligibilityBinding{}, errMismatch
	}
	if owned.Key() != profile.Key() || owned.Hash() != profile.Hash() || !owned.Valid() {
		return eligibilityBinding{}, errMismatch
	}
	required, err := requiredColumns(owned)
	if err != nil {
		return eligibilityBinding{}, errMismatch
	}
	if err := match(owned.Source(), required, source, exposure); err != nil {
		return eligibilityBinding{}, errMismatch
	}
	value := eligibilityBinding{profile: owned, binding: source.binding}
	value.seal = eligibilityBindingSeal(value.profile, value.binding)
	if !value.valid() {
		return eligibilityBinding{}, errMismatch
	}
	return value, nil
}

// valid reports whether the stored profile and common tuple are well formed,
// the retained source-scope, connection, database, schema, and relation values
// still equal the sealed profile's approved projection, and the stored seal is
// exactly the seal those values reproduce.
func (value eligibilityBinding) valid() bool {
	if !value.profile.Valid() || !value.binding.valid() {
		return false
	}
	approved := value.profile.Source().Values()
	if value.binding.sourceScopeID != approved.SourceScopeID ||
		value.binding.connectionID != approved.ConnectionID ||
		value.binding.databaseIdentity != approved.DatabaseIdentity ||
		value.binding.schemaName != approved.SchemaName ||
		value.binding.relationName != approved.RelationName {
		return false
	}
	return value.seal == eligibilityBindingSeal(value.profile, value.binding)
}

// equal reports whether two valid bindings retain the exact same common tuple,
// profile key, and profile hash. Seals alone are never compared, and a zero or
// invalid binding is never equal to anything, including itself.
func (value eligibilityBinding) equal(other eligibilityBinding) bool {
	if !value.valid() || !other.valid() {
		return false
	}
	return value.binding == other.binding && value.profile.Key() == other.profile.Key() &&
		value.profile.Hash() == other.profile.Hash()
}

// eligibilityBindingSeal returns the domain-separated SHA-256 seal over the
// profile key, the profile hash, and all twelve retained common tuple fields in
// declaration order: the domain contributes its exact bytes, every string field
// contributes its unsigned 64-bit big-endian byte length followed by its exact
// UTF-8 bytes, and every revision contributes its unsigned 64-bit big-endian
// representation. No value can shift the boundary of another. The seal detects
// accidental mutation only; it is not an authentication token, credential, or
// permission.
func eligibilityBindingSeal(profile analytic.DatasetProfile, binding bindingFacts) [32]byte {
	key := profile.Key()
	var encoded []byte
	encoded = append(encoded, eligibilityBindingDomain...)
	encoded = appendSealString(encoded, key.DatasetID())
	encoded = appendSealRevision(encoded, key.Version())
	encoded = appendSealString(encoded, profile.Hash())
	encoded = appendSealString(encoded, binding.workspaceID)
	encoded = appendSealRevision(encoded, binding.workspaceRevision)
	encoded = appendSealString(encoded, binding.workspaceConfigurationHash)
	encoded = appendSealString(encoded, binding.workspaceSourceID)
	encoded = appendSealString(encoded, binding.sourceScopeID)
	encoded = appendSealRevision(encoded, binding.sourceScopeRevision)
	encoded = appendSealString(encoded, binding.sourceScopeConfigurationHash)
	encoded = appendSealString(encoded, binding.connectionID)
	encoded = appendSealRevision(encoded, binding.connectionRevision)
	encoded = appendSealString(encoded, binding.databaseIdentity)
	encoded = appendSealString(encoded, binding.schemaName)
	encoded = appendSealString(encoded, binding.relationName)
	return sha256.Sum256(encoded)
}

// appendSealString appends one unsigned 64-bit big-endian byte length followed
// by the exact UTF-8 bytes of a string.
func appendSealString(encoded []byte, value string) []byte {
	return append(binary.BigEndian.AppendUint64(encoded, uint64(len(value))), value...)
}

// appendSealRevision appends one revision as its unsigned 64-bit big-endian
// representation; validation guarantees the revision is positive before a seal
// is computed.
func appendSealRevision(encoded []byte, value int64) []byte {
	return binary.BigEndian.AppendUint64(encoded, uint64(value))
}
