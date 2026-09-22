package analyticsource

import (
	"crypto/sha256"
	"encoding/binary"

	"knowvault.local/verified-workspace/internal/analytic"
)

// eligibilityBindingDomain separates this seal input from every other digest in
// the repository.
const eligibilityBindingDomain = "knowvault.analyticsource.eligibility-binding.v2"

// executionFacts is the comparable execution metadata one match proved: the
// approved source projection lineage, revision and contract hash, and the
// governed exposure schema revision and hash. It is retained so that two
// resolutions of the current source can prove the same revision and contract
// facts did not drift; it is neither an execution handle nor public authority.
type executionFacts struct {
	projectionLineageID    string
	projectionRevision     int64
	projectionContractHash string
	exposedSchemaRevision  int64
	exposedSchemaHash      string
}

// valid reports whether every retained execution member is well formed exactly
// as received and equal to the approved projection's execution values: no value
// is trimmed, case folded, or otherwise normalized before validation.
func (value executionFacts) valid(profile analytic.DatasetProfile) bool {
	if !profile.Valid() {
		return false
	}
	if !validBindingIdentity(value.projectionLineageID) || !validBindingRevision(value.projectionRevision) ||
		!validBindingHash(value.projectionContractHash) || !validBindingRevision(value.exposedSchemaRevision) ||
		!validBindingHash(value.exposedSchemaHash) {
		return false
	}
	approved := profile.Source().Values()
	return value.projectionLineageID == approved.ProjectionLineageID &&
		value.projectionRevision == approved.ProjectionRevision &&
		value.projectionContractHash == approved.ProjectionContractHash &&
		value.exposedSchemaRevision == approved.ExposedSchemaRevision &&
		value.exposedSchemaHash == approved.ExposedSchemaHash
}

// eligibilityBinding records that one sealed dataset profile matched exact
// source-authority and governed-exposure facts. It retains the common binding
// tuple both trusted sides reported, the execution metadata the match proved,
// and an accidental-mutation seal over both, and is an integrity and comparison
// anchor for a future trusted resolver.
//
// It is never an authorization decision, execution handle, receipt, credential,
// evidence page, or proof of current access, and it re-proves neither original
// provenance, catalog activity, profile membership, current exposure, nor
// current source authorization.
type eligibilityBinding struct {
	profile   analytic.DatasetProfile
	binding   bindingFacts
	execution executionFacts
	seal      [32]byte
}

// newEligibilityBinding matches trusted source and exposure facts against one
// sealed profile and retains the common binding tuple and the execution metadata
// the match proved. The profile is reconstructed as an owned immutable value, so
// later caller mutation of the input or of any returned DTO cannot reach the
// stored copy. Every refusal returns the zero eligibilityBinding and errMismatch.
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
	value := eligibilityBinding{
		profile: owned,
		binding: source.binding,
		execution: executionFacts{
			projectionLineageID:    source.projectionLineageID,
			projectionRevision:     source.projectionRevision,
			projectionContractHash: source.projectionContractHash,
			exposedSchemaRevision:  exposure.exposedSchemaRevision,
			exposedSchemaHash:      exposure.exposedSchemaHash,
		},
	}
	value.seal = eligibilityBindingSeal(value.profile, value.binding, value.execution)
	if !value.valid() {
		return eligibilityBinding{}, errMismatch
	}
	return value, nil
}

// valid reports whether the stored profile, common tuple and execution metadata
// are well formed, the retained source-scope, connection, database, schema, and
// relation values still equal the sealed profile's approved projection, the
// retained execution facts still equal the approved projection's execution
// values, and the stored seal is exactly the seal those values reproduce.
func (value eligibilityBinding) valid() bool {
	if !value.profile.Valid() || !value.binding.valid() || !value.execution.valid(value.profile) {
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
	return value.seal == eligibilityBindingSeal(value.profile, value.binding, value.execution)
}

// equal reports whether two valid bindings retain the exact same common tuple,
// execution metadata, profile key, and profile hash. Seals alone are never
// compared, and a zero or invalid binding is never equal to anything, including
// itself.
func (value eligibilityBinding) equal(other eligibilityBinding) bool {
	if !value.valid() || !other.valid() {
		return false
	}
	return value.binding == other.binding && value.execution == other.execution &&
		value.profile.Key() == other.profile.Key() && value.profile.Hash() == other.profile.Hash()
}

// eligibilityBindingSeal returns the domain-separated SHA-256 seal over the
// profile key, the profile hash, all twelve retained common tuple fields in
// declaration order, and the five retained execution members in declaration
// order: the domain contributes its exact bytes, every string field contributes
// its unsigned 64-bit big-endian byte length followed by its exact UTF-8 bytes,
// and every revision contributes its unsigned 64-bit big-endian representation.
// No value can shift the boundary of another. The seal detects accidental
// mutation only; it is not an authentication token, credential, or permission.
func eligibilityBindingSeal(profile analytic.DatasetProfile, binding bindingFacts, execution executionFacts) [32]byte {
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
	encoded = appendSealString(encoded, execution.projectionLineageID)
	encoded = appendSealRevision(encoded, execution.projectionRevision)
	encoded = appendSealString(encoded, execution.projectionContractHash)
	encoded = appendSealRevision(encoded, execution.exposedSchemaRevision)
	encoded = appendSealString(encoded, execution.exposedSchemaHash)
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
