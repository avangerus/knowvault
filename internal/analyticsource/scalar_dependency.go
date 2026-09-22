package analyticsource

import (
	"bytes"
	jsontext "encoding/json/jsontext"
	jsonv2 "encoding/json/v2"

	"knowvault.local/verified-workspace/internal/source/canon"
)

// The one sealed dependency schema and kind. The schema names the exact payload
// version and the kind records that this is a governed projection of one
// already-authorized observation, not a new read or an authorization decision.
const (
	scalarDependencySchema = "knowvault.analyticsource.scalar-dependency.v1"
	scalarDependencyKind   = "GOVERNED_PROJECTION"
)

// ScalarDependency is the private, persistable dependency record of one live
// scalar observation. It binds the exact sealed observation to the Question Run
// that produced it and retains only the neutral authority facts a later fresh
// reauthorization needs, so a future caller can re-prove the same workspace,
// catalog, dataset, source, connection, projection and exposure identities
// without trusting a manufactured dependency id, a row, a value or the original
// principal. Its only state is the private canonical payload; it exposes no
// exported field, constructor, getter or decoder, and generic JSON renders it as
// the opaque empty object.
type ScalarDependency struct {
	payload scalarDependencyPayload
}

// MarshalJSON renders the dependency as an opaque empty JSON object so that no
// retained authority fact can leak through generic JSON logging. The canonical
// payload is reachable only through EncodeScalarDependency.
func (ScalarDependency) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

// scalarDependencyPayload is the exact canonical payload of one dependency. Its
// json tags name the frozen wire members; the payload carries only neutral
// authority facts: the schema and kind, the Question Run the observation belongs
// to, the retained receipt schema and digest, and the organization, workspace,
// catalog, dataset, source-scope, connection, projection and exposure identities
// and revisions the observation already proved.
//
// It deliberately carries no principal, request or actor, no metric, value,
// period, count, snapshot, limit or window, no row payload, no SQL, no
// credential and no physical schema, relation or column name: later
// authorization uses the current caller and the retained neutral facts only.
type scalarDependencyPayload struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	ReceiptSchema string `json:"receipt_schema"`
	ReceiptDigest string `json:"receipt_digest"`
	QuestionRunID string `json:"question_run_id"`

	OrganizationID string `json:"organization_id"`

	WorkspaceID                string `json:"workspace_id"`
	WorkspaceRevision          int64  `json:"workspace_revision"`
	WorkspaceConfigurationHash string `json:"workspace_configuration_hash"`
	WorkspaceSourceID          string `json:"workspace_source_id"`

	CatalogID       string `json:"catalog_id"`
	CatalogRevision int64  `json:"catalog_revision"`
	CatalogHash     string `json:"catalog_hash"`

	DatasetID      string `json:"dataset_id"`
	ProfileVersion int64  `json:"profile_version"`
	ProfileHash    string `json:"profile_hash"`

	SourceScopeID                string `json:"source_scope_id"`
	SourceScopeRevision          int64  `json:"source_scope_revision"`
	SourceScopeConfigurationHash string `json:"source_scope_configuration_hash"`

	ConnectionID       string `json:"connection_id"`
	ConnectionRevision int64  `json:"connection_revision"`
	DatabaseIdentity   string `json:"database_identity"`

	ProjectionLineageID    string `json:"projection_lineage_id"`
	ProjectionRevision     int64  `json:"projection_revision"`
	ProjectionContractHash string `json:"projection_contract_hash"`

	ExposedSchemaRevision int64  `json:"exposed_schema_revision"`
	ExposedSchemaHash     string `json:"exposed_schema_hash"`
}

// BindScalarDependency binds one valid nonzero sealed ScalarObservation to one
// exact safe Question Run id and returns the private persistable dependency
// record. Every dependency fact except the run id is copied from the
// observation's own private validated receipt, so no caller can supply an
// identity, revision, hash or digest and no public projection is consulted.
//
// It refuses a zero or unverifiable observation, a run id outside the exact safe
// identity shape, and any receipt fact that does not validate. Every refusal
// returns the exact zero ScalarDependency and the exact unwrapped, content-free
// errMismatch, so binding is neither an existence nor an authorization oracle.
func BindScalarDependency(questionRunID string, observation ScalarObservation) (ScalarDependency, error) {
	if !validBindingIdentity(questionRunID) || !validSealedScalarObservation(observation) {
		return ScalarDependency{}, errMismatch
	}
	receipt := observation.completion.receipt
	envelope := receipt.envelope
	dependency := scalarDependencyPayload{
		Schema:        scalarDependencySchema,
		Kind:          scalarDependencyKind,
		ReceiptSchema: envelope.Schema,
		ReceiptDigest: receipt.digest,
		QuestionRunID: questionRunID,

		OrganizationID: envelope.Access.OrganizationID,

		WorkspaceID:                envelope.Workspace.WorkspaceID,
		WorkspaceRevision:          envelope.Workspace.WorkspaceRevision,
		WorkspaceConfigurationHash: envelope.Workspace.WorkspaceConfigurationHash,
		WorkspaceSourceID:          envelope.Workspace.WorkspaceSourceID,

		CatalogID:       envelope.Catalog.CatalogID,
		CatalogRevision: envelope.Catalog.CatalogRevision,
		CatalogHash:     envelope.Catalog.CatalogHash,

		DatasetID:      envelope.Profile.DatasetID,
		ProfileVersion: envelope.Profile.Version,
		ProfileHash:    envelope.Profile.ProfileHash,

		SourceScopeID:                envelope.Source.SourceScopeID,
		SourceScopeRevision:          envelope.Source.SourceScopeRevision,
		SourceScopeConfigurationHash: envelope.Source.SourceScopeConfigurationHash,

		ConnectionID:       envelope.Source.ConnectionID,
		ConnectionRevision: envelope.Source.ConnectionRevision,
		DatabaseIdentity:   envelope.Source.DatabaseIdentity,

		ProjectionLineageID:    envelope.Source.ProjectionLineageID,
		ProjectionRevision:     envelope.Source.ProjectionRevision,
		ProjectionContractHash: envelope.Source.ProjectionContractHash,

		ExposedSchemaRevision: envelope.Source.ExposedSchemaRevision,
		ExposedSchemaHash:     envelope.Source.ExposedSchemaHash,
	}
	if !dependency.valid() {
		return ScalarDependency{}, errMismatch
	}
	return ScalarDependency{payload: dependency}, nil
}

// validSealedScalarObservation reports whether one sealed observation still
// names an exact, coherent, nonzero completion: its receipt must recompute to
// its retained digest and its reducer proof must still name the exact value,
// contributing rows and snapshot hash the receipt envelope carries. It reads the
// observation's private state directly, so no public projection can supply or
// replace a dependency fact.
func validSealedScalarObservation(observation ScalarObservation) bool {
	completion := observation.completion
	receipt := completion.receipt
	if !receipt.valid() {
		return false
	}
	envelope := receipt.envelope
	return completion.sum.value != "" &&
		completion.sum.value == envelope.Result.Value &&
		completion.sum.contributingRows == envelope.Snapshot.ContributingRows &&
		completion.sum.snapshotHash == envelope.Snapshot.SnapshotHash &&
		scalarSumHashPattern.MatchString(completion.sum.snapshotHash)
}

// valid reports whether every retained dependency member is well formed exactly
// as received: the exact schema and kind, the exact dependency and receipt
// schemas, and every identity, revision and hash under the existing closed
// analyticsource validators. No value is trimmed, case folded, defaulted or
// otherwise repaired before validation.
func (value scalarDependencyPayload) valid() bool {
	if value.Schema != scalarDependencySchema || value.Kind != scalarDependencyKind ||
		value.ReceiptSchema != scalarReceiptSchema ||
		!validBindingIdentity(value.QuestionRunID) || !validBindingHash(value.ReceiptDigest) {
		return false
	}
	if !validBindingIdentity(value.OrganizationID) {
		return false
	}
	if !validBindingIdentity(value.WorkspaceID) || !validBindingRevision(value.WorkspaceRevision) ||
		!validBindingHash(value.WorkspaceConfigurationHash) || !validBindingIdentity(value.WorkspaceSourceID) {
		return false
	}
	if !validBindingIdentity(value.CatalogID) || !validBindingRevision(value.CatalogRevision) ||
		!validBindingHash(value.CatalogHash) {
		return false
	}
	if !validBindingIdentity(value.DatasetID) || !validBindingRevision(value.ProfileVersion) ||
		!validBindingHash(value.ProfileHash) {
		return false
	}
	if !validBindingIdentity(value.SourceScopeID) || !validBindingRevision(value.SourceScopeRevision) ||
		!validBindingHash(value.SourceScopeConfigurationHash) {
		return false
	}
	if !validBindingIdentity(value.ConnectionID) || !validBindingRevision(value.ConnectionRevision) ||
		!validBindingIdentity(value.DatabaseIdentity) {
		return false
	}
	if !validBindingIdentity(value.ProjectionLineageID) || !validBindingRevision(value.ProjectionRevision) ||
		!validBindingHash(value.ProjectionContractHash) {
		return false
	}
	return validBindingRevision(value.ExposedSchemaRevision) && validBindingHash(value.ExposedSchemaHash)
}

// EncodeScalarDependency is one of the two sole persistence boundaries for the
// dependency record. It refuses a zero or invalid dependency and otherwise
// returns the exact canonical JCS bytes of the private payload. The bytes carry
// no principal, request, actor, metric, value, period, count, snapshot, limit,
// window, row, SQL, credential or physical name.
func EncodeScalarDependency(dependency ScalarDependency) ([]byte, error) {
	if !dependency.payload.valid() {
		return nil, errMismatch
	}
	raw, err := canon.CanonicalJSON(dependency.payload)
	if err != nil {
		return nil, errMismatch
	}
	return raw, nil
}

// DecodeScalarDependency is the other sole persistence boundary. It strictly
// decodes exactly one canonical dependency payload and returns the sealed
// dependency; it proves structure and integrity only and never current
// authorization.
//
// It rejects unknown and duplicate members, refuses a zero or malformed
// document, requires the input to be byte-for-byte the canonical encoding of the
// decoded payload, and validates the exact enums and every identity, revision
// and hash. Every refusal returns the exact zero ScalarDependency and the exact
// unwrapped, content-free errMismatch, so decoding is neither an existence nor
// an authorization oracle.
func DecodeScalarDependency(raw []byte) (ScalarDependency, error) {
	if len(raw) == 0 {
		return ScalarDependency{}, errMismatch
	}
	var payload scalarDependencyPayload
	if err := jsonv2.Unmarshal(raw, &payload,
		jsonv2.RejectUnknownMembers(true),
		jsontext.AllowDuplicateNames(false)); err != nil {
		return ScalarDependency{}, errMismatch
	}
	if !payload.valid() {
		return ScalarDependency{}, errMismatch
	}
	canonical, err := canon.CanonicalJSON(payload)
	if err != nil || !bytes.Equal(canonical, raw) {
		return ScalarDependency{}, errMismatch
	}
	return ScalarDependency{payload: payload}, nil
}

// VerifyScalarDependencyBinding proves, structurally and without disclosing any
// private fact, that one opaque dependency belongs to the exact Question Run and
// live receipt it is stored beside. It returns nil only when the dependency's
// private payload is valid and its exact Question Run id, receipt schema and
// receipt digest equal the three caller-supplied values byte for byte; the
// supplied run id must pass the existing closed identity validator, the supplied
// schema must be exactly scalarReceiptSchema with no alternate or legacy value,
// and the supplied digest must pass the existing closed hash validator.
//
// It is a pure structural check and never a current authorization: it reads no
// repository, performs no source execution, decodes nothing, repairs nothing and
// grants no access. It returns no dependency and no field, adds no getter, and
// every refusal returns the exact unwrapped, content-free errMismatch, so
// verification is neither an existence nor an authorization oracle.
func VerifyScalarDependencyBinding(
	questionRunID string,
	receiptSchema string,
	receiptDigest string,
	dependency ScalarDependency,
) error {
	if !validBindingIdentity(questionRunID) || receiptSchema != scalarReceiptSchema ||
		!validBindingHash(receiptDigest) {
		return errMismatch
	}
	payload := dependency.payload
	if !payload.valid() {
		return errMismatch
	}
	if payload.QuestionRunID != questionRunID || payload.ReceiptSchema != receiptSchema ||
		payload.ReceiptDigest != receiptDigest {
		return errMismatch
	}
	return nil
}
