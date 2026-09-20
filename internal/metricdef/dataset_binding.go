package metricdef

// R1-C2.6b-1: the optional v2 dataset/profile/measure reference.
//
// DatasetBinding is a pure, immutable value. Its fields are unexported and no
// method mutates an existing binding, so an approved definition can never have
// its binding edited in place; a change must flow through Series and issue a
// new version.
//
// The zero DatasetBinding is the explicit legacy/unbound state: it keeps v1
// definitions and old rows representable. A binding is either exactly zero or
// fully valid; there is no partially populated middle state. A bound value
// carries no approval: approval-time authority over the referenced dataset is
// a later card, so a bound binding is never "approved" by itself, and an
// unbound legacy value stays approvable.
//
// The binding deliberately re-declares its own closed mode vocabulary instead
// of importing internal/analytic: this value is a metricdef-owned lifecycle
// field, and the only mode the contract freezes here is LIVE.

import (
	"encoding/hex"
	"strings"
)

const (
	// profileHashPrefix is the exact algorithm tag a canonical profile hash must
	// carry.
	profileHashPrefix = "sha256:"
	// profileHashHexLength is the exact number of lowercase hex characters that
	// must follow the prefix.
	profileHashHexLength = 64
	// maxBindingIDLength bounds dataset and measure identifiers.
	maxBindingIDLength = maxIDLength
)

// DatasetBindingMode is the closed execution-mode vocabulary of a bound
// dataset reference. Exactly one mode exists; there is no floating or replay
// mode in this card.
type DatasetBindingMode string

// BindingModeLive is the only accepted execution mode.
const BindingModeLive DatasetBindingMode = "LIVE"

func (mode DatasetBindingMode) valid() bool { return mode == BindingModeLive }

// ValidBindingMode reports whether value is the one accepted mode.
func ValidBindingMode(value DatasetBindingMode) bool { return value.valid() }

// DatasetBindingInput is the construction input for a bound DatasetBinding. Its
// fields are exported so callers can build the value, but nothing here aliases
// into the constructed binding: every field is a string or integer copied by
// value.
type DatasetBindingInput struct {
	DatasetID      string
	ProfileVersion int64
	ProfileHash    string
	MeasureID      string
	Mode           DatasetBindingMode
}

// DatasetBinding pins an optional metric definition to one immutable dataset
// profile version, its canonical profile hash, one measure and the LIVE
// execution mode. The zero value is the legacy/unbound state.
type DatasetBinding struct {
	datasetID      string
	profileVersion int64
	profileHash    string
	measureID      string
	mode           DatasetBindingMode
}

// NewDatasetBinding validates input and returns the immutable binding it
// describes. An all-zero input is accepted as the explicit legacy/unbound
// state. Any partially populated input, a non-positive profile version, a hash
// that is not exactly "sha256:" plus 64 lowercase hex characters, or a mode
// other than LIVE is refused with the content-free CodeInvalidDefinition.
func NewDatasetBinding(input DatasetBindingInput) (DatasetBinding, error) {
	if input.DatasetID == "" && input.ProfileVersion == 0 && input.ProfileHash == "" &&
		input.MeasureID == "" && input.Mode == "" {
		return DatasetBinding{}, nil
	}
	if !validLabel(input.DatasetID, maxBindingIDLength) || !validLabel(input.MeasureID, maxBindingIDLength) ||
		input.ProfileVersion < 1 || !validProfileHash(input.ProfileHash) || !input.Mode.valid() {
		return DatasetBinding{}, newError(CodeInvalidDefinition)
	}
	return DatasetBinding{
		datasetID:      input.DatasetID,
		profileVersion: input.ProfileVersion,
		profileHash:    input.ProfileHash,
		measureID:      input.MeasureID,
		mode:           input.Mode,
	}, nil
}

// validProfileHash requires the exact canonical form: the "sha256:" tag, 64
// lowercase hex characters, and nothing else. The label check rejects spaces,
// control characters, non-ASCII bytes and invalid UTF-8 before hex decoding.
func validProfileHash(value string) bool {
	if !validLabel(value, maxIDLength) || len(value) != len(profileHashPrefix)+profileHashHexLength {
		return false
	}
	if !strings.HasPrefix(value, profileHashPrefix) {
		return false
	}
	digest := value[len(profileHashPrefix):]
	// hex.DecodeString accepts uppercase A-F, so reject any character outside
	// [0-9a-f] before decoding to enforce the exact lowercase canonical form.
	for i := 0; i < len(digest); i++ {
		if !isLowerHexDigit(digest[i]) {
			return false
		}
	}
	_, err := hex.DecodeString(digest)
	return err == nil
}

// isLowerHexDigit reports whether b is one of the 16 lowercase hex digits.
func isLowerHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}

// IsZero reports whether the binding is the explicit legacy/unbound state,
// with no member populated at all.
func (binding DatasetBinding) IsZero() bool {
	return binding.datasetID == "" && binding.profileVersion == 0 && binding.profileHash == "" &&
		binding.measureID == "" && binding.mode == ""
}

// Bound reports whether the binding carries a fully populated dataset
// reference. It is the lifecycle predicate that separates unbound legacy
// values from bound ones; it does not imply approval.
func (binding DatasetBinding) Bound() bool { return !binding.IsZero() }

// Valid reports whether the binding is either the zero legacy value or a fully
// populated, well-formed bound value. There is no partially populated middle
// state.
func (binding DatasetBinding) Valid() bool {
	if binding.IsZero() {
		return true
	}
	return validLabel(binding.datasetID, maxBindingIDLength) && binding.profileVersion >= 1 &&
		validProfileHash(binding.profileHash) && validLabel(binding.measureID, maxBindingIDLength) &&
		binding.mode.valid()
}

// DatasetID is the referenced dataset id (empty when unbound).
func (binding DatasetBinding) DatasetID() string { return binding.datasetID }

// ProfileVersion is the pinned positive profile version (0 when unbound).
func (binding DatasetBinding) ProfileVersion() int64 { return binding.profileVersion }

// ProfileHash is the canonical "sha256:" hash of the pinned profile.
func (binding DatasetBinding) ProfileHash() string { return binding.profileHash }

// MeasureID is the referenced measure id (empty when unbound).
func (binding DatasetBinding) MeasureID() string { return binding.measureID }

// Mode is the closed execution mode (BindingModeLive when bound).
func (binding DatasetBinding) Mode() DatasetBindingMode { return binding.mode }
