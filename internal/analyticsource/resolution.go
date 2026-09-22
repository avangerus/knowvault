package analyticsource

// Resolution carries one already-sealed eligibility binding as an opaque value.
// The binding field is private, so a caller can observe only Valid and the
// generic JSON rendering: there is deliberately no constructor, decoder,
// accessor or String/GoString, and nothing here can build, format or serialize
// a value that claims more than the caller already holds.
//
// Valid reports only whether the retained binding still reproduces its own
// seal. It is not an authority, execution or disclosure predicate: it proves
// neither current workspace authority, nor catalog activity, nor current
// exposure, nor current source authorization.
type Resolution struct {
	binding eligibilityBinding
}

// Valid reports whether the retained private binding is well formed, still
// equals the approved projection it was sealed from, and still reproduces its
// own seal. The zero value is invalid.
func (value Resolution) Valid() bool { return value.binding.valid() }

// MarshalJSON renders the resolution as an opaque empty JSON object so that no
// retained private eligibility value can leak through generic JSON logging.
func (Resolution) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }
