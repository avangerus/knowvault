package postgresqlquery

import (
	"bytes"
	"encoding/json/jsontext"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"knowvault.local/verified-workspace/internal/source/canon"
)

const (
	maxJSONPathDepth = 32
	maxJSONLeafCount = 256
)

// JSONLeaf is one scalar (or empty container) in a JSON business-object
// payload. Path is an RFC 6901 JSON Pointer relative to the payload root. Raw
// is canonical JSON for that value; no Go map/float conversion is performed.
type JSONLeaf struct {
	Path string
	Raw  jsontext.Value
}

// JSONLeaves returns bounded canonical leaves for a JSON/JSONB payload. Object
// member names are escaped as JSON Pointer tokens and array indexes are stable
// decimal tokens. Empty objects/arrays remain addressable at their own path so
// a valid payload can never silently disappear from Evidence.
func JSONLeaves(value jsontext.Value) ([]JSONLeaf, error) {
	if len(value) == 0 {
		return nil, &Error{code: CodeInvalidValue}
	}
	canonical := value.Clone()
	if err := canonical.Canonicalize(); err != nil {
		return nil, &Error{code: CodeInvalidValue, cause: err}
	}
	result := make([]JSONLeaf, 0, 8)
	if err := walkJSONLeaves(canonical, "", 0, &result); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, &Error{code: CodeInvalidValue}
	}
	return result, nil
}

func walkJSONLeaves(value jsontext.Value, path string, depth int, result *[]JSONLeaf) error {
	if depth > maxJSONPathDepth || len(*result) >= maxJSONLeafCount {
		return &Error{code: CodeLimitExceeded}
	}
	switch value.Kind() {
	case jsontext.KindBeginObject:
		decoder := jsontext.NewDecoder(bytes.NewReader(value))
		if _, err := decoder.ReadToken(); err != nil {
			return &Error{code: CodeInvalidValue, cause: err}
		}
		members := 0
		for decoder.PeekKind() != jsontext.KindEndObject {
			if decoder.PeekKind() == jsontext.KindInvalid {
				return &Error{code: CodeInvalidValue}
			}
			name, err := decoder.ReadToken()
			if err != nil || name.Kind() != jsontext.KindString {
				return &Error{code: CodeInvalidValue, cause: err}
			}
			// jsontext.Token borrows decoder storage and is voided by the next
			// decoder call, so materialize the member name before ReadValue.
			memberName := name.String()
			child, err := decoder.ReadValue()
			if err != nil {
				return &Error{code: CodeInvalidValue, cause: err}
			}
			childPath := path + "/" + escapeJSONPointerToken(memberName)
			if err := walkJSONLeaves(child, childPath, depth+1, result); err != nil {
				return err
			}
			members++
			if members > maxJSONLeafCount {
				return &Error{code: CodeLimitExceeded}
			}
		}
		if _, err := decoder.ReadToken(); err != nil {
			return &Error{code: CodeInvalidValue, cause: err}
		}
		if members == 0 {
			*result = append(*result, JSONLeaf{Path: path, Raw: value.Clone()})
		}
		return nil
	case jsontext.KindBeginArray:
		decoder := jsontext.NewDecoder(bytes.NewReader(value))
		if _, err := decoder.ReadToken(); err != nil {
			return &Error{code: CodeInvalidValue, cause: err}
		}
		index := 0
		for decoder.PeekKind() != jsontext.KindEndArray {
			if decoder.PeekKind() == jsontext.KindInvalid {
				return &Error{code: CodeInvalidValue}
			}
			child, err := decoder.ReadValue()
			if err != nil {
				return &Error{code: CodeInvalidValue, cause: err}
			}
			if err := walkJSONLeaves(child, path+"/"+strconv.Itoa(index), depth+1, result); err != nil {
				return err
			}
			index++
			if index > maxJSONLeafCount {
				return &Error{code: CodeLimitExceeded}
			}
		}
		if _, err := decoder.ReadToken(); err != nil {
			return &Error{code: CodeInvalidValue, cause: err}
		}
		if index == 0 {
			*result = append(*result, JSONLeaf{Path: path, Raw: value.Clone()})
		}
		return nil
	default:
		*result = append(*result, JSONLeaf{Path: path, Raw: value.Clone()})
		return nil
	}
}

func escapeJSONPointerToken(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(value, "~", "~0"), "/", "~1")
}

// ValidateJSONPath is shared by anchor and publication code. The root path is
// the empty string; all other paths use RFC 6901's slash-separated form and
// contain no control characters.
func ValidateJSONPath(path string) error {
	if len(path) > 4096 || strings.IndexAny(path, "\x00\r\n") >= 0 {
		return fmt.Errorf("invalid JSON pointer")
	}
	if path == "" {
		return nil
	}
	if path[0] != '/' {
		return fmt.Errorf("invalid JSON pointer")
	}
	// RFC 6901 allows arbitrary Unicode member names, but `~` is an escape
	// introducer and may only be followed by 0 or 1. Rejecting other escapes
	// keeps the persisted path canonical and prevents two spellings of one
	// member from producing ambiguous Evidence links.
	for index := 0; index < len(path); {
		r, size := utf8.DecodeRuneInString(path[index:])
		if r == utf8.RuneError && size == 1 {
			return fmt.Errorf("invalid JSON pointer UTF-8")
		}
		if r == '~' {
			if index+1 >= len(path) || (path[index+1] != '0' && path[index+1] != '1') {
				return fmt.Errorf("invalid JSON pointer escape")
			}
			index += 2
			continue
		}
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return fmt.Errorf("invalid JSON pointer control")
		}
		index += size
	}
	return nil
}

// JSONLeafValueHash binds the path to the typed JSON value. Two equal scalar
// values at different paths therefore retain distinct, verifiable Evidence.
func JSONLeafValueHash(column Column, leaf JSONLeaf) (string, error) {
	if err := ValidateJSONPath(leaf.Path); err != nil || leaf.Raw.Kind() == jsontext.KindInvalid {
		return "", &Error{code: CodeInvalidValue, cause: err}
	}
	canonical := leaf.Raw.Clone()
	if err := canonical.Canonicalize(); err != nil {
		return "", &Error{code: CodeInvalidValue, cause: err}
	}
	raw, err := canon.CanonicalJSON(struct {
		Ordinal         int            `json:"ordinal"`
		TypeFingerprint string         `json:"type_fingerprint"`
		LogicalType     LogicalType    `json:"logical_type"`
		JSONPath        string         `json:"json_path"`
		Value           jsontext.Value `json:"value"`
	}{column.Ordinal, column.TypeFingerprint, column.LogicalType, leaf.Path, canonical})
	if err != nil {
		return "", &Error{code: CodeInvalidValue, cause: err}
	}
	return canon.Hash(raw), nil
}
