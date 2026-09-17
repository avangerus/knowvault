package postgresqlquery

import (
	"bytes"
	"encoding/hex"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"knowvault.local/verified-workspace/internal/source/canon"
)

var (
	integerPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)$`)
	numericPattern = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?$`)
	uuidPattern    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
)

// ValueEntry is one typed element of the canonical row array. ValueTag keeps
// NULL distinct from an empty string and from a zero scalar. JSON/JSONB values
// are embedded JSON values, not driver-returned strings.
type ValueEntry struct {
	Ordinal         int         `json:"ordinal"`
	TypeFingerprint string      `json:"type_fingerprint"`
	LogicalType     LogicalType `json:"logical_type"`
	ValueTag        string      `json:"value_tag"`
	Value           any         `json:"value"`
}

// Row is the immutable canonical representation of one external result row.
// Canonical is the exact JCS bytes hashed for SourceVersion identity; Values
// are retained only for the staging/publication owner, never for model input.
type Row struct {
	Values    []ValueEntry
	Canonical []byte
	Hash      string
}

func CanonicalizeRow(columns []Column, raw []any) (Row, error) {
	if len(columns) == 0 || len(columns) != len(raw) {
		return Row{}, &Error{code: CodeInvalidValue}
	}
	ordered := append([]Column(nil), columns...)
	// Projection.Validate guarantees order, but this function is also a direct
	// owner boundary and therefore repeats the check instead of trusting a
	// caller-owned slice.
	for index, column := range ordered {
		if column.Ordinal != index+1 {
			return Row{}, &Error{code: CodeInvalidProjection}
		}
	}
	entries := make([]ValueEntry, len(ordered))
	for index, column := range ordered {
		entry, err := canonicalValue(column, raw[index])
		if err != nil {
			return Row{}, err
		}
		entries[index] = entry
	}
	canonical, err := canon.CanonicalJSON(entries)
	if err != nil {
		return Row{}, &Error{code: CodeInvalidValue, cause: err}
	}
	return Row{Values: entries, Canonical: canonical, Hash: canon.Hash(canonical)}, nil
}

func canonicalValue(column Column, raw any) (ValueEntry, error) {
	entry := ValueEntry{
		Ordinal: column.Ordinal, TypeFingerprint: column.TypeFingerprint,
		LogicalType: column.LogicalType,
	}
	if raw == nil || (isNilPointer(raw)) {
		if !column.Nullable {
			return ValueEntry{}, &Error{code: CodeInvalidValue}
		}
		entry.ValueTag = "NULL"
		entry.Value = nil
		return entry, nil
	}

	var value any
	var tag string
	switch column.LogicalType {
	case TypeBool:
		canonical, err := boolValue(raw)
		if err != nil {
			return ValueEntry{}, err
		}
		value, tag = canonical, "BOOL"
	case TypeInt:
		canonical, err := integerValue(raw)
		if err != nil {
			return ValueEntry{}, err
		}
		if err := validateIntegerRange(column.TypeFingerprint, canonical); err != nil {
			return ValueEntry{}, err
		}
		value, tag = canonical, "INT"
	case TypeNumeric:
		canonical, err := numericValue(raw, column.Precision, column.Scale)
		if err != nil {
			return ValueEntry{}, err
		}
		value, tag = canonical, "NUMERIC"
	case TypeUUID:
		canonical, err := uuidValue(raw)
		if err != nil {
			return ValueEntry{}, err
		}
		value, tag = canonical, "UUID"
	case TypeDate:
		canonical, err := dateValue(raw)
		if err != nil {
			return ValueEntry{}, err
		}
		value, tag = canonical, "DATE"
	case TypeTimestamp:
		canonical, err := timestampValue(raw, column.Precision, false)
		if err != nil {
			return ValueEntry{}, err
		}
		value, tag = canonical, "TIMESTAMP_LOCAL"
	case TypeTimestamptz:
		canonical, err := timestampValue(raw, column.Precision, true)
		if err != nil {
			return ValueEntry{}, err
		}
		value, tag = canonical, "TIMESTAMPTZ_UTC"
	case TypeText:
		canonical, err := textValue(raw, column.MaxBytes)
		if err != nil {
			return ValueEntry{}, err
		}
		value, tag = canonical, "TEXT"
	case TypeJSON, TypeJSONB:
		canonical, err := jsonValue(raw)
		if err != nil {
			return ValueEntry{}, err
		}
		if column.MaxBytes > 0 && len(canonical) > column.MaxBytes {
			return ValueEntry{}, &Error{code: CodeInvalidValue}
		}
		value, tag = jsontext.Value(canonical), string(column.LogicalType)
	default:
		return ValueEntry{}, &Error{code: CodeUnsupportedType}
	}
	entry.ValueTag, entry.Value = tag, value
	return entry, nil
}

func isNilPointer(value any) bool {
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func boolValue(raw any) (bool, error) {
	switch value := raw.(type) {
	case bool:
		return value, nil
	case string:
		if value == "true" {
			return true, nil
		}
		if value == "false" {
			return false, nil
		}
	case []byte:
		return boolValue(string(value))
	}
	return false, &Error{code: CodeInvalidValue}
}

func integerValue(raw any) (string, error) {
	var value string
	switch item := raw.(type) {
	case int:
		value = strconv.Itoa(item)
	case int8:
		value = strconv.FormatInt(int64(item), 10)
	case int16:
		value = strconv.FormatInt(int64(item), 10)
	case int32:
		value = strconv.FormatInt(int64(item), 10)
	case int64:
		value = strconv.FormatInt(item, 10)
	case uint:
		value = strconv.FormatUint(uint64(item), 10)
	case uint8:
		value = strconv.FormatUint(uint64(item), 10)
	case uint16:
		value = strconv.FormatUint(uint64(item), 10)
	case uint32:
		value = strconv.FormatUint(uint64(item), 10)
	case uint64:
		if item > math.MaxInt64 {
			return "", &Error{code: CodeInvalidValue}
		}
		value = strconv.FormatUint(item, 10)
	case string:
		value = item
	case []byte:
		value = string(item)
	default:
		return "", &Error{code: CodeInvalidValue}
	}
	if !integerPattern.MatchString(value) || strings.HasPrefix(value, "-0") {
		return "", &Error{code: CodeInvalidValue}
	}
	return value, nil
}

func validateIntegerRange(fingerprint, value string) error {
	bits := 64
	switch {
	case strings.Contains(fingerprint, "oid:21") || strings.Contains(strings.ToLower(fingerprint), "int2"):
		bits = 16
	case strings.Contains(fingerprint, "oid:23") || strings.Contains(strings.ToLower(fingerprint), "int4"):
		bits = 32
	case strings.Contains(fingerprint, "oid:20") || strings.Contains(strings.ToLower(fingerprint), "int8"):
		bits = 64
	default:
		return nil
	}
	if _, err := strconv.ParseInt(value, 10, bits); err != nil {
		return &Error{code: CodeInvalidValue}
	}
	return nil
}

func numericValue(raw any, precision, scale int) (string, error) {
	if precision < 1 || scale < 0 || scale > precision {
		return "", &Error{code: CodeInvalidProjection}
	}
	var value string
	switch item := raw.(type) {
	case string:
		value = item
	case []byte:
		value = string(item)
	case pgtype.Numeric:
		if !item.Valid || item.NaN || item.InfinityModifier != 0 || item.Int == nil {
			return "", &Error{code: CodeInvalidValue}
		}
		value = numericFromPGType(item.Int, item.Exp)
	default:
		return "", &Error{code: CodeInvalidValue}
	}
	if !numericPattern.MatchString(value) {
		return "", &Error{code: CodeInvalidValue}
	}
	if strings.HasPrefix(value, "-") && strings.Trim(value[1:], "0.") == "" {
		return "", &Error{code: CodeInvalidValue}
	}
	parts := strings.Split(strings.TrimPrefix(value, "-"), ".")
	frac := ""
	if len(parts) == 2 {
		frac = parts[1]
	}
	if len(frac) != scale {
		return "", &Error{code: CodeInvalidValue}
	}
	if len(strings.TrimLeft(parts[0], "0"))+len(frac) > precision {
		// Zero integer digits still consumes one precision position in NUMERIC.
		if strings.Trim(parts[0], "0") != "" || len(frac) > precision-1 {
			return "", &Error{code: CodeInvalidValue}
		}
	}
	return value, nil
}

func numericFromPGType(integer *big.Int, exponent int32) string {
	negative := integer.Sign() < 0
	digits := new(big.Int).Abs(integer).String()
	if exponent >= 0 {
		digits += strings.Repeat("0", int(exponent))
	} else {
		places := int(-exponent)
		if places >= len(digits) {
			digits = strings.Repeat("0", places-len(digits)+1) + digits
		}
		point := len(digits) - places
		digits = digits[:point] + "." + digits[point:]
	}
	if negative {
		return "-" + digits
	}
	return digits
}

func uuidValue(raw any) (string, error) {
	var value string
	switch item := raw.(type) {
	case string:
		value = item
	case []byte:
		value = string(item)
	case [16]byte:
		value = hex.EncodeToString(item[:4]) + "-" + hex.EncodeToString(item[4:6]) + "-" + hex.EncodeToString(item[6:8]) + "-" + hex.EncodeToString(item[8:10]) + "-" + hex.EncodeToString(item[10:])
	case pgtype.UUID:
		if !item.Valid {
			return "", &Error{code: CodeInvalidValue}
		}
		value = hex.EncodeToString(item.Bytes[:4]) + "-" + hex.EncodeToString(item.Bytes[4:6]) + "-" + hex.EncodeToString(item.Bytes[6:8]) + "-" + hex.EncodeToString(item.Bytes[8:10]) + "-" + hex.EncodeToString(item.Bytes[10:])
	default:
		return "", &Error{code: CodeInvalidValue}
	}
	if !uuidPattern.MatchString(value) {
		return "", &Error{code: CodeInvalidValue}
	}
	return strings.ToLower(value), nil
}

func dateValue(raw any) (string, error) {
	switch value := raw.(type) {
	case time.Time:
		return value.Format("2006-01-02"), nil
	case string:
		if parsed, err := time.Parse("2006-01-02", value); err == nil && parsed.Format("2006-01-02") == value {
			return value, nil
		}
	case []byte:
		return dateValue(string(value))
	}
	return "", &Error{code: CodeInvalidValue}
}

func timestampValue(raw any, precision int, withZone bool) (string, error) {
	if precision < 0 || precision > 6 {
		return "", &Error{code: CodeInvalidProjection}
	}
	var value string
	switch item := raw.(type) {
	case time.Time:
		if withZone {
			value = item.UTC().Format(time.RFC3339Nano)
		} else {
			value = item.Format("2006-01-02T15:04:05.999999999")
		}
	case string:
		value = item
	case []byte:
		value = string(item)
	default:
		return "", &Error{code: CodeInvalidValue}
	}
	var parsed time.Time
	var err error
	if withZone {
		if !strings.ContainsAny(value, "Zz+-") {
			return "", &Error{code: CodeInvalidValue}
		}
		parsed, err = time.Parse(time.RFC3339Nano, value)
	} else {
		// The layout parser below is the authority for local timestamps. Do
		// not reject '-' in the date portion; only a value with a zone fails
		// to match the zone-free layouts.
		parsed, err = time.Parse("2006-01-02T15:04:05.999999999", value)
		if err != nil {
			parsed, err = time.Parse("2006-01-02 15:04:05.999999999", value)
		}
	}
	if err != nil || parsed.Year() < 1 || parsed.Year() > 9999 {
		return "", &Error{code: CodeInvalidValue}
	}
	if precision < 9 {
		unit := 1
		for index := precision; index < 9; index++ {
			unit *= 10
		}
		if parsed.Nanosecond()%unit != 0 {
			return "", &Error{code: CodeInvalidValue}
		}
	}
	if withZone {
		parsed = parsed.UTC()
	}
	base := parsed.Format("2006-01-02T15:04:05")
	if precision > 0 {
		fraction := fmt.Sprintf("%09d", parsed.Nanosecond())[:precision]
		base += "." + fraction
	}
	if withZone {
		base += "Z"
	}
	return base, nil
}

func textValue(raw any, maxBytes int) (string, error) {
	var bytesValue []byte
	switch value := raw.(type) {
	case string:
		bytesValue = []byte(value)
	case []byte:
		bytesValue = append([]byte(nil), value...)
	default:
		return "", &Error{code: CodeInvalidValue}
	}
	canonical, err := canon.Canonicalize(bytesValue)
	if err != nil || (maxBytes > 0 && len(canonical) > maxBytes) {
		return "", &Error{code: CodeInvalidValue, cause: err}
	}
	return string(canonical), nil
}

func jsonValue(raw any) ([]byte, error) {
	var bytesValue []byte
	switch value := raw.(type) {
	case string:
		bytesValue = []byte(value)
	case []byte:
		bytesValue = value
	case jsontext.Value:
		bytesValue = []byte(value)
	default:
		return nil, &Error{code: CodeInvalidValue}
	}
	var parsed jsontext.Value
	if err := jsonv2.Unmarshal(bytesValue, &parsed); err != nil {
		return nil, &Error{code: CodeInvalidValue, cause: err}
	}
	if err := parsed.Canonicalize(jsontext.CanonicalizeRawInts(false)); err != nil {
		return nil, &Error{code: CodeInvalidValue, cause: err}
	}
	if len(bytes.TrimSpace(parsed)) == 0 {
		return nil, &Error{code: CodeInvalidValue}
	}
	return append([]byte(nil), parsed...), nil
}
