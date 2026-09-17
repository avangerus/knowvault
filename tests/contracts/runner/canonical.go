package contracts

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type contractError struct {
	Code string
	Info string
}

func (e *contractError) Error() string {
	if e.Info == "" {
		return e.Code
	}
	return e.Code + ": " + e.Info
}

func fail(code string, args ...any) error {
	info := ""
	if len(args) > 0 {
		info = fmt.Sprint(args...)
	}
	return &contractError{Code: code, Info: info}
}

func errorCode(err error) string {
	if err == nil {
		return ""
	}
	var target *contractError
	if errors.As(err, &target) {
		return target.Code
	}
	return "INTERNAL_TEST_ERROR"
}

func repoRoot() string {
	if root := os.Getenv("REPO_ROOT"); root != "" {
		return root
	}
	dir, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "architecture", "contracts")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			panic("repository root not found")
		}
		dir = parent
	}
}

func fixturePath(relative string) string {
	return filepath.Join(repoRoot(), "tests", "contracts", filepath.FromSlash(relative))
}

func strictCanonical(raw []byte) ([]byte, error) {
	value := jsontext.Value(append([]byte(nil), raw...))
	if err := value.Canonicalize(); err != nil {
		message := strings.ToLower(err.Error())
		switch {
		case strings.Contains(message, "duplicate"):
			return nil, fail("JSON_DUPLICATE_MEMBER")
		case strings.Contains(message, "utf-8"), strings.Contains(message, "utf8"), strings.Contains(message, "surrogate"):
			return nil, fail("JSON_INVALID_UNICODE")
		case strings.Contains(message, "number"), strings.Contains(message, "nan"), strings.Contains(message, "infinity"):
			return nil, fail("JSON_NUMBER_NOT_IJSON")
		default:
			return nil, fail("JSON_MALFORMED", err)
		}
	}
	if err := validateSafeJSONNumbers(raw); err != nil {
		return nil, err
	}
	return []byte(value), nil
}

func validateSafeJSONNumbers(raw []byte) error {
	inString := false
	escaped := false
	for i := 0; i < len(raw); i++ {
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if raw[i] == '\\' {
				escaped = true
			} else if raw[i] == '"' {
				inString = false
			}
			continue
		}
		if raw[i] == '"' {
			inString = true
			continue
		}
		if (raw[i] >= '0' && raw[i] <= '9') || (raw[i] == '-' && i+1 < len(raw) && raw[i+1] >= '0' && raw[i+1] <= '9') {
			start := i
			i++
			for i < len(raw) && ((raw[i] >= '0' && raw[i] <= '9') || raw[i] == '.' || raw[i] == 'e' || raw[i] == 'E' || raw[i] == '+' || raw[i] == '-') {
				i++
			}
			numberText := string(raw[start:i])
			i--
			if !jsonNumberWithinSafeMagnitude(numberText) {
				return fail("JSON_NUMBER_NOT_IJSON")
			}
		}
	}
	return nil
}

func jsonNumberWithinSafeMagnitude(token string) bool {
	if strings.HasPrefix(token, "-") {
		token = token[1:]
	}
	parts := strings.FieldsFunc(token, func(r rune) bool { return r == 'e' || r == 'E' })
	if len(parts) > 2 || len(parts) == 0 {
		return false
	}
	exponent := 0
	if len(parts) == 2 {
		parsed, err := strconv.Atoi(parts[1])
		if err != nil {
			return false
		}
		exponent = parsed
	}
	mantissa := parts[0]
	fractionDigits := 0
	if dot := strings.IndexByte(mantissa, '.'); dot >= 0 {
		fractionDigits = len(mantissa) - dot - 1
		mantissa = mantissa[:dot] + mantissa[dot+1:]
	}
	digits := new(big.Int)
	if _, ok := digits.SetString(mantissa, 10); !ok {
		return false
	}
	if digits.Sign() == 0 {
		return true
	}
	scale := exponent - fractionDigits
	limit := big.NewInt(9007199254740991)
	ten := big.NewInt(10)
	if scale >= 0 {
		if scale > 32 {
			return false
		}
		value := new(big.Int).Mul(digits, new(big.Int).Exp(ten, big.NewInt(int64(scale)), nil))
		return value.Cmp(limit) <= 0
	}
	if -scale > 100000 {
		// A non-zero number with a huge negative exponent is safely below the
		// magnitude limit; avoid allocating an attacker-controlled big.Int.
		return true
	}
	right := new(big.Int).Mul(limit, new(big.Int).Exp(ten, big.NewInt(int64(-scale)), nil))
	return digits.Cmp(right) <= 0
}

func loadObject(relative string) (map[string]any, []byte, error) {
	raw, err := os.ReadFile(fixturePath(relative))
	if err != nil {
		return nil, nil, err
	}
	canonical, err := strictCanonical(raw)
	if err != nil {
		return nil, nil, err
	}
	var object map[string]any
	if err := json.Unmarshal(raw, &object); err != nil {
		return nil, nil, fail("JSON_MALFORMED", err)
	}
	return object, canonical, nil
}

func loadAny(relative string) (any, []byte, error) {
	raw, err := os.ReadFile(fixturePath(relative))
	if err != nil {
		return nil, nil, err
	}
	canonical, err := strictCanonical(raw)
	if err != nil {
		return nil, nil, err
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, nil, fail("JSON_MALFORMED", err)
	}
	return value, canonical, nil
}

func canonicalValue(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return strictCanonical(raw)
}

func cloneObject(input map[string]any) map[string]any {
	raw, err := json.Marshal(input)
	if err != nil {
		panic(err)
	}
	var output map[string]any
	if err := json.Unmarshal(raw, &output); err != nil {
		panic(err)
	}
	return output
}

func sha256String(bytes []byte) string {
	digest := sha256.Sum256(bytes)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func hashCanonical(value any) (string, error) {
	bytes, err := canonicalValue(value)
	if err != nil {
		return "", err
	}
	return sha256String(bytes), nil
}

func object(value any) map[string]any {
	result, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	return result
}

func array(value any) []any {
	result, ok := value.([]any)
	if !ok {
		return nil
	}
	return result
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

func intValue(value any) int {
	switch number := value.(type) {
	case float64:
		return int(number)
	case int:
		return number
	case json.Number:
		result, _ := strconv.Atoi(number.String())
		return result
	default:
		return 0
	}
}

func floatValue(value any) float64 {
	result, _ := value.(float64)
	return result
}

func stringSet(items []any) map[string]bool {
	result := make(map[string]bool, len(items))
	for _, item := range items {
		result[stringValue(item)] = true
	}
	return result
}

func assertAllowedFields(value map[string]any, allowed []string) error {
	set := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		set[key] = true
	}
	for key := range value {
		if !set[key] {
			return fail("JSON_UNKNOWN_FIELD", key)
		}
	}
	return nil
}

func decodeSeed(context map[string]any) (ed25519.PrivateKey, ed25519.PublicKey, string, error) {
	key := object(context["key"])
	seed, err := hex.DecodeString(stringValue(key["seed_hex"]))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, nil, "", fmt.Errorf("invalid test seed")
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	declared, err := base64.StdEncoding.DecodeString(stringValue(key["public_key_base64"]))
	if err != nil || !ed25519.PublicKey(declared).Equal(publicKey) {
		return nil, nil, "", fmt.Errorf("test public key does not match seed")
	}
	return privateKey, publicKey, stringValue(key["key_id"]), nil
}

func manifestSigningObject(manifest map[string]any) map[string]any {
	signature := object(manifest["signature"])
	return map[string]any{
		"algorithm":     signature["algorithm"],
		"key_id":        signature["key_id"],
		"manifest_hash": manifest["manifest_hash"],
		"signed_at":     signature["signed_at"],
	}
}

func connectorSigningObject(event map[string]any) map[string]any {
	integrity := object(event["integrity"])
	return map[string]any{
		"algorithm":        integrity["algorithm"],
		"connection_id":    event["connection_id"],
		"connector_job_id": event["connector_job_id"],
		"event_id":         event["event_id"],
		"key_id":           integrity["key_id"],
		"nonce":            integrity["nonce"],
		"payload_hash":     integrity["payload_hash"],
		"signed_at":        integrity["signed_at"],
		"source_scope_id":  event["source_scope_id"],
		"scope_revision":   event["scope_revision"],
	}
}

func rehashAndSignManifest(manifest, context map[string]any) error {
	privateKey, _, keyID, err := decodeSeed(context)
	if err != nil {
		return err
	}
	signature := object(manifest["signature"])
	signature["algorithm"] = "ED25519"
	signature["key_id"] = keyID
	content := cloneObject(manifest)
	delete(content, "manifest_hash")
	delete(content, "signature")
	contentBytes, err := canonicalValue(content)
	if err != nil {
		return err
	}
	manifest["manifest_hash"] = sha256String(contentBytes)
	signingBytes, err := canonicalValue(manifestSigningObject(manifest))
	if err != nil {
		return err
	}
	signature["value_base64"] = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signingBytes))
	return nil
}

func rehashAndSignConnector(event, context map[string]any) error {
	privateKey, _, keyID, err := decodeSeed(context)
	if err != nil {
		return err
	}
	integrity := object(event["integrity"])
	integrity["algorithm"] = "ED25519"
	integrity["key_id"] = keyID
	payload := cloneObject(event)
	delete(payload, "integrity")
	payloadBytes, err := canonicalValue(payload)
	if err != nil {
		return err
	}
	integrity["payload_hash"] = sha256String(payloadBytes)
	signingBytes, err := canonicalValue(connectorSigningObject(event))
	if err != nil {
		return err
	}
	integrity["value_base64"] = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, signingBytes))
	return nil
}

func sortedStrings(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
