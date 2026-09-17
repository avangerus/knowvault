package composition

import (
	"fmt"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/identity"
)

func TestLoadProductionAcceptsOnlyCompleteCanonicalNonSecretConfiguration(t *testing.T) {
	configuration, err := loadProduction(validEnvironment())
	if err != nil {
		t.Fatalf("load canonical configuration: %v", err)
	}
	if configuration.OrganizationID() != identity.OrganizationID("org_alpha") ||
		configuration.ProviderID() != identity.ProviderID("idp_primary") ||
		configuration.PublicOrigin() != "https://workspace.example" ||
		configuration.HTTPAddress() != ":8080" {
		t.Fatalf("unexpected typed configuration: %#v", configuration)
	}
}

func TestLoadProductionRejectsMissingUnknownAndCaseFoldedDuplicateVariables(t *testing.T) {
	tests := map[string][]string{
		"missing":                 validEnvironment()[:3],
		"unknown namespace key":   append(validEnvironment(), "KNOWVAULT_DATABASE_URL=forbidden"),
		"malformed namespace key": append(validEnvironment(), "KNOWVAULT_BROKEN"),
		"lowercase known key":     replaceEnvironment(validEnvironment(), organizationIDEnvironment, "knowvault_organization_id=org_alpha"),
		"case-folded duplicate":   append(validEnvironment(), "knowvault_http_addr=:9090"),
		"exact duplicate":         append(validEnvironment(), organizationIDEnvironment+"=org_beta"),
	}
	for name, environment := range tests {
		t.Run(name, func(t *testing.T) {
			assertInvalidConfiguration(t, environment)
		})
	}

	withUnrelated := append(validEnvironment(), "PATH=/usr/bin", "HOME=/nonsecret")
	if _, err := loadProduction(withUnrelated); err != nil {
		t.Fatalf("unrelated process environment must be ignored: %v", err)
	}
}

func TestLoadProductionRejectsEmptyWhitespaceControlAndInvalidUTF8WithoutNormalization(t *testing.T) {
	invalidValues := []string{"", " org_alpha", "org_alpha ", "org alpha", "org\talpha", "org\nalpha", "org\x00alpha", "org\x7falpha", string([]byte{'o', 'r', 'g', '_', 0xff})}
	for _, value := range invalidValues {
		t.Run(strings.ReplaceAll(value, "\n", "newline"), func(t *testing.T) {
			assertInvalidConfiguration(t, replaceEnvironment(validEnvironment(), organizationIDEnvironment, organizationIDEnvironment+"="+value))
		})
	}
}

func TestLoadProductionRejectsNonCanonicalIdentifiers(t *testing.T) {
	for _, value := range []string{"ab", "org/alpha", "\u043e\u0440\u0433", strings.Repeat("a", 129)} {
		assertInvalidConfiguration(t, replaceEnvironment(validEnvironment(), providerIDEnvironment, providerIDEnvironment+"="+value))
	}
}

func TestLoadProductionRejectsNonCanonicalPublicOrigin(t *testing.T) {
	invalid := []string{
		"http://workspace.example", "https://WORKSPACE.example", "https://workspace.example.", "https://workspace.example:443",
		"https://workspace.example:0443", "https://workspace.example/", "https://workspace.example/path", "https://workspace.example?query",
		"https://user@workspace.example", "https://workspace.example#fragment", "https://-workspace.example", "https://workspace..example",
		"https://2001:db8::1", "https://[2001:0db8::1]",
	}
	for _, value := range invalid {
		t.Run(value, func(t *testing.T) {
			assertInvalidConfiguration(t, replaceEnvironment(validEnvironment(), publicOriginEnvironment, publicOriginEnvironment+"="+value))
		})
	}

	for _, value := range []string{"https://workspace.example:8443", "https://127.0.0.1", "https://[2001:db8::1]"} {
		t.Run("valid_"+value, func(t *testing.T) {
			environment := replaceEnvironment(validEnvironment(), publicOriginEnvironment, publicOriginEnvironment+"="+value)
			if _, err := loadProduction(environment); err != nil {
				t.Fatalf("canonical origin rejected: %v", err)
			}
		})
	}
}

func TestLoadProductionRejectsNonCanonicalHTTPAddress(t *testing.T) {
	invalid := []string{"8080", ":0", ":65536", ":08080", "*:8080", "LOCALHOST:8080", "localhost:08080", "127.0.0.01:8080", "[2001:0db8::1]:8080", "/tmp/server.sock"}
	for _, value := range invalid {
		t.Run(value, func(t *testing.T) {
			assertInvalidConfiguration(t, replaceEnvironment(validEnvironment(), httpAddressEnvironment, httpAddressEnvironment+"="+value))
		})
	}

	for _, value := range []string{":8080", "127.0.0.1:8080", "[::1]:8080", "localhost:8080"} {
		t.Run("valid_"+value, func(t *testing.T) {
			environment := replaceEnvironment(validEnvironment(), httpAddressEnvironment, httpAddressEnvironment+"="+value)
			if _, err := loadProduction(environment); err != nil {
				t.Fatalf("canonical address rejected: %v", err)
			}
		})
	}
}

func TestLoadProductionRejectsEveryWebAssetDirectoryOverride(t *testing.T) {
	for _, entry := range []string{"KNOWVAULT_WEB_DIR=/etc", "KNOWVAULT_WEB_ASSET_DIRECTORY=/run/knowvault/secrets"} {
		t.Run(entry, func(t *testing.T) {
			assertInvalidConfiguration(t, append(validEnvironment(), entry))
		})
	}
}

func TestConfigurationErrorsAreContentFree(t *testing.T) {
	secretLikeValue := "do-not-return-this-value"
	_, err := loadProduction(append(validEnvironment(), "KNOWVAULT_UNKNOWN="+secretLikeValue))
	if err == nil || CodeOf(err) != CodeConfigInvalid || strings.Contains(err.Error(), secretLikeValue) || err.Error() != string(CodeConfigInvalid) {
		t.Fatalf("configuration error is absent, untyped, or leaks input: %v", err)
	}
	if CodeOf(assertionError{}) != CodeConfigInvalid {
		t.Fatal("unexpected errors must map to the safe generic configuration code")
	}
}

func TestConfigurationFormattingRedactsValueAndPointer(t *testing.T) {
	configuration, err := loadProduction(validEnvironment())
	if err != nil {
		t.Fatalf("load canonical configuration: %v", err)
	}
	for _, formatted := range []string{
		fmt.Sprintf("%v", configuration), fmt.Sprintf("%#v", configuration),
		fmt.Sprintf("%v", &configuration), fmt.Sprintf("%#v", &configuration),
	} {
		if formatted != "composition.Config{[REDACTED]}" || strings.Contains(formatted, "org_alpha") ||
			strings.Contains(formatted, "workspace.example") {
			t.Fatalf("configuration formatting leaked startup values: %q", formatted)
		}
	}
}

func validEnvironment() []string {
	return []string{
		organizationIDEnvironment + "=org_alpha",
		providerIDEnvironment + "=idp_primary",
		publicOriginEnvironment + "=https://workspace.example",
		httpAddressEnvironment + "=:8080",
	}
}

func replaceEnvironment(environment []string, name, replacement string) []string {
	result := append([]string(nil), environment...)
	for index, entry := range result {
		if strings.HasPrefix(entry, name+"=") {
			result[index] = replacement
			return result
		}
	}
	panic("test environment key not found: " + name)
}

func assertInvalidConfiguration(t *testing.T, environment []string) {
	t.Helper()
	configuration, err := loadProduction(environment)
	if err == nil || CodeOf(err) != CodeConfigInvalid || configuration != (Config{}) {
		t.Fatalf("invalid environment accepted: config=%#v err=%v", configuration, err)
	}
}

type assertionError struct{}

func (assertionError) Error() string { return "unexpected" }
