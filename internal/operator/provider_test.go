package operator

import "testing"

// The configuration hash must separate field boundaries: a naive separator
// join collides on shifted field contents, and a collision would let a
// conflicting deployment read as recorded.
func TestProviderConfigurationHashSeparatesFieldBoundaries(t *testing.T) {
	base := ProviderRegistration{
		OrganizationID: "org_001", ProviderID: "provider_001",
		IssuerURL: "https://idp.example/auth", ClientID: "x",
		ClientSecretReference: "y|z", RedirectURI: "https://workspace.example/auth/callback",
		CreatedBy: "usr_001",
	}
	shifted := base
	shifted.ClientID = "x|y"
	shifted.ClientSecretReference = "z"
	if providerConfigurationHash(base) == providerConfigurationHash(shifted) {
		t.Fatal("field-boundary collision: shifted client id and secret reference hash identically")
	}
	// The hash is deterministic for the identical payload.
	if providerConfigurationHash(base) != providerConfigurationHash(base) {
		t.Fatal("hash is not deterministic")
	}
}

func TestValidHTTPSURLClosedShape(t *testing.T) {
	valid := []string{
		"https://idp.example/auth",
		"https://idp.example:8443/auth",
		"https://127.0.0.1/auth",
		"https://idp.example",
	}
	for _, value := range valid {
		if !validHTTPSURL(value) {
			t.Fatalf("rejected %q", value)
		}
	}
	invalid := []string{
		"https:///",                      // empty host
		"https://IDP.example/auth",       // non-canonical uppercase host
		"https://idp.example./auth",      // trailing dot
		"https://idp.example/auth?q=1",   // query
		"https://idp.example/auth#frag",  // fragment
		"https://user@idp.example/auth",  // userinfo
		"https://-idp.example/auth",      // leading hyphen label
		"https://idp..example/auth",      // empty label
		"https://idp.example:0/auth",     // port out of range
		"https://idp.example:99999/auth", // port out of range
		"https://idp.example:8443x/auth", // non-numeric port
		"https://idp.example:443:1/auth", // double port
		"https://[::1]:8443/auth",        // explicit port on IPv6 literal
		"http://idp.example/auth",        // wrong scheme
		"idp.example/auth",               // no scheme
		"https://idp.example/a b",        // whitespace
	}
	for _, value := range invalid {
		if validHTTPSURL(value) {
			t.Fatalf("accepted %q", value)
		}
	}
}

func TestValidOpaqueIDClosedShape(t *testing.T) {
	valid := []string{"org_001", "a", "x1_y-2"}
	for _, value := range valid {
		if !validOpaqueID(value) {
			t.Fatalf("rejected %q", value)
		}
	}
	invalid := []string{"", " org_001", "org_001 ", "org\tbad", "org\nbad", "org\x1fbad", "org\x7fbad"}
	for _, value := range invalid {
		if validOpaqueID(value) {
			t.Fatalf("accepted %q", value)
		}
	}
	long := make([]byte, 257)
	for index := range long {
		long[index] = 'a'
	}
	if validOpaqueID(string(long)) {
		t.Fatal("accepted over-length value")
	}
}
