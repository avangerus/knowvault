package netcanon

import "testing"

// The rule is shared by the server composition and the deployment operator;
// both consumers rely on this single closed shape.
func TestValidCanonicalHostClosedShape(t *testing.T) {
	valid := []string{
		"idp.example", "a-b.example.com", "127.0.0.1", "::1",
	}
	for _, value := range valid {
		if !ValidCanonicalHost(value) {
			t.Fatalf("rejected %q", value)
		}
	}
	invalid := []string{
		"",
		"IDP.example",             // uppercase
		"idp.example.",            // trailing dot
		"-idp.example",            // leading hyphen label
		"idp-.example",            // trailing hyphen label
		"idp..example",            // empty label
		"idp.example_",            // invalid character
		"127.0.0.01",              // non-canonical IP literal
		"127.0.0.1.",              // dotted IP with trailing dot
		"300.400.500.600",         // numeric-only but not a canonical IP
		string(make([]byte, 254)), // over 253 characters
	}
	for _, value := range invalid {
		if ValidCanonicalHost(value) {
			t.Fatalf("accepted %q", value)
		}
	}
	overlong := make([]byte, 64)
	for index := range overlong {
		overlong[index] = 'a'
	}
	if ValidCanonicalHost(string(overlong) + ".example") {
		t.Fatal("accepted a label over 63 characters")
	}
}
