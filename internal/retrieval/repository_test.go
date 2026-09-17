package retrieval

import "testing"

func TestValidHMAC(t *testing.T) {
	tests := map[string]bool{
		"hmac-sha256:k1:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef":         true,
		"hmac-sha256:k999999999:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": true,
		"hmac-sha256:k0:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef":         false,
		"hmac-sha256:k01:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef":        false,
		"hmac-sha256:k1:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef":         false,
		"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef":                 false,
	}
	for value, want := range tests {
		if got := validHMAC(value); got != want {
			t.Errorf("validHMAC(%q)=%v, want %v", value, got, want)
		}
	}
}

func TestValidOpaqueRejectsControls(t *testing.T) {
	for _, value := range []string{"", " leading", "trailing ", "line\nfeed", "nul\x00byte", "delete\x7f", "c1\u0085control"} {
		if validOpaque(value) {
			t.Errorf("validOpaque(%q)=true, want false", value)
		}
	}
	for _, value := range []string{"workspace_01", "principal-1", "\u0440\u0443\u0441\u0441\u043a\u0438\u0439-id"} {
		if !validOpaque(value) {
			t.Errorf("validOpaque(%q)=false, want true", value)
		}
	}
}
