package search

import (
	"strings"
	"testing"
)

func TestParseMountedManifestBindsTenantAndFixedFiles(t *testing.T) {
	raw := []byte(`{"schema":"knowvault-search-manifest-v1","organization_id":"org_alpha","endpoint":"https://search.example:9443","index_alias":"org-alpha-v1","generation":3,"generation_fence":7,"root_ca_file":"root-ca.pem"}`)
	manifest, err := parseMountedManifest(raw, "org_alpha")
	if err != nil {
		t.Fatalf("valid search manifest rejected: %v", err)
	}
	if manifest.Endpoint != "https://search.example:9443" || manifest.IndexAlias != "org-alpha-v1" || manifest.Generation != 3 || manifest.GenerationFence != 7 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
}

func TestParseMountedManifestRejectsAmbiguousOrUntrustedValues(t *testing.T) {
	base := `{"schema":"knowvault-search-manifest-v1","organization_id":"org_alpha","endpoint":"https://search.example:9443","index_alias":"org-alpha-v1","generation":3,"generation_fence":7,"root_ca_file":"root-ca.pem"}`
	cases := map[string]string{
		"wrong tenant":       strings.Replace(base, `"org_alpha"`, `"org_beta"`, 1),
		"http endpoint":      strings.Replace(base, `https://search.example:9443`, `http://search.example:9443`, 1),
		"ip endpoint":        strings.Replace(base, `https://search.example:9443`, `https://127.0.0.1:9443`, 1),
		"path endpoint":      strings.Replace(base, `https://search.example:9443`, `https://search.example:9443/path`, 1),
		"noncanonical alias": strings.Replace(base, `org-alpha-v1`, `_org-alpha-v1`, 1),
		"zero generation":    strings.Replace(base, `"generation":3`, `"generation":0`, 1),
		"traversal root":     strings.Replace(base, `root-ca.pem`, `../root-ca.pem`, 1),
		"only certificate":   strings.Replace(base, `"root_ca_file":"root-ca.pem"`, `"root_ca_file":"root-ca.pem","client_certificate_file":"client-cert.pem"`, 1),
		"unknown member":     strings.TrimSuffix(base, "}") + `,"unexpected":true}`,
		"duplicate member":   strings.Replace(base, `"generation":3,`, `"generation":3,"generation":3,`, 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if manifest, err := parseMountedManifest([]byte(raw), "org_alpha"); manifest != (mountedManifest{}) || CodeOf(err) != CodeMountInvalid {
				t.Fatalf("manifest=%#v err=%v", manifest, err)
			}
		})
	}
}

func TestSearchEndpointUsesTransportCanonicalRule(t *testing.T) {
	valid := []string{"https://search.example", "https://search.example:9443"}
	for _, value := range valid {
		if !validSearchEndpoint(value) {
			t.Fatalf("valid endpoint rejected: %q", value)
		}
	}
	for _, value := range []string{"", "https://127.0.0.1", "https://search.example.", "https://search.example/", "https://user:secret@search.example"} {
		if validSearchEndpoint(value) {
			t.Fatalf("unsafe endpoint accepted: %q", value)
		}
	}
}
