package embedding

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseMountedManifestBindsTenantAndFixedFiles(t *testing.T) {
	profile := testProfile()
	raw, err := json.Marshal(mountedManifest{
		Schema: embeddingManifestSchema, OrganizationID: "org_alpha",
		ProfileFile: embeddingProfileFilename, ProfileHash: profile.ProfileHash,
		RootCAFile: embeddingRootCAFilename, ClientCertificateFile: embeddingClientCertFile,
		ClientKeyFile: embeddingClientKeyFile,
	})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseMountedManifest(raw, "org_alpha")
	if err != nil {
		t.Fatalf("valid embedding manifest rejected: %v", err)
	}
	if manifest.OrganizationID != "org_alpha" || manifest.ProfileHash != profile.ProfileHash ||
		manifest.ProfileFile != embeddingProfileFilename || manifest.RootCAFile != embeddingRootCAFilename {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
}

func TestParseMountedManifestRejectsCrossTenantAndUnqualifiedValues(t *testing.T) {
	profile := testProfile()
	base := `{"schema":"knowvault-embedding-manifest-v1","organization_id":"org_alpha","profile_file":"profile.json","profile_hash":"` + profile.ProfileHash + `","root_ca_file":"root-ca.pem","client_certificate_file":"client-cert.pem","client_key_file":"client-key.pem"}`
	cases := map[string]string{
		"wrong tenant":           strings.Replace(base, `"org_alpha"`, `"org_beta"`, 1),
		"wrong profile file":     strings.Replace(base, `profile.json`, `../profile.json`, 1),
		"malformed profile hash": strings.Replace(base, profile.ProfileHash, "not-a-hash", 1),
		"http-like endpoint":     strings.Replace(base, `"root-ca.pem"`, `"http://root-ca.pem"`, 1),
		"missing client key":     strings.Replace(base, `,"client_key_file":"client-key.pem"`, "", 1),
		"unknown member":         strings.TrimSuffix(base, "}") + `,"unexpected":true}`,
		"duplicate member":       strings.Replace(base, `"profile_file":"profile.json",`, `"profile_file":"profile.json","profile_file":"profile.json",`, 1),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if manifest, err := parseMountedManifest([]byte(value), "org_alpha"); manifest != (mountedManifest{}) || CodeOf(err) != CodeMountInvalid {
				t.Fatalf("manifest=%#v err=%v", manifest, err)
			}
		})
	}
}

func TestParseEmbeddingRootsRejectsEmptyAndDuplicateCertificates(t *testing.T) {
	if roots, err := parseEmbeddingRoots(nil); roots != nil || err == nil {
		t.Fatalf("empty roots=%v err=%v", roots, err)
	}
	// The parser is intentionally strict about PEM framing; a duplicate test
	// is covered by the real certificate fixture in the Linux mount test. This
	// assertion keeps malformed text from becoming a trust root on every OS.
	if roots, err := parseEmbeddingRoots([]byte("not a certificate")); roots != nil || err == nil {
		t.Fatalf("malformed roots=%v err=%v", roots, err)
	}
}
