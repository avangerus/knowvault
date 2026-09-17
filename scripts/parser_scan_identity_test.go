package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestParserOCIArchiveScanBindsManifestAndConfigBytes(t *testing.T) {
	config := []byte(`{"architecture":"amd64","os":"linux"}`)
	configDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(config))
	manifest := []byte(fmt.Sprintf(`{"schemaVersion":2,"config":{"digest":%q}}`, configDigest))
	manifestDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(manifest))
	valid := map[string]any{
		"imageID": configDigest, "manifestDigest": manifestDigest,
		"mediaType": "application/vnd.oci.image.manifest.v1+json",
		"manifest":  base64.StdEncoding.EncodeToString(manifest),
		"config":    base64.StdEncoding.EncodeToString(config),
	}
	if !parserScanImageIdentityMatches(valid, configDigest, manifestDigest, "") {
		t.Fatal("exact OCI archive bytes require no fabricated registry digest")
	}
	dockerManifest := "sha256:" + strings.Repeat("d", 64)
	if parserScanImageIdentityMatches(valid, configDigest, manifestDigest, dockerManifest) {
		t.Fatal("OCI evidence must not bypass an asserted Docker distribution identity")
	}
	docker := map[string]any{"imageID": configDigest, "manifestDigest": dockerManifest, "repoDigests": []any{"parser@" + manifestDigest}}
	if !parserScanImageIdentityMatches(docker, configDigest, manifestDigest, dockerManifest) {
		t.Fatal("historical exact Docker identity rejected")
	}
	for name, changed := range map[string]map[string]any{
		"wrong config identity":   {"imageID": "sha256:" + strings.Repeat("0", 64)},
		"wrong manifest identity": {"manifestDigest": "sha256:" + strings.Repeat("0", 64)},
		"missing manifest bytes":  {"manifest": nil},
		"missing config bytes":    {"config": nil},
		"changed manifest bytes":  {"manifest": base64.StdEncoding.EncodeToString(append(append([]byte{}, manifest...), ' '))},
		"changed config bytes":    {"config": base64.StdEncoding.EncodeToString(append(append([]byte{}, config...), ' '))},
		"wrong media type":        {"mediaType": "application/vnd.docker.distribution.manifest.v2+json"},
		"invalid encoding":        {"manifest": "!invalid"},
	} {
		t.Run(name, func(t *testing.T) {
			input := make(map[string]any, len(valid))
			for key, value := range valid {
				input[key] = value
			}
			for key, value := range changed {
				input[key] = value
			}
			if parserScanImageIdentityMatches(input, configDigest, manifestDigest, "") {
				t.Fatal("unbound OCI archive evidence accepted")
			}
		})
	}
}
