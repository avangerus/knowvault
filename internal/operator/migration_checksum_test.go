package operator

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var migrationCommentFixtures = []struct {
	name, legacy, translated string
}{
	{"000077_stage2_evidence_fragment_readable_per_scope.sql", "83ce299c009c877b379f436272dd62780306e659d806d2e62f004387c3055779", "e7706f35480571675c537821b1640e712b12333c79f15b395ccc1fbb2bfa681c"},
	{"000078_stage3_governed_query_workspace_binding.sql", "eeb5f884582201564fda16a5fbd66791ce1b3db81ea3b72de8f789be3234eb45", "a7a988e1b492622c98e604fc4ff3eb9fc682cd3cea7760c268a4c3cbfe096ade"},
	{"000080_stage3_conversation_continuation_revision_tolerant.sql", "60c1745f0274638c97d090a220ede58f26d8dc8292f32d14cd58fd988a5aee27", "8eed587de6da613698860d0072f9bcb3a963dcffc2c653e3bb0f64097c2267cd"},
	{"000082_stage3_structured_snapshot_status_role.sql", "37dc121288e5a3ed63b61bb4a26d3bbec8bf1e6687e68ff1129abb811ed935f6", "8d5ea8f86a88ec814fa30d3d9b3bce383c54dc5a9b3df1cc718866348578d408"},
	{"000083_stage3_structured_source_scope_names.sql", "7456d5908c9356f471c0a465fd1f68041251333c5d8e9ffbcf2dc12ea6853672", "369bb4184bc418040310841979d54b2533f788e05bd5fc4011e38ec3c4a25545"},
	{"000094_stage3_metric_definitions.sql", "fc4927677050e97753598fe04a580c49f97d57b4780551621557c7bcc1c3e6c8", "9de3a3797bfcfcb99f500cc67b64f29d1d5285389cbf0c8541c5b03cb307d440"},
}

func TestMigrationCommentChecksumCompatibilityIsExactAndDirectional(t *testing.T) {
	for index, fixture := range migrationCommentFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			cases := []struct {
				label, name, recorded, actual string
				want                          bool
			}{
				{"translated exact", fixture.name, fixture.translated, fixture.translated, true},
				{"legacy exact", fixture.name, fixture.legacy, fixture.legacy, true},
				{"approved comment translation", fixture.name, fixture.legacy, fixture.translated, true},
				{"reverse transition", fixture.name, fixture.translated, fixture.legacy, false},
				{"different name", "000999_unlisted.sql", fixture.legacy, fixture.translated, false},
				{"renamed path", "prefix/" + fixture.name, fixture.legacy, fixture.translated, false},
				{"tampered actual", fixture.name, fixture.legacy, strings.Repeat("0", 64), false},
				{"tampered recorded", fixture.name, strings.Repeat("0", 64), fixture.translated, false},
				{"empty recorded", fixture.name, "", fixture.translated, false},
				{"empty actual", fixture.name, fixture.legacy, "", false},
				{"uppercase recorded", fixture.name, strings.ToUpper(fixture.legacy), fixture.translated, false},
				{"uppercase actual", fixture.name, fixture.legacy, strings.ToUpper(fixture.translated), false},
				{"prefixed recorded", fixture.name, "sha256:" + fixture.legacy, fixture.translated, false},
			}
			for otherIndex, other := range migrationCommentFixtures {
				if otherIndex == index {
					continue
				}
				cases = append(cases,
					struct {
						label, name, recorded, actual string
						want                          bool
					}{"other legacy " + other.name, fixture.name, other.legacy, fixture.translated, false},
					struct {
						label, name, recorded, actual string
						want                          bool
					}{"other translated " + other.name, fixture.name, fixture.legacy, other.translated, false},
					struct {
						label, name, recorded, actual string
						want                          bool
					}{"other pair " + other.name, fixture.name, other.legacy, other.translated, false},
				)
			}
			for _, test := range cases {
				t.Run(test.label, func(t *testing.T) {
					if got := migrationChecksumMatches(test.name, test.recorded, test.actual); got != test.want {
						t.Fatalf("matches=%v, want %v", got, test.want)
					}
				})
			}
		})
	}
	const unlisted = "000001_unlisted.sql"
	if !migrationChecksumMatches(unlisted, "same", "same") {
		t.Fatal("ordinary exact equality changed")
	}
	if migrationChecksumMatches(unlisted, "old", "new") {
		t.Fatal("ordinary checksum mismatch was accepted")
	}
}

func TestMigrationCommentPinsMatchFilesAndRejectFurtherChanges(t *testing.T) {
	for _, fixture := range migrationCommentFixtures {
		t.Run(fixture.name, func(t *testing.T) {
			raw := readMigrationCommentFixture(t, fixture.name)
			if got := migrationBytesChecksum(raw); got != fixture.translated {
				t.Fatalf("translated migration pin drift: got %s, want %s", got, fixture.translated)
			}
			for _, suffix := range []string{"\nSELECT 1;\n", "\n-- unapproved comment revision\n"} {
				tampered := append(append([]byte(nil), raw...), suffix...)
				if migrationChecksumMatches(fixture.name, fixture.legacy, migrationBytesChecksum(tampered)) {
					t.Fatal("additional SQL or comment change was accepted")
				}
			}
		})
	}
}

func readMigrationCommentFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "db", "migrations", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func migrationBytesChecksum(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
