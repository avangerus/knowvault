package workspaceapi

// Review blocker B1: ":promote" accepted arbitrary SQL text in an HTTP body
// and stored it without ever comparing it to a query that had run. That is SQL
// authorship on an API surface, which PRODUCT_CONSTITUTION.md §7 forbids;
// ADR-0089's carve-out covers only "the model composes over the exposed
// schema, the dedicated role executes". The body now carries a reference to an
// executed attempt and the hash the operator was shown, and nothing else that
// could be a statement.

import (
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"strings"
	"testing"
)

// decodeBody mirrors decodeJSON's exact strictness so the shape of the request
// object is tested, not a reimplementation of it.
func decodeBody(raw string, destination any) error {
	return jsonv2.Unmarshal([]byte(raw), destination,
		jsonv2.RejectUnknownMembers(true),
		jsonv2.MatchCaseInsensitiveNames(false),
		jsontext.AllowDuplicateNames(false),
		jsontext.AllowInvalidUTF8(false),
	)
}

func TestPromoteBodyRefusesAnySQLField(t *testing.T) {
	for name, raw := range map[string]string{
		"the field that used to exist": `{"attempt_id":"gqat_01","sql_hash":"sha256:` + strings.Repeat("a", 64) + `","sql":"SELECT 1"}`,
		"only a statement":             `{"sql":"SELECT 1"}`,
		"a differently spelled one":    `{"attempt_id":"gqat_01","sql_hash":"sha256:` + strings.Repeat("a", 64) + `","sql_text":"SELECT 1"}`,
		"a statement in the name":      `{"attempt_id":"gqat_01","sql_hash":"sha256:` + strings.Repeat("a", 64) + `","query":"SELECT 1"}`,
	} {
		var body governedQueryPromoteBody
		if err := decodeBody(raw, &body); err == nil {
			t.Fatalf("%s: the promote body accepted a statement: %s", name, raw)
		}
	}
}

func TestPromoteBodyAcceptsOnlyAReferenceAndItsHash(t *testing.T) {
	hash := "sha256:" + strings.Repeat("a", 64)
	var body governedQueryPromoteBody
	if err := decodeBody(`{"attempt_id":"gqat_01ARZ3NDEKTSV4RRFFQ69G5FAV","sql_hash":"`+hash+"\",\"name\":\"\u0420\u0435\u0439\u0441\u044b \u0437\u0430 \u043d\u0435\u0434\u0435\u043b\u044e\",\"schedule\":\"daily\"}", &body); err != nil {
		t.Fatalf("the reference form must decode: %v", err)
	}
	if body.AttemptID == nil || *body.AttemptID != "gqat_01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatalf("attempt reference lost: %#v", body.AttemptID)
	}
	if body.SQLHash == nil || *body.SQLHash != hash {
		t.Fatalf("confirmed hash lost: %#v", body.SQLHash)
	}
	if body.Name != "\u0420\u0435\u0439\u0441\u044b \u0437\u0430 \u043d\u0435\u0434\u0435\u043b\u044e" || body.Schedule != "daily" {
		t.Fatalf("the projection's own operator-visible settings must survive: name=%q schedule=%q", body.Name, body.Schedule)
	}
}

// The reference alone is not enough: the operator confirms WHICH executed
// statement is being saved, so a body without the hash is refused before any
// database round trip.
func TestPromoteBodyRequiresBothTheReferenceAndTheHash(t *testing.T) {
	hash := "sha256:" + strings.Repeat("a", 64)
	for name, raw := range map[string]string{
		"no hash":      `{"attempt_id":"gqat_01ARZ3NDEKTSV4RRFFQ69G5FAV"}`,
		"no reference": `{"sql_hash":"` + hash + `"}`,
		"neither":      `{}`,
	} {
		var body governedQueryPromoteBody
		if err := decodeBody(raw, &body); err != nil {
			t.Fatalf("%s: expected a decodable body the handler then rejects, got %v", name, err)
		}
		if body.AttemptID != nil && *body.AttemptID != "" && body.SQLHash != nil && *body.SQLHash != "" {
			t.Fatalf("%s: expected an incomplete promote request", name)
		}
	}
}
