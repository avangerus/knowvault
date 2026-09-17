package knowledgegraph

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
)

func TestRelationMatchIncludesEndpointProvenanceContract(t *testing.T) {
	typeOfMatch := reflect.TypeOf(RelationMatch{})
	for _, fieldName := range []string{
		"SubjectSourceObjectID", "SubjectSourceVersionID", "SubjectEvidenceFragmentID",
		"ObjectSourceObjectID", "ObjectSourceVersionID", "ObjectEvidenceFragmentID",
	} {
		field, ok := typeOfMatch.FieldByName(fieldName)
		if !ok {
			t.Fatalf("RelationMatch is missing endpoint provenance field %s", fieldName)
		}
		if field.Type.Kind() != reflect.String {
			t.Fatalf("RelationMatch.%s type=%s, want opaque string ID", fieldName, field.Type)
		}
	}
}

func TestTermResolutionIncompleteForOpaqueStrongAmbiguityAndTruncation(t *testing.T) {
	termHash, err := SemanticTermHash("Kafka")
	if err != nil {
		t.Fatal(err)
	}
	resolution := TermResolution{
		AmbiguousTermHashes: []string{termHash},
		TruncatedTermHashes: []string{termHash},
	}
	if !resolution.Incomplete() {
		t.Fatal("ambiguous or truncated resolution was reported complete")
	}
	if strings.Contains(strings.Join(resolution.AmbiguousTermHashes, " "), "Kafka") ||
		strings.Contains(strings.Join(resolution.TruncatedTermHashes, " "), "Kafka") {
		t.Fatal("term resolution exposed plaintext catalog text")
	}
}

func TestResolveTermsDetailedRejectsInvalidTransaction(t *testing.T) {
	_, err := NewRepository().ResolveTermsDetailed(context.Background(), database.Transaction{}, database.AccessContext{}, ResolveQuery{
		WorkspaceID: "workspace_1",
		Terms:       []string{"Kafka"},
		Limit:       1,
	})
	if CodeOf(err) != CodeInvalid {
		t.Fatalf("invalid transaction error code=%s, want %s", CodeOf(err), CodeInvalid)
	}
}
