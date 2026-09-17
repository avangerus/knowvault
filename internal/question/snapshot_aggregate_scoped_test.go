package question

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/platform/database"
)

func TestLoadStructuredSnapshotForSourceVersionRejectsEmptyAnchor(t *testing.T) {
	service := &Service{}
	_, _, _, err := service.loadStructuredSnapshotForSourceVersion(
		context.Background(), database.AccessContext{}, "workspace", "fragment", "")
	if err == nil {
		t.Fatal("empty source-version anchor was accepted")
	}
}
