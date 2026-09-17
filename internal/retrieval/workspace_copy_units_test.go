package retrieval

import (
	"reflect"
	"testing"

	"knowvault.local/verified-workspace/internal/source/evidence"
)

func copyUnitTestGroups(t *testing.T, names ...string) ([]workspaceSearchGroup, map[string]evidence.Fragment) {
	t.Helper()
	groups := make([]workspaceSearchGroup, len(names))
	for i, name := range names {
		var err error
		groups[i], err = workspaceGroupFromDocument(workspaceGroupTestDocument(name, 2))
		if err != nil {
			t.Fatal(err)
		}
		groups[i].Score = float64(len(names) - i)
	}
	probes := workspaceGroupTestProbeMap(groups)
	for id, probe := range probes {
		probe.ObjectType, probe.CanonicalFormat, probe.ParserProfileRevision = "FILE", "MARKDOWN", "markdown-v1"
		probes[id] = probe
	}
	return groups, probes
}

func copyUnitTestIDs(groups []workspaceSearchGroup) []string {
	ids := make([]string, len(groups))
	for i, group := range groups {
		ids[i] = group.ID
	}
	return ids
}

func TestWorkspaceCopyUnitsPromoteDistinctPassagesAndKeepEveryAddressAcrossPages(t *testing.T) {
	groups, probes := copyUnitTestGroups(t, "original", "copy-a", "distinct", "copy-b")
	// A distinct passage of the very same file must keep its rank. Only the
	// identical passages in other source objects move behind it.
	distinct := &groups[2]
	distinct.SourceObjectID, distinct.SourceVersionID, distinct.ExtractionID = groups[0].SourceObjectID, groups[0].SourceVersionID, groups[0].ExtractionID
	for i := range distinct.Members {
		member := &distinct.Members[i]
		member.SourceObjectID, member.SourceVersionID, member.ExtractionID = distinct.SourceObjectID, distinct.SourceVersionID, distinct.ExtractionID
		member.TextHash = workspaceGroupTestHash("hmac-sha256:k1:", i+3)
	}
	probe := probes[distinct.Members[0].FragmentID]
	probe.SourceObjectID, probe.SourceVersionID, probe.ExtractionID = distinct.SourceObjectID, distinct.SourceVersionID, distinct.ExtractionID
	probe.EvidenceTextHash = distinct.Members[0].TextHash
	probes[probe.FragmentID] = probe
	want := []workspaceSearchGroup{groups[0], groups[2], groups[1], groups[3]}
	for _, pageSize := range []int64{1, 2, 3, 10} {
		var got []workspaceSearchGroup
		var offset int64
		for {
			page, err := planWorkspaceGroupWindow(groups, probes, len(groups), offset, pageSize)
			if err != nil {
				t.Fatal(err)
			}
			if page.Partial {
				t.Fatal("copy deferral must not report missing candidates")
			}
			got = append(got, page.Groups...)
			if !page.HasMore {
				break
			}
			if page.NextOffset <= offset {
				t.Fatal("cursor did not advance")
			}
			offset = page.NextOffset
		}
		// Deep equality covers original scores, every member and its immutable
		// version/hash identity, not just the new display order.
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("page size %d: got %v want %v", pageSize, copyUnitTestIDs(got), copyUnitTestIDs(want))
		}
	}
	if got := copyUnitTestIDs(groups); !reflect.DeepEqual(got, []string{"original", "copy-a", "distinct", "copy-b"}) {
		t.Fatalf("input ranking was mutated: %v", got)
	}
}

func TestWorkspaceCopyUnitsDeniedOriginalCannotDemoteReadableCopy(t *testing.T) {
	groups, probes := copyUnitTestGroups(t, "denied-original", "readable-copy", "other-file")
	delete(probes, groups[0].Members[0].FragmentID)
	groups[2].ContentHash = workspaceGroupTestHash("sha256:", 7)
	for i := range groups[2].Members {
		groups[2].Members[i].ContentHash = groups[2].ContentHash
	}
	probe := probes[groups[2].Members[0].FragmentID]
	probe.ContentHash = groups[2].ContentHash
	probes[probe.FragmentID] = probe
	page, err := planWorkspaceGroupWindow(groups, probes, len(groups), 0, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Groups) != 1 || page.Groups[0].ID != "readable-copy" || page.NextOffset != 1 {
		t.Fatalf("denied content influenced the visible order: %+v", page)
	}
}

func TestWorkspaceCopyUnitsRequireSameFileReading(t *testing.T) {
	for _, variation := range []string{"row", "git-file", "unknown-type", "unknown-format", "different-format", "unknown-parser", "different-parser", "different-content", "different-text", "different-member-order", "same-object"} {
		t.Run(variation, func(t *testing.T) {
			groups, probes := copyUnitTestGroups(t, "first", "second", "third")
			// Third always has independent content, so accidental deferral of
			// second would be visible as first/third/second.
			third := probes[groups[2].Members[0].FragmentID]
			third.CanonicalFormat = "TXT"
			probes[third.FragmentID] = third
			second := probes[groups[1].Members[0].FragmentID]
			switch variation {
			case "row":
				second.ObjectType = "DATABASE_ROW"
			case "git-file":
				second.ObjectType = "GIT_FILE"
			case "unknown-type":
				second.ObjectType = ""
			case "unknown-format":
				second.CanonicalFormat = ""
			case "different-format":
				second.CanonicalFormat = "DOCX"
			case "unknown-parser":
				second.ParserProfileRevision = ""
			case "different-parser":
				second.ParserProfileRevision = "markdown-v2"
			case "different-content":
				groups[1].ContentHash = workspaceGroupTestHash("sha256:", 6)
			case "different-text":
				groups[1].Members[1].TextHash = workspaceGroupTestHash("hmac-sha256:k1:", 6)
			case "different-member-order":
				groups[1].Members[0].TextHash, groups[1].Members[1].TextHash = groups[1].Members[1].TextHash, groups[1].Members[0].TextHash
			case "same-object":
				groups[1].SourceObjectID = groups[0].SourceObjectID
			}
			probes[second.FragmentID] = second
			got := deferWorkspaceCopyUnits(groups, probes)
			if !reflect.DeepEqual(got, groups) {
				t.Fatalf("non-copy moved: %v", copyUnitTestIDs(got))
			}
		})
	}
}
