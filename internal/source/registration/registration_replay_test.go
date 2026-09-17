package registration

// Regression proof for the source-registration replay contract (demo-cycle
// FAIL: re-registering the same lineage answered 409 SOURCE_CONFLICT).  Every
// Stage-2 lineage id is a content derivation of the tenant plus this exact
// request, so an exact re-registration deterministically derives the SAME
// connection/discovered-scope/source-scope ids and therefore converges on the
// already-committed lineage (created=false) instead of surfacing a spurious
// SOURCE_CONFLICT, while a genuine configuration divergence on an
// already-taken identity keeps the fail-closed typed-conflict path intact.
// These are DB-free unit checks of the derivation surface the service's replay
// branch and the app.*_registration_begin functions both use.

import (
	"testing"

	"knowvault.local/verified-workspace/internal/source/canon"
)

func folderLineage(org string, request RegisterRequest) (conn, discovered, scope, credRef string) {
	conn = connectionID(org, request.RootIdentity)
	discovered = discoveredScopeID(org, conn, request.RelativeRoot)
	scope = scopeID(org, discovered)
	credRef = credentialReference(org, conn)
	return conn, discovered, scope, credRef
}

func TestFolderExactReplayDerivesIdenticalRegistrationIDs(t *testing.T) {
	request := RegisterRequest{
		Name: "Engineering docs", RootAlias: "docs-root", RootIdentity: "vol-1",
		RelativeRoot: "projects/alpha", Kind: "documents", Recursive: true,
		IncludeGlobs: []string{"**/*"}, ExcludeGlobs: []string{}, MaxFileBytes: 1048576,
		OCRMode: "OFF", Formats: []string{"TXT", "MARKDOWN"},
	}
	// An exact re-POST is byte-identical: the content-derived lineage must not
	// move, so a second Register converges on the first rows (created=false) and
	// never mints a second connection/source_scope.
	connA, discA, scopeA, credA := folderLineage("org_registration", request)
	connB, discB, scopeB, credB := folderLineage("org_registration", request)
	if connA != connB || discA != discB || scopeA != scopeB || credA != credB {
		t.Fatalf("exact replay drifted lineage: first=(%q,%q,%q,%q) second=(%q,%q,%q,%q)",
			connA, discA, scopeA, credA, connB, discB, scopeB, credB)
	}
	if connA == "" || discA == "" || scopeA == "" || credA == "" {
		t.Fatalf("registration derived an empty id: conn=%q disc=%q scope=%q cred=%q", connA, discA, scopeA, credA)
	}
}

func TestFolderReplayIsTenantScoped(t *testing.T) {
	request := RegisterRequest{RootIdentity: "vol-1", RelativeRoot: "projects/alpha"}
	orgAconn, orgAdisc, _, _ := folderLineage("org_a", request)
	orgBconn, orgBdisc, _, _ := folderLineage("org_b", request)
	if orgAconn == orgBconn || orgAdisc == orgBdisc {
		t.Fatalf("registration lineage crossed organization boundary: a=(%q,%q) b=(%q,%q)",
			orgAconn, orgAdisc, orgBconn, orgBdisc)
	}
}

func TestFolderDisplayChangeIsAGenuineLineageCollision(t *testing.T) {
	// The display name feeds the sealed display artifact but not the lineage
	// ids.  Changing only the name keeps every derived id identical, so the
	// re-registration would hit the exact-match guard in
	// app.source_folder_registration_begin (name compared) and fail closed as a
	// typed conflict rather than silently overwriting the existing lineage.
	base := RegisterRequest{Name: "Engineering docs", RootIdentity: "vol-1", RelativeRoot: "projects/alpha"}
	renamed := base
	renamed.Name = "A different display name"

	_, _, scopeBase, _ := folderLineage("org_registration", base)
	_, _, scopeRenamed, _ := folderLineage("org_registration", renamed)
	if scopeBase != scopeRenamed {
		t.Fatal("a display-only change must not move the scope id; otherwise it would silently overwrite")
	}

	// The guarded CodeConflict mapping is preserved: a typed collision surfaces
	// SOURCE_CONFLICT, never a success or a persistence fallback.
	conflict := &Error{code: CodeConflict}
	if got := CodeOf(conflict); got != CodeConflict {
		t.Fatalf("CodeConflict mapping changed: got %q want %q", got, CodeConflict)
	}
}

func TestRemoteExactReplayConvergesAndRealBranchChangeIsADifferentLineage(t *testing.T) {
	org := "org_registration"
	request := RegisterRequest{
		SourceType: "GIT", Provider: "GITHUB", Endpoint: "https://api.github.com",
		RepositoryID: "acme/knowledge", BranchName: "main",
	}
	conn := remoteConnectionID(org, request.SourceType, request.Endpoint, request.Provider, request.RepositoryID, request.Mailbox)

	identityMain, err := canon.GitScopeIdentityBytes(conn, request.Provider, request.RepositoryID, request.BranchName)
	if err != nil {
		t.Fatal(err)
	}
	identityMainHash := canon.Hash(identityMain)
	discMain := remoteDiscoveredScopeID(org, conn, request.SourceType, identityMainHash)
	scopeMain := scopeID(org, discMain)

	// An exact re-POST derives the same remote lineage -> created=false replay.
	if remoteConnectionID(org, request.SourceType, request.Endpoint, request.Provider, request.RepositoryID, request.Mailbox) != conn {
		t.Fatal("exact remote replay drifted connection id")
	}
	if remoteDiscoveredScopeID(org, conn, request.SourceType, identityMainHash) != discMain {
		t.Fatal("exact remote replay drifted discovered scope id")
	}

	// A genuinely different branch is a different source lineage (distinct
	// discovered/scope id), so it registers as a new lineage rather than a
	// spurious conflict on the original one.
	rebased := request
	rebased.BranchName = "develop"
	identityDevelop, err := canon.GitScopeIdentityBytes(conn, rebased.Provider, rebased.RepositoryID, rebased.BranchName)
	if err != nil {
		t.Fatal(err)
	}
	discDevelop := remoteDiscoveredScopeID(org, conn, request.SourceType, canon.Hash(identityDevelop))
	scopeDevelop := scopeID(org, discDevelop)
	if discDevelop == discMain || scopeDevelop == scopeMain {
		t.Fatalf("a real branch change must be a distinct lineage: main=(%q,%q) develop=(%q,%q)",
			discMain, scopeMain, discDevelop, scopeDevelop)
	}
}

func TestScheduledUniqueConflictOnlySkipsLiveScopeConstraint(t *testing.T) {
	for name, testCase := range map[string]struct {
		sqlState       string
		constraintName string
		want           bool
	}{
		"live scope job": {
			sqlState: uniqueViolationSQLState, constraintName: liveScopeSyncConstraint,
			want: true,
		},
		"different unique index": {
			sqlState: uniqueViolationSQLState, constraintName: "job_pkey",
			want: false,
		},
		"different SQL state": {
			sqlState: "23514", constraintName: liveScopeSyncConstraint,
			want: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := isLiveScopeSyncConflict(testCase.sqlState, testCase.constraintName); got != testCase.want {
				t.Fatalf("isLiveScopeSyncConflict=%v, want %v", got, testCase.want)
			}
		})
	}
}
