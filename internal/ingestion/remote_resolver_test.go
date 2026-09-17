package ingestion

import (
	"context"
	"strings"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/platform/database"
	"knowvault.local/verified-workspace/internal/source/canon"
)

func TestRemoteResolverRejectsInvalidTargetBeforeAnyDependency(t *testing.T) {
	resolver := &RemoteObservationAdapterResolver{}
	access := database.AccessContext{OrganizationID: "org_demo", PrincipalID: "knowvault_worker", RequestID: "req_demo"}
	if _, err := resolver.Resolve(context.Background(), access, ObservationAdapterTarget{SourceType: "FOLDER"}); CodeOf(err) != "INGEST_RESOLVER_INVALID" {
		t.Fatalf("invalid target code=%q err=%v", CodeOf(err), err)
	}
}

func TestRemoteResolverCanonicalConfigShapesRoundTrip(t *testing.T) {
	gitTrust, err := canon.GitTrustBytes("conn_demo", "GITHUB", "https://api.github.com", "")
	if err != nil {
		t.Fatal(err)
	}
	var parsedGitTrust remoteGitTrust
	if err := decodeRemote(gitTrust, &parsedGitTrust); err != nil || parsedGitTrust.ConnectionID != "conn_demo" {
		t.Fatalf("git trust=%#v err=%v", parsedGitTrust, err)
	}
	gitConfig, err := canon.GitScopeConfigBytes("GITHUB", "acme/repo", "main", []string{"**/*.go"}, nil,
		[]string{"text/x-go"}, 1024)
	if err != nil {
		t.Fatal(err)
	}
	var parsedGitConfig remoteGitConfig
	if err := decodeRemote(gitConfig, &parsedGitConfig); err != nil || parsedGitConfig.PathMatcher != "scope-glob-v1" || parsedGitConfig.Submodules || parsedGitConfig.LFSContent {
		t.Fatalf("git config=%#v err=%v", parsedGitConfig, err)
	}
	since := time.Date(2026, 8, 30, 0, 0, 0, 0, time.UTC)
	mailConfig, err := canon.MailScopeConfigBytes("imap.example:993", "tenant-a", "INBOX", &since, true, 8<<20, 4<<20, []string{"text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	var parsedMailConfig remoteMailConfig
	if err := decodeRemote(mailConfig, &parsedMailConfig); err != nil || parsedMailConfig.Since == nil {
		t.Fatalf("mail config=%#v err=%v", parsedMailConfig, err)
	}
	parsedSince, err := parseCanonicalSince(parsedMailConfig.Since)
	if err != nil || parsedSince == nil || !parsedSince.Equal(since) {
		t.Fatalf("since=%v err=%v", parsedSince, err)
	}
	if got := gitFormats([]string{"text/x-go", "application/json", "text/markdown"}); !got["SOURCE_CODE"] || !got["JSON"] || !got["MARKDOWN"] {
		t.Fatalf("git formats=%v", got)
	}
	if got := mailFormats(true, []string{"text/plain", "application/pdf"}); !got["EML"] || !got["TXT"] || !got["PDF"] {
		t.Fatalf("mail formats=%v", got)
	}
}

func TestRemoteResolverRejectsNonCanonicalOrUnknownConfig(t *testing.T) {
	var trust remoteGitTrust
	if err := decodeRemote([]byte(`{"schema_version":"source-git-trust-v1","source_type":"GIT","connection_id":"c","provider":"GITHUB","endpoint":"https://example","web_base_url":"","extra":true}`), &trust); err == nil {
		t.Fatal("unknown remote config member was accepted")
	}
	if _, err := parseCanonicalSince(stringPtr("2026-08-30T00:00:00+03:00")); err == nil {
		t.Fatal("non-UTC since was accepted")
	}
	if validSHA256("sha256:"+strings.Repeat("0", 63)) || validSHA256("sha256:"+strings.Repeat("g", 64)) || validSHA256("sha256:"+strings.Repeat("A", 64)) {
		t.Fatal("invalid SHA accepted")
	}
}

func TestRemoteResolverTrustLoaderMustReturnSourcePurposeRoots(t *testing.T) {
	loader := SourceTrustLoader(func() (SourceTrustPools, error) { return SourceTrustPools{}, nil })
	if loader == nil {
		t.Fatal("nil trust loader")
	}
	if roots, err := loader(); err != nil {
		t.Fatalf("loader err=%v", err)
	} else if roots.GitRoots != nil || roots.MailRoots != nil {
		t.Fatalf("zero source roots did not fail closed: %v", roots)
	}
}

func stringPtr(value string) *string { return &value }
