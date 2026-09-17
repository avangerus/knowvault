package composition

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestStartupStageOfAcceptsOnlyTheClosedRuntimeStartupTaxonomy(t *testing.T) {
	stages := []StartupStage{
		StartupStageTrustBundle,
		StartupStageSecrets,
		StartupStageDatabaseURL,
		StartupStageDatabaseRoots,
		StartupStageDatabase,
		StartupStageAuditStore,
		StartupStageIdentityStore,
		StartupStageWorkspaceStore,
		StartupStageJobQueue,
		StartupStageArtifactCodec,
		StartupStageSourceDigestKey,
		StartupStageSourceRegistration,
		StartupStageOIDCPreflight,
		StartupStageIdentityDigestor,
		StartupStageSessionDigestor,
		StartupStageTenantSecurity,
		StartupStageTenantResolver,
		StartupStageHTTPAuthResolver,
		StartupStageTransportCodec,
		StartupStageBrowserTransport,
		StartupStageOIDCRoots,
		StartupStageOIDCHTTPClient,
		StartupStageHTTPAuth,
		StartupStageOIDCHandler,
		StartupStageEvidenceViewer,
		StartupStageSearchMount,
		StartupStageSearchClient,
		StartupStageEmbeddingMount,
		StartupStageEmbeddingClient,
		StartupStageRetrievalExecutor,
		StartupStageGenerationMount,
		StartupStageGovernedQueryMount,
		StartupStageWorkspaceHandler,
		StartupStageWebUI,
		StartupStageHTTPDispatcher,
		StartupStageHTTPServer,
	}
	for _, stage := range stages {
		t.Run(string(stage), func(t *testing.T) {
			err := runtimeStartupError(stage)
			if CodeOf(err) != CodeRuntimeStartupFailed {
				t.Fatalf("code = %q, want %q", CodeOf(err), CodeRuntimeStartupFailed)
			}
			if got := StartupStageOf(err); got != stage {
				t.Fatalf("stage = %q, want %q", got, stage)
			}
			if got := err.Error(); got != string(CodeRuntimeStartupFailed) {
				t.Fatalf("error string = %q", got)
			}
		})
	}

	if got := StartupStageOf(runtimeError(CodeRuntimeRunFailed)); got != StartupStageUnknown {
		t.Fatalf("non-startup error stage = %q, want %q", got, StartupStageUnknown)
	}
	if got := StartupStageOf(errors.New("unrelated failure")); got != StartupStageUnknown {
		t.Fatalf("foreign error stage = %q, want %q", got, StartupStageUnknown)
	}
	if got := StartupStageOf(&Error{code: CodeRuntimeStartupFailed, stage: StartupStage("not-allowlisted")}); got != StartupStageUnknown {
		t.Fatalf("malformed stage = %q, want %q", got, StartupStageUnknown)
	}
}

func TestStartupFailureFormattingDoesNotLeakStageOrUnderlyingDetails(t *testing.T) {
	secret := "postgres://knowvault:super-secret@example.invalid/db"
	sentinel := errors.New(secret)
	err := &Error{code: CodeRuntimeStartupFailed, stage: StartupStage("startup-secret=" + secret)}
	formatted := fmt.Sprintf("%v|%#v", err, err)
	if strings.Contains(formatted, secret) || strings.Contains(formatted, "startup-secret") {
		t.Fatalf("startup error leaked private details: %q", formatted)
	}
	if errors.Is(err, sentinel) {
		t.Fatal("content-free startup error unexpectedly unwraps an underlying sentinel")
	}
	if got := err.Error(); got != string(CodeRuntimeStartupFailed) {
		t.Fatalf("error string = %q", got)
	}
	if got := StartupStageOf(err); got != StartupStageUnknown {
		t.Fatalf("unallowlisted stage = %q, want %q", got, StartupStageUnknown)
	}

	known := runtimeStartupError(StartupStageDatabase)
	knownFormatted := fmt.Sprintf("%#v", known)
	if strings.Contains(knownFormatted, string(StartupStageDatabase)) || !strings.Contains(knownFormatted, "REDACTED") {
		t.Fatalf("known startup stage escaped through GoString: %q", knownFormatted)
	}
}
