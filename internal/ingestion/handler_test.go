package ingestion

import (
	"context"
	"testing"

	"knowvault.local/verified-workspace/internal/source/observation"
)

type bindingTestAdapter struct{ kind observation.Kind }

func (adapter bindingTestAdapter) Kind() observation.Kind { return adapter.kind }
func (adapter bindingTestAdapter) Observe(context.Context, observation.Request) (observation.Page, error) {
	return observation.Page{}, nil
}

// TestResolveActivationGateRefusesUntrustedOrNonSyncingScope pins the
// resolution-time trust gate (SRC-014): a scope revision that is not SYNCING or
// whose trust profile is not verified must never resolve, and a non-FOLDER or
// non-WORKSPACE_MANAGED scope is refused as unsupported.
func TestResolveActivationGateRefusesUntrustedOrNonSyncingScope(t *testing.T) {
	tests := []struct {
		name             string
		sourceType       string
		accessMode       string
		activationStatus string
		trustVerified    bool
		wantCode         string
	}{
		{"syncing trusted folder resolves", "FOLDER", "WORKSPACE_MANAGED", "SYNCING", true, ""},
		{"syncing trusted git resolves at gate", "GIT", "WORKSPACE_MANAGED", "SYNCING", true, ""},
		{"syncing trusted mail resolves at gate", "MAIL", "WORKSPACE_MANAGED", "SYNCING", true, ""},
		{"non-folder source refused", "SITE", "WORKSPACE_MANAGED", "SYNCING", true, "INGEST_SCOPE_UNSUPPORTED"},
		{"source-enforced access refused", "FOLDER", "SOURCE_ENFORCED", "SYNCING", true, "INGEST_SCOPE_UNSUPPORTED"},
		{"non-syncing revision refused", "FOLDER", "WORKSPACE_MANAGED", "DRAFT", true, "INGEST_ACTIVATION_NOT_READY"},
		{"untrusted revision refused", "FOLDER", "WORKSPACE_MANAGED", "SYNCING", false, "INGEST_ACTIVATION_NOT_READY"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := activationGate(tc.sourceType, tc.accessMode, tc.activationStatus, tc.trustVerified)
			if tc.wantCode == "" {
				if err != nil {
					t.Fatalf("gate unexpectedly refused: %v", err)
				}
				return
			}
			if got := CodeOf(err); got != tc.wantCode {
				t.Fatalf("gate code = %q, want %q", got, tc.wantCode)
			}
		})
	}
}

func TestObservationSourceTypeMappingIsClosed(t *testing.T) {
	cases := map[string]string{"FOLDER": "DOCUMENT", "GIT": "GIT", "MAIL": "MAIL"}
	for sourceType, want := range cases {
		kind, ok := observationKindForSourceType(sourceType)
		if !ok || string(kind) != want {
			t.Fatalf("source type %q = (%q,%v), want (%q,true)", sourceType, kind, ok, want)
		}
	}
	for _, sourceType := range []string{"SITE", "POSTGRESQL_QUERY", "", "git"} {
		if _, ok := observationKindForSourceType(sourceType); ok {
			t.Fatalf("unsupported source type %q was mapped", sourceType)
		}
	}
}

func TestObservationBindingValidationRejectsWrongKindAndUntrustedFormats(t *testing.T) {
	if _, _, err := validateObservationBinding("GIT", ObservationAdapterBinding{
		Adapter: bindingTestAdapter{kind: observation.KindMail}, Formats: map[string]bool{"TXT": true},
	}); CodeOf(err) != "INGEST_ADAPTER_INVALID" {
		t.Fatalf("wrong adapter kind code=%q", CodeOf(err))
	}
	if _, _, err := validateObservationBinding("MAIL", ObservationAdapterBinding{
		Adapter: bindingTestAdapter{kind: observation.KindMail}, Formats: map[string]bool{"UNKNOWN": true},
	}); CodeOf(err) != "INGEST_ADAPTER_INVALID" {
		t.Fatalf("unknown format code=%q", CodeOf(err))
	}
	kind, formats, err := validateObservationBinding("MAIL", ObservationAdapterBinding{
		Adapter: bindingTestAdapter{kind: observation.KindMail}, Formats: map[string]bool{"EML": true},
	})
	if err != nil || kind != observation.KindMail || !formats["EML"] {
		t.Fatalf("valid binding rejected: kind=%q formats=%v err=%v", kind, formats, err)
	}
}

func TestInvalidObservationBindingRetiresReturnedConnector(t *testing.T) {
	closed := false
	_, _, err := validateObservationBindingForResolution("GIT", ObservationAdapterBinding{
		Adapter: bindingTestAdapter{kind: observation.KindMail},
		Formats: map[string]bool{"TXT": true},
		Close: func() error {
			closed = true
			return nil
		},
	})
	if CodeOf(err) != "INGEST_ADAPTER_INVALID" {
		t.Fatalf("invalid binding code=%q err=%v", CodeOf(err), err)
	}
	if !closed {
		t.Fatal("invalid binding left connector open")
	}
}
