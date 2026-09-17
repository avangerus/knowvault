package identity

import (
	"strings"
	"testing"
	"time"
)

var identityNow = time.Date(2026, time.July, 15, 10, 0, 0, 0, time.UTC)

func TestValidateAcceptsOnlyExactCurrentActiveSnapshot(t *testing.T) {
	t.Parallel()

	claims := mustClaims(t, "org_alpha", "usr_alice", 7, "idp_alpha", 3, identityNow.Add(time.Hour))
	current := mustCurrentPrincipal(t, "org_alpha", "usr_alice", PrincipalActive, 7)
	provider := mustCurrentProvider(t, "org_alpha", "idp_alpha", ProviderActive, 3)
	if err := Validate(identityNow, claims, current, provider); err != nil {
		t.Fatalf("exact active snapshot denied: %v", err)
	}
}

func TestValidateFailsClosedForChangedOrUnavailableCurrentState(t *testing.T) {
	t.Parallel()

	claims := mustClaims(t, "org_alpha", "usr_alice", 7, "idp_alpha", 3, identityNow.Add(time.Hour))
	validProvider := mustCurrentProvider(t, "org_alpha", "idp_alpha", ProviderActive, 3)
	for name, testCase := range map[string]struct {
		claims   Claims
		current  CurrentPrincipal
		provider CurrentProvider
		now      time.Time
		code     ErrorCode
	}{
		"unknown principal": {
			claims: claims, current: UnknownCurrentPrincipal(), now: identityNow, code: CodePrincipalUnknown,
		},
		"disabled principal": {
			claims: claims, current: mustCurrentPrincipal(t, "org_alpha", "usr_alice", PrincipalDisabled, 7), now: identityNow, code: CodePrincipalInactive,
		},
		"deprovisioned principal": {
			claims: claims, current: mustCurrentPrincipal(t, "org_alpha", "usr_alice", PrincipalDeprovisioned, 7), now: identityNow, code: CodePrincipalInactive,
		},
		"expired at exact boundary": {
			claims: mustClaims(t, "org_alpha", "usr_alice", 7, "idp_alpha", 3, identityNow), current: mustCurrentPrincipal(t, "org_alpha", "usr_alice", PrincipalActive, 7), now: identityNow, code: CodeSessionExpired,
		},
		"organization mismatch": {
			claims: claims, current: mustCurrentPrincipal(t, "org_beta", "usr_alice", PrincipalActive, 7), now: identityNow, code: CodeSessionMismatch,
		},
		"principal mismatch": {
			claims: claims, current: mustCurrentPrincipal(t, "org_alpha", "usr_bob", PrincipalActive, 7), now: identityNow, code: CodeSessionMismatch,
		},
		"session revision mismatch": {
			claims: claims, current: mustCurrentPrincipal(t, "org_alpha", "usr_alice", PrincipalActive, 8), now: identityNow, code: CodeSessionMismatch,
		},
		"unknown provider": {
			claims: claims, current: mustCurrentPrincipal(t, "org_alpha", "usr_alice", PrincipalActive, 7), provider: UnknownCurrentProvider(), now: identityNow, code: CodeProviderUnknown,
		},
		"disabled provider": {
			claims: claims, current: mustCurrentPrincipal(t, "org_alpha", "usr_alice", PrincipalActive, 7), provider: mustCurrentProvider(t, "org_alpha", "idp_alpha", ProviderDisabled, 3), now: identityNow, code: CodeProviderInactive,
		},
		"provider organization mismatch": {
			claims: claims, current: mustCurrentPrincipal(t, "org_alpha", "usr_alice", PrincipalActive, 7), provider: mustCurrentProvider(t, "org_beta", "idp_alpha", ProviderActive, 3), now: identityNow, code: CodeSessionMismatch,
		},
		"provider revision mismatch": {
			claims: claims, current: mustCurrentPrincipal(t, "org_alpha", "usr_alice", PrincipalActive, 7), provider: mustCurrentProvider(t, "org_alpha", "idp_alpha", ProviderActive, 4), now: identityNow, code: CodeSessionMismatch,
		},
	} {
		name, testCase := name, testCase
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			provider := testCase.provider
			if !provider.Known() && testCase.code != CodeProviderUnknown {
				provider = validProvider
			}
			if got := CodeOf(Validate(testCase.now, testCase.claims, testCase.current, provider)); got != testCase.code {
				t.Fatalf("denial code = %q, want %q", got, testCase.code)
			}
		})
	}
}

func TestConstructorsRejectAmbiguousOrIncompleteSnapshots(t *testing.T) {
	t.Parallel()

	for name, build := range map[string]func() error{
		"claims empty organization": func() error {
			_, err := NewClaims("", "usr_alice", 1, "idp_alpha", 1, identityNow.Add(time.Hour))
			return err
		},
		"claims external-looking whitespace": func() error {
			_, err := NewClaims("org_alpha", "alice@example.com", 1, "idp_alpha", 1, identityNow.Add(time.Hour))
			return err
		},
		"claims zero revision": func() error {
			_, err := NewClaims("org_alpha", "usr_alice", 0, "idp_alpha", 1, identityNow.Add(time.Hour))
			return err
		},
		"claims zero expiry": func() error {
			_, err := NewClaims("org_alpha", "usr_alice", 1, "idp_alpha", 1, time.Time{})
			return err
		},
		"claims missing provider": func() error {
			_, err := NewClaims("org_alpha", "usr_alice", 1, "", 1, identityNow.Add(time.Hour))
			return err
		},
		"current invalid status": func() error {
			_, err := NewCurrentPrincipal("org_alpha", "usr_alice", "ACTIVE_OR_UNKNOWN", 1)
			return err
		},
		"current zero revision": func() error {
			_, err := NewCurrentPrincipal("org_alpha", "usr_alice", PrincipalActive, 0)
			return err
		},
		"provider invalid status": func() error {
			_, err := NewCurrentProvider("org_alpha", "idp_alpha", "ACTIVE_OR_UNKNOWN", 1)
			return err
		},
	} {
		name, build := name, build
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := build(); err == nil {
				t.Fatal("invalid snapshot was accepted")
			}
		})
	}
}

func TestKeyedDigestAcceptsOnlyVersionedLowercaseHMACSHA256(t *testing.T) {
	t.Parallel()

	valid := "hmac-sha256:k12:" + strings.Repeat("a", 64)
	digest, err := NewKeyedDigest(valid)
	if err != nil || digest.Value() != valid {
		t.Fatalf("valid digest rejected: %#v %v", digest, err)
	}
	for _, invalid := range []string{
		"hmac-sha256:k0:" + strings.Repeat("a", 64),
		"hmac-sha256:k1:" + strings.Repeat("A", 64),
		"hmac-sha256:k1:short",
		"raw-oidc-subject",
	} {
		if _, err := NewKeyedDigest(invalid); CodeOf(err) != CodeDigestInvalid {
			t.Fatalf("invalid digest accepted: %q (%v)", invalid, err)
		}
	}
}

func TestValidationErrorsAreContentFree(t *testing.T) {
	t.Parallel()

	claims := mustClaims(t, "org_alpha", "usr_alice", 1, "idp_alpha", 1, identityNow.Add(time.Hour))
	current := mustCurrentPrincipal(t, "org_alpha", "usr_secret_value", PrincipalActive, 2)
	err := Validate(identityNow, claims, current, mustCurrentProvider(t, "org_alpha", "idp_alpha", ProviderActive, 1))
	if CodeOf(err) != CodeSessionMismatch {
		t.Fatalf("mismatch code = %q", CodeOf(err))
	}
	if err == nil || strings.Contains(err.Error(), "usr_secret_value") || strings.Contains(err.Error(), "org_alpha") {
		t.Fatalf("identity error leaked contextual content: %v", err)
	}
	if got := CodeOf(nil); got != CodeDenied {
		t.Fatalf("unexpected nil error code = %q", got)
	}
}

func TestValidateRejectsZeroClock(t *testing.T) {
	t.Parallel()

	claims := mustClaims(t, "org_alpha", "usr_alice", 1, "idp_alpha", 1, identityNow.Add(time.Hour))
	current := mustCurrentPrincipal(t, "org_alpha", "usr_alice", PrincipalActive, 1)
	if got := CodeOf(Validate(time.Time{}, claims, current, mustCurrentProvider(t, "org_alpha", "idp_alpha", ProviderActive, 1))); got != CodeValidationInvalid {
		t.Fatalf("zero clock code = %q", got)
	}
}

func mustClaims(t *testing.T, organizationID OrganizationID, principalID PrincipalID, sessionRevision int64, providerID ProviderID, providerRevision int64, expiresAt time.Time) Claims {
	t.Helper()
	claims, err := NewClaims(organizationID, principalID, sessionRevision, providerID, providerRevision, expiresAt)
	if err != nil {
		t.Fatalf("NewClaims() error = %v", err)
	}
	return claims
}

func mustCurrentPrincipal(t *testing.T, organizationID OrganizationID, principalID PrincipalID, status PrincipalStatus, sessionRevision int64) CurrentPrincipal {
	t.Helper()
	principal, err := NewCurrentPrincipal(organizationID, principalID, status, sessionRevision)
	if err != nil {
		t.Fatalf("NewCurrentPrincipal() error = %v", err)
	}
	return principal
}

func mustCurrentProvider(t *testing.T, organizationID OrganizationID, providerID ProviderID, status ProviderStatus, revision int64) CurrentProvider {
	t.Helper()
	provider, err := NewCurrentProvider(organizationID, providerID, status, revision)
	if err != nil {
		t.Fatalf("NewCurrentProvider() error = %v", err)
	}
	return provider
}
