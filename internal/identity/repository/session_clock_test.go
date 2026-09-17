package repository

import (
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/identity"
)

// clockStore builds a Store with only the injectable app clock set. The
// regression tests below drive store.validateSession directly, so the
// database and audit stores are never touched; this exercises the exact
// production helper ResolveSession calls at its final validation step.
func clockStore(appNow time.Time) *Store {
	return &Store{now: func() time.Time { return appNow }}
}

func clockClaims(t *testing.T, expiresAt time.Time) identity.Claims {
	t.Helper()
	claims, err := identity.NewClaims("org_alpha", "usr_alice", 7, "idp_alpha", 3, expiresAt)
	if err != nil {
		t.Fatalf("build claims: %v", err)
	}
	return claims
}

func clockPrincipal(t *testing.T, status identity.PrincipalStatus, revision int64) identity.CurrentPrincipal {
	t.Helper()
	principal, err := identity.NewCurrentPrincipal("org_alpha", "usr_alice", status, revision)
	if err != nil {
		t.Fatalf("build current principal: %v", err)
	}
	return principal
}

func clockProvider(t *testing.T, status identity.ProviderStatus, revision int64) identity.CurrentProvider {
	t.Helper()
	provider, err := identity.NewCurrentProvider("org_alpha", "idp_alpha", status, revision)
	if err != nil {
		t.Fatalf("build current provider: %v", err)
	}
	return provider
}

// TestValidateSessionRejectsDatabaseExpiredWhenAppClockLags checks that a session the database already considers expired must not
// authorise merely because the app clock is behind it.
func TestValidateSessionRejectsDatabaseExpiredWhenAppClockLags(t *testing.T) {
	databaseNow := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	appNow := databaseNow.Add(-2 * time.Minute)
	expiresAt := databaseNow.Add(-time.Minute) // expired one minute before the DB instant

	store := clockStore(appNow)
	claims := clockClaims(t, expiresAt)
	principal := clockPrincipal(t, identity.PrincipalActive, 7)
	provider := clockProvider(t, identity.ProviderActive, 3)

	err := store.validateSession(claims, principal, provider, databaseNow)
	if code := identity.CodeOf(err); code != identity.CodeSessionExpired {
		t.Fatalf("lagging app clock: code=%q, want CodeSessionExpired (err=%v)", code, err)
	}
}

// TestValidateSessionRejectsAtExactDatabaseExpiryBoundary proves the boundary
// is inclusive-denied exactly as identity.Validate defines it: a session whose
// expiry equals the database instant is expired.
func TestValidateSessionRejectsAtExactDatabaseExpiryBoundary(t *testing.T) {
	databaseNow := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	appNow := databaseNow.Add(-5 * time.Minute)
	expiresAt := databaseNow // exactly the DB decision instant

	store := clockStore(appNow)
	claims := clockClaims(t, expiresAt)
	principal := clockPrincipal(t, identity.PrincipalActive, 7)
	provider := clockProvider(t, identity.ProviderActive, 3)

	err := store.validateSession(claims, principal, provider, databaseNow)
	if code := identity.CodeOf(err); code != identity.CodeSessionExpired {
		t.Fatalf("exact DB expiry boundary: code=%q, want CodeSessionExpired (err=%v)", code, err)
	}
}

// TestValidateSessionRejectsAppExpiredWhenDatabaseClockLags proves the
// existing app-clock expiration is preserved: when the app clock runs ahead
// and considers the session expired, validation still denies.
func TestValidateSessionRejectsAppExpiredWhenDatabaseClockLags(t *testing.T) {
	appNow := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	databaseNow := appNow.Add(-2 * time.Minute)
	expiresAt := appNow.Add(-time.Minute) // expired relative to the app clock

	store := clockStore(appNow)
	claims := clockClaims(t, expiresAt)
	principal := clockPrincipal(t, identity.PrincipalActive, 7)
	provider := clockProvider(t, identity.ProviderActive, 3)

	err := store.validateSession(claims, principal, provider, databaseNow)
	if code := identity.CodeOf(err); code != identity.CodeSessionExpired {
		t.Fatalf("ahead app clock: code=%q, want CodeSessionExpired (err=%v)", code, err)
	}
}

// TestValidateSessionAllowsWhenBothClocksBeforeExpiry proves a live session
// still authorises under the later-of-two rule.
func TestValidateSessionAllowsWhenBothClocksBeforeExpiry(t *testing.T) {
	appNow := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	databaseNow := appNow.Add(time.Second)
	expiresAt := appNow.Add(10 * time.Minute) // live on both clocks

	store := clockStore(appNow)
	claims := clockClaims(t, expiresAt)
	principal := clockPrincipal(t, identity.PrincipalActive, 7)
	provider := clockProvider(t, identity.ProviderActive, 3)

	if err := store.validateSession(claims, principal, provider, databaseNow); err != nil {
		t.Fatalf("live session denied: %v (code=%q)", err, identity.CodeOf(err))
	}
}

// TestValidateSessionRetainsTypedErrorPriority proves the later-of-two rule
// does not reorder or mask identity.Validate's typed failures: a disabled
// principal or provider and a revision mismatch keep their own codes even
// when the database clock is the binding validation instant.
func TestValidateSessionRetainsTypedErrorPriority(t *testing.T) {
	databaseNow := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	appNow := databaseNow.Add(-2 * time.Minute)
	expiresAt := databaseNow.Add(time.Hour) // live: expiry is not the failing rule

	store := clockStore(appNow)
	claims := clockClaims(t, expiresAt)

	cases := []struct {
		name      string
		principal identity.CurrentPrincipal
		provider  identity.CurrentProvider
		want      identity.ErrorCode
	}{
		{
			name:      "disabled principal",
			principal: clockPrincipal(t, identity.PrincipalDisabled, 7),
			provider:  clockProvider(t, identity.ProviderActive, 3),
			want:      identity.CodePrincipalInactive,
		},
		{
			name:      "disabled provider",
			principal: clockPrincipal(t, identity.PrincipalActive, 7),
			provider:  clockProvider(t, identity.ProviderDisabled, 3),
			want:      identity.CodeProviderInactive,
		},
		{
			name:      "revision mismatch",
			principal: clockPrincipal(t, identity.PrincipalActive, 8),
			provider:  clockProvider(t, identity.ProviderActive, 3),
			want:      identity.CodeSessionMismatch,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			err := store.validateSession(claims, testCase.principal, testCase.provider, databaseNow)
			if code := identity.CodeOf(err); code != testCase.want {
				t.Fatalf("code=%q, want %q (err=%v)", code, testCase.want, err)
			}
		})
	}
}
