package registration

import (
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/source/postgresqlquery"
)

func TestDiscoveryRequestIDIsStableForScopedIdempotency(t *testing.T) {
	const hash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	left := discoveryRequestID("org_alpha", "usr_owner", hash)
	right := discoveryRequestID("org_alpha", "usr_owner", hash)
	if left != right || !validGeneratedID(left, "sdrq_") {
		t.Fatalf("discovery request id = %q/%q", left, right)
	}
	if discoveryRequestID("org_beta", "usr_owner", hash) == left ||
		discoveryRequestID("org_alpha", "usr_other", hash) == left ||
		discoveryRequestID("org_alpha", "usr_owner", "sha256:"+repeatHex('f', 64)) == left {
		t.Fatal("discovery id does not stay scoped to organization and idempotency hash")
	}
}

func TestNormalizeDiscoveryLimitsUsesBoundedServerProfile(t *testing.T) {
	limits, err := normalizeDiscoveryLimits(postgresqlquery.DiscoveryLimits{})
	if err != nil || limits != postgresqlquery.DefaultDiscoveryLimits() {
		t.Fatalf("default discovery limits = %#v, err=%v", limits, err)
	}
	if _, err := normalizeDiscoveryLimits(postgresqlquery.DiscoveryLimits{
		MaxViews: 65, MaxColumns: 1, MaxCommentBytes: 1,
		StatementTimeout: time.Second, TransactionTimeout: time.Second,
	}); err == nil {
		t.Fatal("request accepted more views than the durable result bound")
	}
	tooLongStatement := postgresqlquery.DefaultDiscoveryLimits()
	tooLongStatement.StatementTimeout = 5*time.Minute + time.Millisecond
	if _, err := normalizeDiscoveryLimits(tooLongStatement); err == nil {
		t.Fatal("request accepted a statement timeout beyond the durable bound")
	}
	tooLongTransaction := postgresqlquery.DefaultDiscoveryLimits()
	tooLongTransaction.TransactionTimeout = 10*time.Minute + time.Millisecond
	if _, err := normalizeDiscoveryLimits(tooLongTransaction); err == nil {
		t.Fatal("request accepted a transaction timeout beyond the durable bound")
	}
}

func TestDiscoveryRequestValidationRejectsCallerControlledSecretsAndSelection(t *testing.T) {
	valid := DiscoveryRequest{
		ConnectionID: "conn_01ARZ3NDEKTSV4RRFFQ69G5FAV", IdempotencyKey: "request-1",
	}
	if !validGeneratedID(valid.ConnectionID, "conn_") || !validIdempotencyKey(valid.IdempotencyKey) {
		t.Fatal("valid opaque discovery request was rejected by its shape helpers")
	}
	for _, key := range []string{" request", "request\x00"} {
		if validIdempotencyKey(key) {
			t.Fatalf("unsafe idempotency key accepted: %q", key)
		}
	}
}

func repeatHex(character byte, count int) string {
	result := make([]byte, count)
	for index := range result {
		result[index] = character
	}
	return string(result)
}
