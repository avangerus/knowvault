package observation

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"knowvault.local/verified-workspace/internal/connector/mail"
)

func TestMailAdapterBindsServerOwnedScopeBeforeNetwork(t *testing.T) {
	connector, err := mail.New(mail.Config{Endpoint: "127.0.0.1:1", Mailbox: "ops@example.com", Folder: "INBOX",
		Username: "reader", Password: "secret", MaxMessageBytes: 128, MaxAttachmentBytes: 64,
		TLSConfig: &tls.Config{ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("connector: %v", err)
	}
	adapter, err := NewMailAdapter(connector, "org_demo", "scope_mail", 2)
	if err != nil {
		t.Fatalf("adapter: %v", err)
	}
	_, err = adapter.Observe(context.Background(), Request{OrganizationID: "other", SourceScopeID: "scope_mail", SourceScopeRevision: 2, MaxObjects: 1, MaxBytes: 128})
	if CodeOf(err) != CodeInvalidRequest {
		t.Fatalf("scope mismatch code=%q err=%v", CodeOf(err), err)
	}
	if got := mailMediaFamily("application/pdf"); got != "PDF" {
		t.Fatalf("pdf family=%q", got)
	}
	if got := mailMediaFamily("message/rfc822"); got != "TEXT" {
		t.Fatalf("message family=%q", got)
	}
}
