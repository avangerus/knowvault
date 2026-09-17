package tenantsecurity

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"knowvault.local/verified-workspace/internal/identity"
)

func TestContextRequiresDistinctKeySelectionsAndCanonicalDeploymentIdentity(t *testing.T) {
	identityDigestor := &recordingDigestor{name: "identity", secret: "super-secret-identity"}
	sessionDigestor := &recordingDigestor{name: "session", secret: "super-secret-session"}
	security, err := NewContext("org_alpha", "idp_primary", "https://workspace.example", "key_identity", identityDigestor, "key_session", sessionDigestor)
	if err != nil {
		t.Fatal(err)
	}
	if security.OrganizationID() != "org_alpha" || security.ProviderID() != "idp_primary" || security.PublicOrigin() != "https://workspace.example" || security.IdentityDigestor() == nil || security.SessionDigestor() == nil {
		t.Fatalf("context projection mismatch: %#v", security)
	}
	for _, formatted := range []string{fmt.Sprint(security), fmt.Sprintf("%#v", security), fmt.Sprintf("%#v", security.IdentityDigestor()), fmt.Sprintf("%#v", security.SessionDigestor())} {
		if strings.Contains(formatted, "super-secret") || !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("security formatting is not redacted: %q", formatted)
		}
	}
	if _, err := security.IdentityDigestor().Digest("subject", "raw-subject"); err != nil {
		t.Fatal(err)
	}
	if _, err := security.SessionDigestor().Digest("session_token", "raw-session"); err != nil {
		t.Fatal(err)
	}
	if _, err := security.IdentityDigestor().Digest("session_token", "wrong-selection"); CodeOf(err) != CodeResolutionFailed {
		t.Fatalf("identity selection accepted session purpose: %v", err)
	}
	if _, err := security.SessionDigestor().Digest("subject", "wrong-selection"); CodeOf(err) != CodeResolutionFailed {
		t.Fatalf("session selection accepted identity purpose: %v", err)
	}

	for name, build := range map[string]func() (Context, error){
		"same key reference": func() (Context, error) {
			return NewContext("org_alpha", "idp_primary", "https://workspace.example", "key_same", identityDigestor, "key_same", sessionDigestor)
		},
		"same digestor instance": func() (Context, error) {
			return NewContext("org_alpha", "idp_primary", "https://workspace.example", "key_identity", identityDigestor, "key_session", identityDigestor)
		},
		"same key material under different references": func() (Context, error) {
			return NewContext("org_alpha", "idp_primary", "https://workspace.example", "key_identity_alias", &recordingDigestor{name: "same", secret: "material"}, "key_session_alias", &recordingDigestor{name: "same", secret: "material"})
		},
		"default port alias": func() (Context, error) {
			return NewContext("org_alpha", "idp_primary", "https://workspace.example:443", "key_identity", identityDigestor, "key_session", sessionDigestor)
		},
		"path origin": func() (Context, error) {
			return NewContext("org_alpha", "idp_primary", "https://workspace.example/", "key_identity", identityDigestor, "key_session", sessionDigestor)
		},
		"invalid tenant": func() (Context, error) {
			return NewContext("org alpha", "idp_primary", "https://workspace.example", "key_identity", identityDigestor, "key_session", sessionDigestor)
		},
		"nil digestor": func() (Context, error) {
			return NewContext("org_alpha", "idp_primary", "https://workspace.example", "key_identity", identityDigestor, "key_session", nil)
		},
		"typed nil digestor": func() (Context, error) {
			var typedNil *recordingDigestor
			return NewContext("org_alpha", "idp_primary", "https://workspace.example", "key_identity", identityDigestor, "key_session", typedNil)
		},
	} {
		name, build := name, build
		t.Run(name, func(t *testing.T) {
			if _, err := build(); CodeOf(err) != CodeConfigurationInvalid {
				t.Fatalf("error=%v code=%s", err, CodeOf(err))
			}
		})
	}
}

func TestContextRequiresIndependentOIDCTransportKeyReference(t *testing.T) {
	security, err := NewContext("org_alpha", "idp_primary", "https://workspace.example", "kms_identity", &recordingDigestor{name: "identity"}, "kms_session", &recordingDigestor{name: "session"})
	if err != nil {
		t.Fatal(err)
	}
	transportFingerprint := sha256.Sum256([]byte("transport-key"))
	if err := security.ValidateOIDCTransportKeySelection("kms_oidc_transport", transportFingerprint); err != nil {
		t.Fatalf("independent reference rejected: %v", err)
	}
	for _, reference := range []string{"", "bad reference", "kms_identity", "kms_session"} {
		if err := security.ValidateOIDCTransportKeySelection(reference, transportFingerprint); CodeOf(err) != CodeConfigurationInvalid {
			t.Fatalf("reference %q accepted: %v", reference, err)
		}
	}
	for _, reused := range [][32]byte{security.IdentityDigestor().KeyMaterialFingerprint(), security.SessionDigestor().KeyMaterialFingerprint(), {}} {
		if err := security.ValidateOIDCTransportKeySelection("different_alias", reused); CodeOf(err) != CodeConfigurationInvalid {
			t.Fatalf("same key material accepted under a different reference: %v", err)
		}
	}
	if err := (Context{}).ValidateOIDCTransportKeySelection("kms_oidc_transport", transportFingerprint); CodeOf(err) != CodeConfigurationInvalid {
		t.Fatalf("zero context accepted: %v", err)
	}
}

func TestStaticAndHTTPResolversNeverSelectTenantFromRequestData(t *testing.T) {
	identityDigestor := &recordingDigestor{name: "identity"}
	sessionDigestor := &recordingDigestor{name: "session"}
	security, err := NewContext("org_alpha", "idp_primary", "https://workspace.example", "key_identity", identityDigestor, "key_session", sessionDigestor)
	if err != nil {
		t.Fatal(err)
	}
	static, err := NewStaticResolver(security)
	if err != nil {
		t.Fatal(err)
	}
	httpResolver, err := NewHTTPAuthResolver(static)
	if err != nil {
		t.Fatal(err)
	}

	for _, clientControlled := range []string{"evil.example", "org_other", "Forwarded: host=evil.example"} {
		ctx := context.WithValue(context.Background(), clientValueKey{}, clientControlled)
		resolved, err := httpResolver.Resolve(ctx)
		if err != nil || resolved.OrganizationID != "org_alpha" || resolved.Origin != "https://workspace.example" || resolved.Digestor == nil {
			t.Fatalf("client value %q changed trusted context: %#v err=%v", clientControlled, resolved, err)
		}
		if _, err := resolved.Digestor.Digest("session_token", "opaque"); err != nil {
			t.Fatal(err)
		}
	}
	if identityDigestor.calls != 0 {
		t.Fatal("HTTP projection touched identity digestor")
	}
	if _, err := httpResolver.Resolve(nil); CodeOf(err) != CodeResolutionFailed {
		t.Fatalf("nil context error=%v", err)
	}
}

func TestErrorsAreContentFreeAndHaveNoUnwrapChain(t *testing.T) {
	_, err := NewStaticResolver(Context{})
	if err == nil || err.Error() != string(CodeConfigurationInvalid) {
		t.Fatalf("error=%v", err)
	}
	if _, ok := err.(interface{ Unwrap() error }); ok {
		t.Fatal("tenant security error must not retain a cause")
	}
}

type clientValueKey struct{}

type recordingDigestor struct {
	name   string
	calls  int
	secret string
}

func (digestor *recordingDigestor) Digest(purpose, raw string) (identity.KeyedDigest, error) {
	digestor.calls++
	hash := sha256.Sum256([]byte(digestor.name + "\x00" + purpose + "\x00" + raw))
	return identity.NewKeyedDigest("hmac-sha256:k1:" + fmt.Sprintf("%x", hash[:]))
}

func (digestor *recordingDigestor) KeyMaterialFingerprint() [32]byte {
	return sha256.Sum256([]byte(digestor.name + "\x00" + digestor.secret))
}
