//go:build linux

package secretmount

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"knowvault.local/verified-workspace/internal/identity"
	"knowvault.local/verified-workspace/internal/platform/oidcweb"
)

func TestLoadMountedPreloadsExactMaterialAndResolvesTypedClientSecret(t *testing.T) {
	fixture := newProviderFixture(t)
	provider, err := loadProviderFixture(fixture)
	if err != nil {
		t.Fatal(err)
	}
	databaseURL, err := provider.DatabaseURL()
	if err != nil || databaseURL != fixture.databaseURL {
		t.Fatalf("database URL=%q err=%v", databaseURL, err)
	}
	identityKey, err := provider.IdentityKey()
	if err != nil || identityKey.Reference() != fixture.configuration.IdentityHMAC.Reference || identityKey.Version() != fixture.configuration.IdentityHMAC.Version || !bytes.Equal(identityKey.Bytes(), fixture.identityKey) {
		t.Fatalf("identity key=%#v err=%v", identityKey, err)
	}
	copyBytes := identityKey.Bytes()
	copyBytes[0] ^= 0xff
	if bytes.Equal(copyBytes, identityKey.Bytes()) {
		t.Fatal("identity key bytes were returned by reference")
	}
	sessionKey, err := provider.SessionKey()
	if err != nil || sessionKey.Reference() != fixture.configuration.SessionHMAC.Reference || sessionKey.Version() != fixture.configuration.SessionHMAC.Version || !bytes.Equal(sessionKey.Bytes(), fixture.sessionKey) {
		t.Fatalf("session key=%#v err=%v", sessionKey, err)
	}
	sourceDigestKey, err := provider.SourceDigestKey()
	if err != nil || sourceDigestKey.Reference() != fixture.configuration.SourceDigestHMAC.Reference || sourceDigestKey.Version() != fixture.configuration.SourceDigestHMAC.Version || !bytes.Equal(sourceDigestKey.Bytes(), fixture.sourceDigestKey) {
		t.Fatalf("source digest key=%#v err=%v", sourceDigestKey, err)
	}
	transportKey, err := provider.OIDCTransportKey()
	if err != nil || transportKey.Reference() != fixture.configuration.OIDCTransportAEAD.Reference || transportKey.KeyID() != fixture.configuration.OIDCTransportAEAD.KeyID || !bytes.Equal(transportKey.Bytes(), fixture.transportKey) {
		t.Fatalf("transport key=%#v err=%v", transportKey, err)
	}
	artifactWrapKey, err := provider.ArtifactWrapKey()
	if err != nil || artifactWrapKey.Reference() != fixture.configuration.ArtifactWrapKEK.Reference || artifactWrapKey.Version() != fixture.configuration.ArtifactWrapKEK.Version || !bytes.Equal(artifactWrapKey.Bytes(), fixture.artifactWrapKey) {
		t.Fatalf("artifact wrap key=%#v err=%v", artifactWrapKey, err)
	}
	wrapCopy := artifactWrapKey.Bytes()
	wrapCopy[0] ^= 0xff
	if bytes.Equal(wrapCopy, artifactWrapKey.Bytes()) {
		t.Fatal("artifact wrap key bytes were returned by reference")
	}
	secret, err := provider.Resolve(context.Background(), fixture.request)
	if err != nil || secret != fixture.clientSecret {
		t.Fatalf("secret=%q err=%v", secret, err)
	}
}

func TestLoadMountedAppliesStrictLoadToExplicitRoot(t *testing.T) {
	fixture := newProviderFixture(t)
	organizationID := identity.OrganizationID(fixture.configuration.OrganizationID)
	providerID := identity.ProviderID(fixture.configuration.ProviderID)
	provider, err := LoadMounted(fixture.root, organizationID, providerID)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	databaseURL, err := provider.DatabaseURL()
	if err != nil || databaseURL != fixture.databaseURL {
		t.Fatalf("database URL=%q err=%v", databaseURL, err)
	}
	// The explicit-root variant never widens the tenant binding: a mismatched
	// tenant or provider must be rejected by the same closed validation.
	if wrongTenant, loadErr := LoadMounted(fixture.root, identity.OrganizationID("other_org"), providerID); loadErr == nil {
		wrongTenant.Close()
		t.Fatal("LoadMounted accepted a tenant the manifest does not bind")
	}
	if wrongProvider, loadErr := LoadMounted(fixture.root, organizationID, identity.ProviderID("other_provider")); loadErr == nil {
		wrongProvider.Close()
		t.Fatal("LoadMounted accepted a provider the manifest does not bind")
	}
	// A root without a manifest stays an unavailable mount, not a fallback.
	if missingRoot, loadErr := LoadMounted(filepath.Join(fixture.root, "absent"), organizationID, providerID); loadErr == nil {
		missingRoot.Close()
		t.Fatal("LoadMounted accepted a root without a manifest")
	}
}

func TestPurposeTypedCapabilitiesOwnClearableCopiesWithoutClosingProvider(t *testing.T) {
	fixture := newProviderFixture(t)
	provider, err := loadProviderFixture(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()

	identity, err := provider.IdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	session, err := provider.SessionKey()
	if err != nil {
		t.Fatal(err)
	}
	sourceDigest, err := provider.SourceDigestKey()
	if err != nil {
		t.Fatal(err)
	}
	transport, err := provider.OIDCTransportKey()
	if err != nil {
		t.Fatal(err)
	}
	artifactWrap, err := provider.ArtifactWrapKey()
	if err != nil {
		t.Fatal(err)
	}

	// These function signatures are deliberately purpose-specific. Passing
	// session, transport or artifact-wrap to identitySink (or converting their
	// private shapes) does not compile.
	identitySink := func(IdentityKey) {}
	sessionSink := func(SessionKey) {}
	sourceDigestSink := func(SourceDigestKey) {}
	transportSink := func(OIDCTransportKey) {}
	artifactWrapSink := func(ArtifactWrapKey) {}
	identitySink(identity)
	sessionSink(session)
	sourceDigestSink(sourceDigest)
	transportSink(transport)
	artifactWrapSink(artifactWrap)

	returnedBytes := identity.Bytes()
	clear(returnedBytes)
	if !bytes.Equal(identity.Bytes(), fixture.identityKey) {
		t.Fatal("clearing returned Bytes mutated capability")
	}
	identityCopy := identity
	identityCopy.Clear()
	if identity.Reference() != "" || identity.Version() != 0 || identity.Bytes() != nil {
		t.Fatal("identity capability copy did not share Clear lifecycle")
	}
	sessionCopy := session
	sessionCopy.Clear()
	if session.Reference() != "" || session.Version() != 0 || session.Bytes() != nil {
		t.Fatal("session capability copy did not share Clear lifecycle")
	}
	sourceDigestCopy := sourceDigest
	sourceDigestCopy.Clear()
	if sourceDigest.Reference() != "" || sourceDigest.Version() != 0 || sourceDigest.Bytes() != nil {
		t.Fatal("source digest capability copy did not share Clear lifecycle")
	}
	transportCopy := transport
	transportCopy.Clear()
	if transport.Reference() != "" || transport.KeyID() != "" || transport.Bytes() != nil {
		t.Fatal("transport capability copy did not share Clear lifecycle")
	}
	artifactWrapCopy := artifactWrap
	artifactWrapCopy.Clear()
	if artifactWrap.Reference() != "" || artifactWrap.Version() != 0 || artifactWrap.Bytes() != nil {
		t.Fatal("artifact wrap capability copy did not share Clear lifecycle")
	}

	freshIdentity, err := provider.IdentityKey()
	if err != nil || !bytes.Equal(freshIdentity.Bytes(), fixture.identityKey) {
		t.Fatalf("provider-owned identity changed after local Clear: key=%#v err=%v", freshIdentity, err)
	}
	freshIdentity.Clear()
	for _, formatted := range []string{
		fmt.Sprint(identity), fmt.Sprintf("%#v", &identity), fmt.Sprint(session), fmt.Sprintf("%#v", &session),
		fmt.Sprint(sourceDigest), fmt.Sprintf("%#v", &sourceDigest),
		fmt.Sprint(transport), fmt.Sprintf("%#v", &transport), fmt.Sprint(artifactWrap), fmt.Sprintf("%#v", &artifactWrap),
	} {
		if !strings.Contains(formatted, "REDACTED") || strings.Contains(formatted, fixture.configuration.IdentityHMAC.Reference) || strings.Contains(formatted, string(fixture.identityKey)) {
			t.Fatalf("typed capability formatting leaked material: %q", formatted)
		}
	}
}

func TestCapabilityCopiesRaceSafelyWithClear(t *testing.T) {
	fixture := newProviderFixture(t)
	provider, err := loadProviderFixture(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	key, err := provider.IdentityKey()
	if err != nil {
		t.Fatal(err)
	}

	var workers sync.WaitGroup
	for index := 0; index < 16; index++ {
		copyOfKey := key
		workers.Add(1)
		go func() {
			defer workers.Done()
			for iteration := 0; iteration < 200; iteration++ {
				_ = copyOfKey.Reference()
				_ = copyOfKey.Version()
				material := copyOfKey.Bytes()
				clear(material)
			}
		}()
	}
	copyOfKey := key
	workers.Add(1)
	go func() {
		defer workers.Done()
		copyOfKey.Clear()
	}()
	workers.Wait()
	if key.Reference() != "" || key.Bytes() != nil {
		t.Fatal("cleared capability remained available")
	}
}

func TestLoadMountedRejectsStrictManifestFormsAndTraversal(t *testing.T) {
	for name, mutate := range map[string]func(*providerFixture){
		"unknown member": func(fixture *providerFixture) {
			writeProviderFile(t, fixture.root, manifestFilename, append(bytes.TrimSuffix(fixture.manifestRaw, []byte("}")), []byte(`,"unknown":true}`)...))
		},
		"duplicate member": func(fixture *providerFixture) {
			raw := strings.Replace(string(fixture.manifestRaw), `"database_url_file":"db_url",`, `"database_url_file":"db_url","database_url_file":"db_url",`, 1)
			writeProviderFile(t, fixture.root, manifestFilename, []byte(raw))
		},
		"trailing JSON": func(fixture *providerFixture) {
			writeProviderFile(t, fixture.root, manifestFilename, append(append([]byte(nil), fixture.manifestRaw...), []byte(" trailing")...))
		},
		"traversal filename": func(fixture *providerFixture) {
			fixture.configuration.IdentityHMAC.Filename = "../identity_key"
			writeProviderManifest(t, fixture)
		},
		"wrong schema": func(fixture *providerFixture) {
			fixture.configuration.Schema = "knowvault-secret-manifest-v2"
			writeProviderManifest(t, fixture)
		},
		"cross tenant client": func(fixture *providerFixture) {
			fixture.configuration.OIDCClients[0].OrganizationID = "org_other"
			writeProviderManifest(t, fixture)
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newProviderFixture(t)
			mutate(fixture)
			if provider, err := loadProviderFixture(fixture); provider != nil || CodeOf(err) != CodeManifestInvalid {
				t.Fatalf("provider=%#v err=%v", provider, err)
			}
		})
	}
}

func TestLoadMountedRejectsManifestOutsideExpectedTenantScope(t *testing.T) {
	fixture := newProviderFixture(t)
	if provider, err := loadMountedForTenant(fixture.root, "org_other", "provider_001"); provider != nil || CodeOf(err) != CodeManifestInvalid {
		t.Fatalf("cross-tenant provider=%#v err=%v", provider, err)
	}
	if provider, err := loadMountedForTenant(fixture.root, "org_001", "provider_other"); provider != nil || CodeOf(err) != CodeManifestInvalid {
		t.Fatalf("cross-provider provider=%#v err=%v", provider, err)
	}
}

func TestLoadMountedRejectsUnsafeDatabaseModesAndKeyMaterial(t *testing.T) {
	for name, mutate := range map[string]func(*providerFixture){
		"sslmode disable": func(fixture *providerFixture) {
			writeProviderFile(t, fixture.root, fixture.configuration.DatabaseURLFile, []byte("postgres://db.example/knowvault?sslmode=disable"))
		},
		"sslmode prefer": func(fixture *providerFixture) {
			writeProviderFile(t, fixture.root, fixture.configuration.DatabaseURLFile, []byte("postgres://db.example/knowvault?sslmode=prefer"))
		},
		"sslmode missing": func(fixture *providerFixture) {
			writeProviderFile(t, fixture.root, fixture.configuration.DatabaseURLFile, []byte("postgres://db.example/knowvault"))
		},
		"arbitrary service file": func(fixture *providerFixture) {
			writeProviderFile(t, fixture.root, fixture.configuration.DatabaseURLFile, []byte("postgres://user:password@db.example:5432/knowvault?sslmode=verify-full&servicefile=/tmp/evil"))
		},
		"multiple host fallback": func(fixture *providerFixture) {
			writeProviderFile(t, fixture.root, fixture.configuration.DatabaseURLFile, []byte("postgres://user:password@db.example:5432,other.example:5432/knowvault?sslmode=verify-full"))
		},
		"padded key encoding": func(fixture *providerFixture) {
			writeProviderFile(t, fixture.root, fixture.configuration.IdentityHMAC.Filename, []byte(base64.StdEncoding.EncodeToString(fixture.identityKey)))
		},
		"noncanonical trailing key bits": func(fixture *providerFixture) {
			encoded := []byte(base64.RawURLEncoding.EncodeToString(fixture.identityKey))
			alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
			index := strings.IndexByte(alphabet, encoded[len(encoded)-1])
			encoded[len(encoded)-1] = alphabet[index|1]
			writeProviderFile(t, fixture.root, fixture.configuration.IdentityHMAC.Filename, encoded)
		},
		"zero key material": func(fixture *providerFixture) {
			writeProviderFile(t, fixture.root, fixture.configuration.IdentityHMAC.Filename, []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
		},
		"duplicate key reference": func(fixture *providerFixture) {
			fixture.configuration.SessionHMAC.Reference = fixture.configuration.IdentityHMAC.Reference
			writeProviderManifest(t, fixture)
		},
		"duplicate key material": func(fixture *providerFixture) {
			writeProviderFile(t, fixture.root, fixture.configuration.SessionHMAC.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.identityKey)))
		},
		"duplicate source digest reference": func(fixture *providerFixture) {
			fixture.configuration.SourceDigestHMAC.Reference = fixture.configuration.IdentityHMAC.Reference
			writeProviderManifest(t, fixture)
		},
		"duplicate source digest material": func(fixture *providerFixture) {
			writeProviderFile(t, fixture.root, fixture.configuration.SourceDigestHMAC.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.identityKey)))
		},
		"duplicate artifact wrap reference": func(fixture *providerFixture) {
			fixture.configuration.ArtifactWrapKEK.Reference = fixture.configuration.IdentityHMAC.Reference
			writeProviderManifest(t, fixture)
		},
		"duplicate artifact wrap material": func(fixture *providerFixture) {
			writeProviderFile(t, fixture.root, fixture.configuration.ArtifactWrapKEK.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.identityKey)))
		},
		"zero artifact wrap material": func(fixture *providerFixture) {
			writeProviderFile(t, fixture.root, fixture.configuration.ArtifactWrapKEK.Filename, []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newProviderFixture(t)
			mutate(fixture)
			if provider, err := loadProviderFixture(fixture); provider != nil || CodeOf(err) != CodeMaterialInvalid {
				t.Fatalf("provider=%#v err=%v", provider, err)
			}
		})
	}
}

func TestProviderRejectsEveryClientSecretTupleMismatch(t *testing.T) {
	fixture := newProviderFixture(t)
	provider, err := loadProviderFixture(fixture)
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*oidcweb.ClientSecretRequest){
		"organization": func(request *oidcweb.ClientSecretRequest) { request.OrganizationID = "org_other" },
		"provider":     func(request *oidcweb.ClientSecretRequest) { request.ProviderID = "provider_other" },
		"revision":     func(request *oidcweb.ClientSecretRequest) { request.ProviderRevision++ },
		"reference":    func(request *oidcweb.ClientSecretRequest) { request.Reference = "client_ref_other" },
	} {
		t.Run(name, func(t *testing.T) {
			request := fixture.request
			mutate(&request)
			if secret, err := provider.Resolve(context.Background(), request); secret != "" || CodeOf(err) != CodeLookupDenied {
				t.Fatalf("secret=%q err=%v", secret, err)
			}
			if err := provider.ValidateClientBinding(context.Background(), request); CodeOf(err) != CodeLookupDenied {
				t.Fatalf("validation err=%v", err)
			}
		})
	}
	if err := provider.ValidateClientBinding(context.Background(), fixture.request); err != nil {
		t.Fatalf("valid binding: %v", err)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := provider.ValidateClientBinding(cancelled, fixture.request); CodeOf(err) != CodeLookupDenied {
		t.Fatalf("cancelled validation err=%v", err)
	}
}

func TestProviderCloseZeroizesMaterialAndFailsClosed(t *testing.T) {
	fixture := newProviderFixture(t)
	provider, err := loadProviderFixture(fixture)
	if err != nil {
		t.Fatal(err)
	}
	state := provider.state
	databaseBacking := state.databaseURL
	clientKey := clientKey{string(fixture.request.OrganizationID), string(fixture.request.ProviderID), fixture.request.ProviderRevision, fixture.request.Reference}
	clientBacking := state.clients[clientKey]
	providerCopy := *provider
	for _, formatted := range []string{fmt.Sprint(provider), fmt.Sprintf("%#v", provider), fmt.Sprint(providerCopy), fmt.Sprintf("%#v", providerCopy)} {
		if !strings.Contains(formatted, "REDACTED") || strings.Contains(formatted, fixture.clientSecret) || strings.Contains(formatted, fixture.databaseURL) {
			t.Fatalf("provider formatting leaked material: %q", formatted)
		}
	}
	if err := providerCopy.Close(); err != nil {
		t.Fatal(err)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if !allZero(databaseBacking) || !allZero(clientBacking) || !allZero(state.identity.value[:]) || !allZero(state.session.value[:]) || !allZero(state.sourceDigest.value[:]) || !allZero(state.transport.value[:]) || !allZero(state.artifactWrap.value[:]) {
		t.Fatal("provider retained secret bytes after close")
	}
	if state.databaseURL != nil || state.clients != nil || !state.closed {
		t.Fatalf("closed state database=%#v clients=%#v closed=%v", state.databaseURL, state.clients, state.closed)
	}
	if value, err := provider.DatabaseURL(); value != "" || CodeOf(err) != CodeUnavailable {
		t.Fatalf("database after close=%q err=%v", value, err)
	}
	if value, err := provider.IdentityKey(); value.identity != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("identity after close=%#v err=%v", value, err)
	}
	if value, err := provider.SessionKey(); value.session != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("session after close=%#v err=%v", value, err)
	}
	if value, err := provider.SourceDigestKey(); value.sourceDigest != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("source digest after close=%#v err=%v", value, err)
	}
	if value, err := provider.OIDCTransportKey(); value.transport != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("transport after close=%#v err=%v", value, err)
	}
	if value, err := provider.ArtifactWrapKey(); value.artifactWrap != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("artifact wrap after close=%#v err=%v", value, err)
	}
	if secret, err := provider.Resolve(context.Background(), fixture.request); secret != "" || CodeOf(err) != CodeLookupDenied {
		t.Fatalf("resolve after close=%q err=%v", secret, err)
	}
	if err := provider.ValidateClientBinding(context.Background(), fixture.request); CodeOf(err) != CodeLookupDenied {
		t.Fatalf("validate after close err=%v", err)
	}
	for _, formatted := range []string{fmt.Sprint(provider), fmt.Sprintf("%#v", provider)} {
		if !strings.Contains(formatted, "REDACTED") || strings.Contains(formatted, fixture.clientSecret) || strings.Contains(formatted, fixture.databaseURL) {
			t.Fatalf("closed provider formatting leaked material: %q", formatted)
		}
	}
}

func TestZeroProviderFailsClosedAndFormatsRedacted(t *testing.T) {
	var provider Provider
	if value, err := provider.DatabaseURL(); value != "" || CodeOf(err) != CodeUnavailable {
		t.Fatalf("zero database=%q err=%v", value, err)
	}
	if value, err := provider.IdentityKey(); value.identity != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("zero identity=%#v err=%v", value, err)
	}
	if value, err := provider.SessionKey(); value.session != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("zero session=%#v err=%v", value, err)
	}
	if value, err := provider.SourceDigestKey(); value.sourceDigest != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("zero source digest=%#v err=%v", value, err)
	}
	if value, err := provider.OIDCTransportKey(); value.transport != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("zero transport=%#v err=%v", value, err)
	}
	if value, err := provider.ArtifactWrapKey(); value.artifactWrap != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("zero artifact wrap=%#v err=%v", value, err)
	}
	request := oidcweb.ClientSecretRequest{OrganizationID: "org_001", ProviderID: "provider_001", ProviderRevision: 1, Reference: "client_ref"}
	if secret, err := provider.Resolve(context.Background(), request); secret != "" || CodeOf(err) != CodeLookupDenied {
		t.Fatalf("zero resolve=%q err=%v", secret, err)
	}
	if err := provider.ValidateClientBinding(context.Background(), request); CodeOf(err) != CodeLookupDenied {
		t.Fatalf("zero validate err=%v", err)
	}
	if err := provider.Close(); err != nil {
		t.Fatalf("zero close err=%v", err)
	}
	for _, formatted := range []string{fmt.Sprint(provider), fmt.Sprintf("%#v", provider), fmt.Sprint(&provider), fmt.Sprintf("%#v", &provider)} {
		if formatted != "secretmount.Provider{[REDACTED]}" {
			t.Fatalf("zero formatting=%q", formatted)
		}
	}
}

func TestProviderConcurrentCloseAndAccessIsRaceSafe(t *testing.T) {
	fixture := newProviderFixture(t)
	provider, err := loadProviderFixture(fixture)
	if err != nil {
		t.Fatal(err)
	}
	errCh := make(chan error, 32768)
	var workers sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		handle := *provider
		workers.Add(1)
		go func(providerCopy Provider) {
			defer workers.Done()
			for iteration := 0; iteration < 200; iteration++ {
				if value, accessErr := providerCopy.DatabaseURL(); accessErr == nil {
					if value != fixture.databaseURL {
						errCh <- fmt.Errorf("unexpected database URL %q", value)
					}
				} else if CodeOf(accessErr) != CodeUnavailable {
					errCh <- fmt.Errorf("database error: %w", accessErr)
				}
				if secret, accessErr := providerCopy.Resolve(context.Background(), fixture.request); accessErr == nil {
					if secret != fixture.clientSecret {
						errCh <- fmt.Errorf("unexpected client secret")
					}
				} else if CodeOf(accessErr) != CodeLookupDenied {
					errCh <- fmt.Errorf("resolve error: %w", accessErr)
				}
				if accessErr := providerCopy.ValidateClientBinding(context.Background(), fixture.request); accessErr != nil && CodeOf(accessErr) != CodeLookupDenied {
					errCh <- fmt.Errorf("validate error: %w", accessErr)
				}
				if key, accessErr := providerCopy.IdentityKey(); accessErr == nil {
					key.Clear()
				} else if CodeOf(accessErr) != CodeUnavailable {
					errCh <- fmt.Errorf("identity accessor error: %w", accessErr)
				}
				if key, accessErr := providerCopy.SessionKey(); accessErr == nil {
					key.Clear()
				} else if CodeOf(accessErr) != CodeUnavailable {
					errCh <- fmt.Errorf("session accessor error: %w", accessErr)
				}
				if key, accessErr := providerCopy.SourceDigestKey(); accessErr == nil {
					key.Clear()
				} else if CodeOf(accessErr) != CodeUnavailable {
					errCh <- fmt.Errorf("source digest accessor error: %w", accessErr)
				}
				if key, accessErr := providerCopy.OIDCTransportKey(); accessErr == nil {
					key.Clear()
				} else if CodeOf(accessErr) != CodeUnavailable {
					errCh <- fmt.Errorf("transport accessor error: %w", accessErr)
				}
				if key, accessErr := providerCopy.ArtifactWrapKey(); accessErr == nil {
					key.Clear()
				} else if CodeOf(accessErr) != CodeUnavailable {
					errCh <- fmt.Errorf("artifact wrap accessor error: %w", accessErr)
				}
			}
		}(handle)
	}
	for closer := 0; closer < 8; closer++ {
		handle := *provider
		workers.Add(1)
		go func(providerCopy Provider) {
			defer workers.Done()
			if closeErr := providerCopy.Close(); closeErr != nil {
				errCh <- closeErr
			}
		}(handle)
	}
	workers.Wait()
	close(errCh)
	for workerErr := range errCh {
		t.Error(workerErr)
	}
}

func allZero(value []byte) bool {
	for _, octet := range value {
		if octet != 0 {
			return false
		}
	}
	return true
}

func TestProviderNeverRereadsMountedSourceFilesAndRedactsFormatting(t *testing.T) {
	fixture := newProviderFixture(t)
	provider, err := loadProviderFixture(fixture)
	if err != nil {
		t.Fatal(err)
	}
	writeProviderFile(t, fixture.root, fixture.configuration.OIDCClients[0].Filename, []byte("replacement-client-secret"))
	writeProviderFile(t, fixture.root, fixture.configuration.DatabaseURLFile, []byte("postgres://replacement.example/db?sslmode=verify-full"))
	if secret, err := provider.Resolve(context.Background(), fixture.request); err != nil || secret != fixture.clientSecret {
		t.Fatalf("preloaded secret=%q err=%v", secret, err)
	}
	if databaseURL, err := provider.DatabaseURL(); err != nil || databaseURL != fixture.databaseURL {
		t.Fatalf("preloaded database URL=%q err=%v", databaseURL, err)
	}
	identityKey, err := provider.IdentityKey()
	if err != nil {
		t.Fatal(err)
	}
	wrongRequest := fixture.request
	wrongRequest.Reference = "client_ref_other"
	_, lookupErr := provider.Resolve(context.Background(), wrongRequest)
	for _, formatted := range []string{
		fmt.Sprint(provider), fmt.Sprintf("%#v", provider), fmt.Sprint(identityKey), fmt.Sprintf("%#v", identityKey), fmt.Sprint(lookupErr), fmt.Sprintf("%#v", lookupErr),
	} {
		if strings.Contains(formatted, fixture.root) || strings.Contains(formatted, fixture.databaseURL) || strings.Contains(formatted, fixture.clientSecret) ||
			strings.Contains(formatted, fixture.configuration.IdentityHMAC.Reference) || strings.Contains(formatted, string(fixture.identityKey)) {
			t.Fatalf("formatting leaked mounted material: %q", formatted)
		}
	}
	for _, formatted := range []string{fmt.Sprint(provider), fmt.Sprintf("%#v", identityKey)} {
		if !strings.Contains(formatted, "REDACTED") {
			t.Fatalf("formatting was not redacted: %q", formatted)
		}
	}
}

func TestLoadMountedPreviousArtifactPairExposesPreviousAndZeroizesOnClose(t *testing.T) {
	fixture := newProviderFixture(t)
	withPreviousPair(t, fixture)
	provider, err := loadProviderFixture(fixture)
	if err != nil {
		t.Fatal(err)
	}
	state := provider.state
	if state.artifactWrapPrev == nil {
		t.Fatal("previous pair not mounted")
	}
	prevBacking := state.artifactWrapPrev.value[:]
	previous, found, err := provider.ArtifactWrapKeyPrevious()
	if err != nil || !found {
		t.Fatalf("previous key found=%v err=%v", found, err)
	}
	if previous.Reference() != fixture.configuration.ArtifactWrapKEKPrev.Reference ||
		previous.Version() != fixture.configuration.ArtifactWrapKEKPrev.Version ||
		!bytes.Equal(previous.Bytes(), fixture.artifactWrapPrevKey) {
		t.Fatalf("previous key=%#v", previous)
	}
	copyBytes := previous.Bytes()
	copyBytes[0] ^= 0xff
	if bytes.Equal(copyBytes, previous.Bytes()) {
		t.Fatal("previous key bytes were returned by reference")
	}
	active, err := provider.ArtifactWrapKey()
	if err != nil || active.Reference() != fixture.configuration.ArtifactWrapKEK.Reference ||
		active.Version() != fixture.configuration.ArtifactWrapKEK.Version {
		t.Fatalf("active key=%#v err=%v", active, err)
	}
	active.Clear()
	if err := provider.Close(); err != nil {
		t.Fatal(err)
	}
	if !allZero(prevBacking) {
		t.Fatal("previous pair retained bytes after close")
	}
	if state.artifactWrapPrev != nil {
		t.Fatal("previous pair state retained after close")
	}
	if value, found, err := provider.ArtifactWrapKeyPrevious(); found || value.artifactWrap != nil || CodeOf(err) != CodeUnavailable {
		t.Fatalf("previous after close found=%v value=%#v err=%v", found, value, err)
	}
}

func TestLoadMountedWithoutPreviousPairReportsAbsent(t *testing.T) {
	fixture := newProviderFixture(t)
	provider, err := loadProviderFixture(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	if value, found, err := provider.ArtifactWrapKeyPrevious(); found || value.artifactWrap != nil || err != nil {
		t.Fatalf("previous without rotation found=%v value=%#v err=%v", found, value, err)
	}
}

func TestLoadMountedRejectsInvalidPreviousArtifactPair(t *testing.T) {
	for _, testCase := range []struct {
		name   string
		want   ErrorCode
		mutate func(*providerFixture)
	}{
		{
			"previous reference equals active", CodeManifestInvalid, func(fixture *providerFixture) {
				prev := versionedKeyManifest{Reference: fixture.configuration.ArtifactWrapKEK.Reference, Version: 3, Filename: "artifact_kek_prev"}
				fixture.configuration.ArtifactWrapKEKPrev = &prev
				writeProviderFile(t, fixture.root, prev.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.artifactWrapPrevKey)))
				writeProviderManifest(t, fixture)
			},
		},
		{
			"previous version equals active", CodeManifestInvalid, func(fixture *providerFixture) {
				prev := versionedKeyManifest{Reference: "artifact_kek_prev_ref", Version: fixture.configuration.ArtifactWrapKEK.Version, Filename: "artifact_kek_prev"}
				fixture.configuration.ArtifactWrapKEKPrev = &prev
				writeProviderFile(t, fixture.root, prev.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.artifactWrapPrevKey)))
				writeProviderManifest(t, fixture)
			},
		},
		{
			"previous filename equals active", CodeManifestInvalid, func(fixture *providerFixture) {
				prev := versionedKeyManifest{Reference: "artifact_kek_prev_ref", Version: 3, Filename: fixture.configuration.ArtifactWrapKEK.Filename}
				fixture.configuration.ArtifactWrapKEKPrev = &prev
				writeProviderManifest(t, fixture)
			},
		},
		{
			"previous filename equals session", CodeManifestInvalid, func(fixture *providerFixture) {
				prev := versionedKeyManifest{Reference: "artifact_kek_prev_ref", Version: 3, Filename: fixture.configuration.SessionHMAC.Filename}
				fixture.configuration.ArtifactWrapKEKPrev = &prev
				writeProviderManifest(t, fixture)
			},
		},
		{
			"previous invalid reference", CodeManifestInvalid, func(fixture *providerFixture) {
				prev := versionedKeyManifest{Reference: "artifact kek prev", Version: 3, Filename: "artifact_kek_prev"}
				fixture.configuration.ArtifactWrapKEKPrev = &prev
				writeProviderFile(t, fixture.root, prev.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.artifactWrapPrevKey)))
				writeProviderManifest(t, fixture)
			},
		},
		{
			"previous material equals active", CodeMaterialInvalid, func(fixture *providerFixture) {
				prev := versionedKeyManifest{Reference: "artifact_kek_prev_ref", Version: 3, Filename: "artifact_kek_prev"}
				fixture.configuration.ArtifactWrapKEKPrev = &prev
				writeProviderFile(t, fixture.root, prev.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.artifactWrapKey)))
				writeProviderManifest(t, fixture)
			},
		},
		{
			"previous reference equals identity", CodeMaterialInvalid, func(fixture *providerFixture) {
				prev := versionedKeyManifest{Reference: fixture.configuration.IdentityHMAC.Reference, Version: 3, Filename: "artifact_kek_prev"}
				fixture.configuration.ArtifactWrapKEKPrev = &prev
				writeProviderFile(t, fixture.root, prev.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.artifactWrapPrevKey)))
				writeProviderManifest(t, fixture)
			},
		},
		{
			"previous zero material", CodeMaterialInvalid, func(fixture *providerFixture) {
				prev := versionedKeyManifest{Reference: "artifact_kek_prev_ref", Version: 3, Filename: "artifact_kek_prev"}
				fixture.configuration.ArtifactWrapKEKPrev = &prev
				writeProviderFile(t, fixture.root, prev.Filename, []byte(base64.RawURLEncoding.EncodeToString(make([]byte, 32))))
				writeProviderManifest(t, fixture)
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := newProviderFixture(t)
			testCase.mutate(fixture)
			if provider, err := loadProviderFixture(fixture); provider != nil || CodeOf(err) != testCase.want {
				t.Fatalf("provider=%#v err=%v want=%v", provider, err, testCase.want)
			}
		})
	}
}

type providerFixture struct {
	root                string
	configuration       manifest
	manifestRaw         []byte
	databaseURL         string
	identityKey         []byte
	sessionKey          []byte
	transportKey        []byte
	sourceDigestKey     []byte
	artifactWrapKey     []byte
	clientSecret        string
	request             oidcweb.ClientSecretRequest
	artifactWrapPrevKey []byte
}

func newProviderFixture(t *testing.T) *providerFixture {
	t.Helper()
	fixture := &providerFixture{
		root:                newMountedRootFixture(t),
		databaseURL:         "postgres://user:password@db.example:5432/knowvault?sslmode=verify-full",
		identityKey:         bytes.Repeat([]byte{0x11}, 32),
		sessionKey:          bytes.Repeat([]byte{0x22}, 32),
		sourceDigestKey:     bytes.Repeat([]byte{0x55}, 32),
		transportKey:        bytes.Repeat([]byte{0x33}, 32),
		artifactWrapKey:     bytes.Repeat([]byte{0x44}, 32),
		artifactWrapPrevKey: bytes.Repeat([]byte{0x66}, 32),
		clientSecret:        "client-secret-value",
		configuration: manifest{
			Schema:            manifestSchema,
			OrganizationID:    "org_001",
			ProviderID:        "provider_001",
			DatabaseURLFile:   "db_url",
			IdentityHMAC:      versionedKeyManifest{Reference: "identity_ref", Version: 7, Filename: "identity_key"},
			SessionHMAC:       versionedKeyManifest{Reference: "session_ref", Version: 9, Filename: "session_key"},
			SourceDigestHMAC:  versionedKeyManifest{Reference: "source_digest_ref", Version: 11, Filename: "source_digest_key"},
			OIDCTransportAEAD: transportKeyManifest{Reference: "transport_ref", KeyID: "transport_kid", Filename: "transport_key"},
			ArtifactWrapKEK:   versionedKeyManifest{Reference: "artifact_kek_ref", Version: 4, Filename: "artifact_kek"},
			OIDCClients:       []clientSecretManifest{{OrganizationID: "org_001", ProviderID: "provider_001", ProviderRevision: 3, Reference: "client_ref", Filename: "client_secret"}},
		},
	}
	fixture.request = oidcweb.ClientSecretRequest{OrganizationID: identity.OrganizationID("org_001"), ProviderID: identity.ProviderID("provider_001"), ProviderRevision: 3, Reference: "client_ref"}
	writeProviderFile(t, fixture.root, fixture.configuration.DatabaseURLFile, []byte(fixture.databaseURL))
	writeProviderFile(t, fixture.root, fixture.configuration.IdentityHMAC.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.identityKey)))
	writeProviderFile(t, fixture.root, fixture.configuration.SessionHMAC.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.sessionKey)))
	writeProviderFile(t, fixture.root, fixture.configuration.SourceDigestHMAC.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.sourceDigestKey)))
	writeProviderFile(t, fixture.root, fixture.configuration.OIDCTransportAEAD.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.transportKey)))
	writeProviderFile(t, fixture.root, fixture.configuration.ArtifactWrapKEK.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.artifactWrapKey)))
	writeProviderFile(t, fixture.root, fixture.configuration.OIDCClients[0].Filename, []byte(fixture.clientSecret))
	writeProviderManifest(t, fixture)
	return fixture
}

func loadProviderFixture(fixture *providerFixture) (*Provider, error) {
	return loadMountedForTenant(fixture.root, identity.OrganizationID(fixture.configuration.OrganizationID), identity.ProviderID(fixture.configuration.ProviderID))
}

// withPreviousPair mounts an in-flight rotation window (ADR-0070 §3) on top of
// the base fixture: a distinct previous KEK pair with its own file, reference
// and version.
func withPreviousPair(t *testing.T, fixture *providerFixture) {
	t.Helper()
	prev := versionedKeyManifest{Reference: "artifact_kek_prev_ref", Version: 3, Filename: "artifact_kek_prev"}
	fixture.configuration.ArtifactWrapKEKPrev = &prev
	writeProviderFile(t, fixture.root, prev.Filename, []byte(base64.RawURLEncoding.EncodeToString(fixture.artifactWrapPrevKey)))
	writeProviderManifest(t, fixture)
}

func writeProviderManifest(t *testing.T, fixture *providerFixture) {
	t.Helper()
	raw, err := json.Marshal(fixture.configuration)
	if err != nil {
		t.Fatal(err)
	}
	fixture.manifestRaw = raw
	writeProviderFile(t, fixture.root, manifestFilename, raw)
}

func writeProviderFile(t *testing.T, root, filename string, contents []byte) {
	t.Helper()
	path := filepath.Join(root, filename)
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 0, RuntimeGID); err != nil {
		t.Fatal(err)
	}
}
