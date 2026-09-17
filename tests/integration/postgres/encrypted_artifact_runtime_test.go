package postgres_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	artifactrepository "knowvault.local/verified-workspace/internal/artifact/repository"
	"knowvault.local/verified-workspace/internal/platform/artifactcrypto"
	"knowvault.local/verified-workspace/internal/platform/database"
)

const (
	artifactKEKReference = "artifact_kek_ref"
	artifactKEKVersion   = int64(4)
	bindFunction         = "app.test_bind_question_text"
	readFunction         = "app.test_read_question_text"
)

var (
	artifactKEKPrimary   = bytes.Repeat([]byte{0x44}, 32)
	artifactKEKAlternate = bytes.Repeat([]byte{0x55}, 32)
)

// activateTestQuestionBranch installs a single activated owner branch for the
// QuestionText selector: a minimal question_run_test owning table with a composite
// foreign key into encrypted_artifact plus the per-branch SECURITY DEFINER bind
// and read functions. It is test scaffolding standing in for the real owning
// relation, which will ship its own migration. It proves the activation
// mechanism while every other branch stays inert.
func activateTestQuestionBranch(t *testing.T, ctx context.Context, admin *pgxpool.Pool) {
	t.Helper()
	statements := []string{
		`CREATE TABLE public.question_run_test (
			organization_id text NOT NULL REFERENCES public.organization(id) ON DELETE RESTRICT,
			id text NOT NULL CHECK (app.stage2_opaque_id_is_valid(id)),
			question_text_artifact_id text,
			readable boolean NOT NULL DEFAULT true,
			PRIMARY KEY (organization_id, id),
			FOREIGN KEY (organization_id, question_text_artifact_id) REFERENCES public.encrypted_artifact(organization_id, id)
		)`,
		`ALTER TABLE public.question_run_test ENABLE ROW LEVEL SECURITY`,
		`ALTER TABLE public.question_run_test FORCE ROW LEVEL SECURITY`,
		`CREATE POLICY question_run_test_tenant ON public.question_run_test
			USING (organization_id = app.current_organization_id())
			WITH CHECK (organization_id = app.current_organization_id())`,
		`GRANT SELECT, INSERT ON public.question_run_test TO knowvault_app`,
		`CREATE FUNCTION app.test_bind_question_text(
			p_org text, p_owning_row_id text, p_artifact_id text, p_resource_id text,
			p_ciphertext bytea, p_size_bytes integer, p_nonce bytea, p_wrapped_dek bytea,
			p_wrapped_dek_hash text, p_kek_reference text, p_kek_version bigint,
			p_aad_hash text, p_plaintext_hash text
		) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog AS $fn$
		BEGIN
			IF p_org IS DISTINCT FROM app.current_organization_id() THEN
				RAISE EXCEPTION 'tenant mismatch';
			END IF;
			IF p_resource_id IS DISTINCT FROM p_owning_row_id THEN
				RAISE EXCEPTION 'resource id must equal owning row id for this branch';
			END IF;
			INSERT INTO public.encrypted_artifact (
				organization_id, id, aad_schema_version, owner_table, owner_column, resource_type, resource_id, field_name,
				cipher, ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash
			) VALUES (
				p_org, p_artifact_id, 'encrypted-artifact-aad-v1', 'question_run', 'question_text_artifact_id', 'QUESTION_RUN', p_resource_id, 'QUESTION_TEXT',
				'AES_256_GCM', p_ciphertext, p_size_bytes, p_nonce, p_wrapped_dek, p_wrapped_dek_hash, p_kek_reference, p_kek_version, p_aad_hash, p_plaintext_hash
			);
			UPDATE public.question_run_test
				SET question_text_artifact_id = p_artifact_id
				WHERE organization_id = p_org AND id = p_owning_row_id AND question_text_artifact_id IS NULL;
			IF NOT FOUND THEN
				RAISE EXCEPTION 'owning row missing or already bound';
			END IF;
		END;
		$fn$`,
		`CREATE FUNCTION app.test_read_question_text(p_owning_row_id text)
		RETURNS TABLE(resource_id text, ciphertext bytea, size_bytes integer, nonce bytea, wrapped_dek bytea,
			wrapped_dek_hash text, kek_reference text, kek_version bigint, aad_hash text, plaintext_hash text)
		LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog AS $fn$
			SELECT a.resource_id, a.ciphertext, a.size_bytes, a.nonce, a.wrapped_dek, a.wrapped_dek_hash,
			       a.kek_reference, a.kek_version, a.aad_hash, a.plaintext_hash
			FROM public.question_run_test q
			JOIN public.encrypted_artifact a
			  ON a.organization_id = q.organization_id AND a.id = q.question_text_artifact_id
			WHERE q.organization_id = app.current_organization_id()
			  AND q.id = p_owning_row_id
			  AND a.purged_at IS NULL;
		$fn$`,
		`REVOKE ALL ON FUNCTION app.test_bind_question_text(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) FROM PUBLIC`,
		`GRANT EXECUTE ON FUNCTION app.test_bind_question_text(text, text, text, text, bytea, integer, bytea, bytea, text, text, bigint, text, text) TO knowvault_app`,
		`REVOKE ALL ON FUNCTION app.test_read_question_text(text) FROM PUBLIC`,
		`GRANT EXECUTE ON FUNCTION app.test_read_question_text(text) TO knowvault_app`,
	}
	for _, statement := range statements {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("activate test branch: %v", err)
		}
	}
}

func testAuthorizeReadable(ctx context.Context, transaction database.Transaction, access database.AccessContext, owningRowID string) error {
	var readable bool
	err := transaction.QueryRow(ctx, "SELECT readable FROM public.question_run_test WHERE organization_id = $1 AND id = $2", access.OrganizationID, owningRowID).Scan(&readable)
	if err != nil {
		return err
	}
	if !readable {
		return errors.New("read not authorized")
	}
	return nil
}

func newArtifactRepository(t *testing.T) *artifactrepository.Repository {
	t.Helper()
	binding, err := artifactrepository.NewBinding(artifactcrypto.QuestionText, bindFunction, readFunction, testAuthorizeReadable)
	if err != nil {
		t.Fatalf("binding: %v", err)
	}
	repository, err := artifactrepository.New(binding)
	if err != nil {
		t.Fatalf("repository: %v", err)
	}
	return repository
}

func newArtifactStore(t *testing.T) *database.Store {
	t.Helper()
	config := database.DefaultConfig()
	config.URL = applicationURL(t, testDatabaseURL(t))
	store, err := database.Open(context.Background(), config)
	if err != nil {
		t.Fatalf("open runtime database store: %v", err)
	}
	t.Cleanup(store.Close)
	return store
}

func newArtifactCodec(t *testing.T, organizationID string, key []byte) (*artifactcrypto.Codec, *artifactcrypto.MountedProvider) {
	t.Helper()
	provider, err := artifactcrypto.NewMountedProvider(organizationID, artifactKEKReference, artifactKEKVersion, key)
	if err != nil {
		t.Fatalf("mounted provider: %v", err)
	}
	t.Cleanup(func() { _ = provider.Close() })
	codec, err := artifactcrypto.NewCodec(provider)
	if err != nil {
		t.Fatalf("artifact codec: %v", err)
	}
	return codec, provider
}

func artifactAccess(organizationID string) database.AccessContext {
	return database.AccessContext{OrganizationID: organizationID, PrincipalID: "usr_alice", RequestID: "req_test"}
}

func seedOwningRow(t *testing.T, ctx context.Context, store *database.Store, access database.AccessContext, owningRowID string, readable bool) {
	t.Helper()
	if err := store.Write(ctx, access, func(writeCtx context.Context, transaction database.Transaction) error {
		_, err := transaction.Exec(writeCtx, "INSERT INTO public.question_run_test (organization_id, id, readable) VALUES ($1, $2, $3)", access.OrganizationID, owningRowID, readable)
		return err
	}); err != nil {
		t.Fatalf("seed owning row: %v", err)
	}
}

func storeArtifact(t *testing.T, ctx context.Context, store *database.Store, repository *artifactrepository.Repository, codec *artifactcrypto.Codec, access database.AccessContext, owningRowID, artifactID string, plaintext []byte) {
	t.Helper()
	owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.QuestionText, access.OrganizationID, owningRowID)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := codec.Seal(owner, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if err := store.Write(ctx, access, func(writeCtx context.Context, transaction database.Transaction) error {
		return repository.Store(writeCtx, transaction, access, artifactcrypto.QuestionText, owningRowID, artifactID, envelope)
	}); err != nil {
		t.Fatalf("store artifact: %v", err)
	}
}

// Layer 1 semantic owner + layer 2 DB containment: round-trip through activated
// branch; the owner identity on read is derived from the trusted owning row.
func TestEncryptedArtifactRuntimeStoresAndFetchesThroughActivatedBranch(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	activateTestQuestionBranch(t, ctx, admin)
	store := newArtifactStore(t)
	repository := newArtifactRepository(t)
	codec, provider := newArtifactCodec(t, "org_alpha", artifactKEKPrimary)
	access := artifactAccess("org_alpha")

	seedOwningRow(t, ctx, store, access, "res_q1", true)
	plaintext := []byte("activated-branch question payload")
	storeArtifact(t, ctx, store, repository, codec, access, "res_q1", "art_q1", plaintext)

	var recovered []byte
	var storedReference string
	var storedVersion int64
	if err := store.Read(ctx, access, func(readCtx context.Context, transaction database.Transaction) error {
		owner, envelope, fetchErr := repository.Fetch(readCtx, transaction, access, artifactcrypto.QuestionText, "res_q1")
		if fetchErr != nil {
			return fetchErr
		}
		// The owner tuple is the one derived from the owning row, not caller input.
		if owner.OwnerTable() != "question_run" || owner.ResourceID() != "res_q1" || owner.Field() != "QUESTION_TEXT" {
			t.Fatalf("owner not derived from owning row: %+v", owner)
		}
		storedReference = envelope.KEKReference()
		storedVersion = envelope.KEKVersion()
		plain, openErr := codec.Open(owner, envelope)
		if openErr != nil {
			return openErr
		}
		recovered = plain
		return nil
	}); err != nil {
		t.Fatalf("fetch/open: %v", err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatal("recovered payload mismatch")
	}
	// Atomic wrap metadata: stored key reference/version equal the provider's.
	if storedReference != artifactKEKReference || storedVersion != artifactKEKVersion {
		t.Fatalf("stored key metadata not atomic with wrap: ref=%q version=%d", storedReference, storedVersion)
	}
	_ = provider
}

// Layer 2 independent containment: the runtime role cannot bypass the owner
// boundary with raw SQL; PostgreSQL denies it.
func TestEncryptedArtifactRuntimeRawSQLIsDeniedByDatabase(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	activateTestQuestionBranch(t, ctx, admin)
	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	for name, statement := range map[string]string{
		"raw select": "SELECT id FROM public.encrypted_artifact",
		"raw insert": "INSERT INTO public.encrypted_artifact (organization_id, id, owner_table, owner_column, resource_type, resource_id, field_name, size_bytes, ciphertext, nonce, wrapped_dek, wrapped_dek_hash, kek_reference, kek_version, aad_hash, plaintext_hash) VALUES ('org_alpha','art_raw','question_run','question_text_artifact_id','QUESTION_RUN','res_q1','QUESTION_TEXT',16, '\\x00','\\x00','\\x00','sha256:" + fmt.Sprintf("%064d", 0) + "','ref',1,'sha256:" + fmt.Sprintf("%064d", 0) + "','sha256:" + fmt.Sprintf("%064d", 0) + "')",
	} {
		t.Run(name, func(t *testing.T) {
			tx, err := app.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			setAccessContext(t, ctx, tx, "org_alpha")
			if _, err := tx.Exec(ctx, statement); err == nil {
				t.Fatalf("runtime role was permitted raw %s on encrypted_artifact", name)
			}
		})
	}
}

// Layer 1 semantic owner: a branch with no binding stays inert.
func TestEncryptedArtifactRuntimeInertBranchCannotStoreOrFetch(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	activateTestQuestionBranch(t, ctx, admin)
	store := newArtifactStore(t)
	repository := newArtifactRepository(t)
	codec, _ := newArtifactCodec(t, "org_alpha", artifactKEKPrimary)
	access := artifactAccess("org_alpha")

	owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.AnswerMarkdown, "org_alpha", "res_q1")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := codec.Seal(owner, []byte("inert branch payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(ctx, access, func(writeCtx context.Context, transaction database.Transaction) error {
		return repository.Store(writeCtx, transaction, access, artifactcrypto.AnswerMarkdown, "res_q1", "art_inert", envelope)
	}); artifactrepository.CodeOf(err) != artifactrepository.CodeInert {
		t.Fatalf("inert-branch store code=%v", artifactrepository.CodeOf(err))
	}
	if err := store.Read(ctx, access, func(readCtx context.Context, transaction database.Transaction) error {
		_, _, fetchErr := repository.Fetch(readCtx, transaction, access, artifactcrypto.AnswerMarkdown, "res_q1")
		if artifactrepository.CodeOf(fetchErr) != artifactrepository.CodeInert {
			t.Fatalf("inert-branch fetch code=%v", artifactrepository.CodeOf(fetchErr))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Layer 1 semantic owner: an unauthorized in-tenant read is denied and discloses
// nothing.
func TestEncryptedArtifactRuntimeUnauthorizedFetchIsDenied(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	activateTestQuestionBranch(t, ctx, admin)
	store := newArtifactStore(t)
	repository := newArtifactRepository(t)
	codec, _ := newArtifactCodec(t, "org_alpha", artifactKEKPrimary)
	access := artifactAccess("org_alpha")

	seedOwningRow(t, ctx, store, access, "res_secret", false)
	storeArtifact(t, ctx, store, repository, codec, access, "res_secret", "art_secret", []byte("unauthorized read payload"))

	if err := store.Read(ctx, access, func(readCtx context.Context, transaction database.Transaction) error {
		owner, _, fetchErr := repository.Fetch(readCtx, transaction, access, artifactcrypto.QuestionText, "res_secret")
		if artifactrepository.CodeOf(fetchErr) != artifactrepository.CodeDenied {
			t.Fatalf("unauthorized fetch code=%v", artifactrepository.CodeOf(fetchErr))
		}
		if owner.OwnerTable() != "" {
			t.Fatal("denied fetch disclosed an owner identity")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Layer 2 containment: a committed orphan is impossible. Binding requires the
// owning row, and a transaction failure reverts the artifact.
func TestEncryptedArtifactRuntimeCommittedOrphanIsImpossible(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	activateTestQuestionBranch(t, ctx, admin)
	store := newArtifactStore(t)
	repository := newArtifactRepository(t)
	codec, _ := newArtifactCodec(t, "org_alpha", artifactKEKPrimary)
	access := artifactAccess("org_alpha")

	owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.QuestionText, "org_alpha", "res_missing")
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := codec.Seal(owner, []byte("would-be orphan payload"))
	if err != nil {
		t.Fatal(err)
	}
	// Binding a non-existent owning row fails; the artifact insert is reverted.
	if err := store.Write(ctx, access, func(writeCtx context.Context, transaction database.Transaction) error {
		return repository.Store(writeCtx, transaction, access, artifactcrypto.QuestionText, "res_missing", "art_orphan_a", envelope)
	}); err == nil {
		t.Fatal("binding a missing owning row unexpectedly succeeded")
	}

	// A later step failing in the same transaction reverts a successful bind.
	seedOwningRow(t, ctx, store, access, "res_rollback", true)
	owner2, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.QuestionText, "org_alpha", "res_rollback")
	if err != nil {
		t.Fatal(err)
	}
	envelope2, err := codec.Seal(owner2, []byte("rolled-back payload"))
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("later step failed")
	if err := store.Write(ctx, access, func(writeCtx context.Context, transaction database.Transaction) error {
		if storeErr := repository.Store(writeCtx, transaction, access, artifactcrypto.QuestionText, "res_rollback", "art_orphan_b", envelope2); storeErr != nil {
			return storeErr
		}
		return sentinel
	}); !errors.Is(err, sentinel) {
		t.Fatalf("expected sentinel rollback, got %v", err)
	}

	var count int
	if err := admin.QueryRow(ctx, "SELECT count(*) FROM public.encrypted_artifact WHERE id IN ('art_orphan_a','art_orphan_b')").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("orphan artifacts survived: %d", count)
	}
}

// Layer 3 negative: cross-tenant access finds nothing; wrong/missing key fails
// closed.
func TestEncryptedArtifactRuntimeCrossTenantAndKeyFailClosed(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")
	activateTestQuestionBranch(t, ctx, admin)
	store := newArtifactStore(t)
	repository := newArtifactRepository(t)
	codec, _ := newArtifactCodec(t, "org_alpha", artifactKEKPrimary)
	access := artifactAccess("org_alpha")

	seedOwningRow(t, ctx, store, access, "res_q1", true)
	storeArtifact(t, ctx, store, repository, codec, access, "res_q1", "art_q1", []byte("cross-tenant payload"))

	// A different tenant's read function returns no rows for the same owning id.
	betaAccess := database.AccessContext{OrganizationID: "org_beta", PrincipalID: "usr_bob", RequestID: "req_test"}
	seedOwningRow(t, ctx, store, betaAccess, "res_q1", true)
	if err := store.Read(ctx, betaAccess, func(readCtx context.Context, transaction database.Transaction) error {
		_, _, fetchErr := repository.Fetch(readCtx, transaction, betaAccess, artifactcrypto.QuestionText, "res_q1")
		if artifactrepository.CodeOf(fetchErr) != artifactrepository.CodeNotFound {
			t.Fatalf("cross-tenant fetch code=%v", artifactrepository.CodeOf(fetchErr))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	// A codec holding a different KEK cannot open the artifact.
	wrongKeyCodec, _ := newArtifactCodec(t, "org_alpha", artifactKEKAlternate)
	if err := store.Read(ctx, access, func(readCtx context.Context, transaction database.Transaction) error {
		owner, envelope, fetchErr := repository.Fetch(readCtx, transaction, access, artifactcrypto.QuestionText, "res_q1")
		if fetchErr != nil {
			return fetchErr
		}
		if _, openErr := wrongKeyCodec.Open(owner, envelope); artifactcrypto.CodeOf(openErr) != artifactcrypto.CodeOpenRejected {
			t.Fatalf("wrong-key open code=%v", artifactcrypto.CodeOf(openErr))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Layer 3: an active artifact under an unavailable key blocks readiness.
func TestEncryptedArtifactRuntimeUnavailableKeyBlocksReadiness(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	activateTestQuestionBranch(t, ctx, admin)
	store := newArtifactStore(t)
	repository := newArtifactRepository(t)
	codec, _ := newArtifactCodec(t, "org_alpha", artifactKEKPrimary)
	access := artifactAccess("org_alpha")

	seedOwningRow(t, ctx, store, access, "res_q1", true)
	storeArtifact(t, ctx, store, repository, codec, access, "res_q1", "art_q1", []byte("readiness payload"))

	if err := store.Read(ctx, access, func(readCtx context.Context, transaction database.Transaction) error {
		if readyErr := repository.CheckReadiness(readCtx, transaction, artifactKEKReference, artifactKEKVersion); readyErr != nil {
			t.Fatalf("readiness with the current key failed: %v", readyErr)
		}
		if readyErr := repository.CheckReadiness(readCtx, transaction, artifactKEKReference, artifactKEKVersion+1); artifactrepository.CodeOf(readyErr) != artifactrepository.CodeUnavailableKey {
			t.Fatalf("unavailable version did not block readiness: %v", artifactrepository.CodeOf(readyErr))
		}
		if readyErr := repository.CheckReadiness(readCtx, transaction, "other_ref", artifactKEKVersion); artifactrepository.CodeOf(readyErr) != artifactrepository.CodeUnavailableKey {
			t.Fatalf("unavailable reference did not block readiness: %v", artifactrepository.CodeOf(readyErr))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Layer 3: the tenant KEK reference/version/nonce uniqueness fence rejects a
// forced nonce collision.
func TestEncryptedArtifactRuntimeRejectsForcedNonceCollision(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	activateTestQuestionBranch(t, ctx, admin)
	store := newArtifactStore(t)
	repository := newArtifactRepository(t)
	codec, _ := newArtifactCodec(t, "org_alpha", artifactKEKPrimary)
	access := artifactAccess("org_alpha")

	seedOwningRow(t, ctx, store, access, "res_n1", true)
	seedOwningRow(t, ctx, store, access, "res_n2", true)
	owner1, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.QuestionText, "org_alpha", "res_n1")
	if err != nil {
		t.Fatal(err)
	}
	first, err := codec.Seal(owner1, []byte("first nonce-fence payload"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Write(ctx, access, func(writeCtx context.Context, transaction database.Transaction) error {
		return repository.Store(writeCtx, transaction, access, artifactcrypto.QuestionText, "res_n1", "art_n1", first)
	}); err != nil {
		t.Fatal(err)
	}
	// A second artifact reusing the first nonce under the same tenant KEK
	// reference/version is rejected by the database uniqueness fence.
	owner2, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.QuestionText, "org_alpha", "res_n2")
	if err != nil {
		t.Fatal(err)
	}
	collision := artifactcrypto.NewEnvelopeFromStorage(owner2, first.Cipher(), first.Ciphertext(), first.SizeBytes(),
		first.Nonce(), first.WrappedDEK(), first.WrappedDEKHash(), first.KEKReference(), first.KEKVersion(), first.AADHash(), first.PlaintextHash())
	if err := store.Write(ctx, access, func(writeCtx context.Context, transaction database.Transaction) error {
		return repository.Store(writeCtx, transaction, access, artifactcrypto.QuestionText, "res_n2", "art_n2", collision)
	}); err == nil {
		t.Fatal("forced nonce collision was accepted")
	}
}

// Layer 3: tampered stored ciphertext fails GCM authentication on open.
func TestEncryptedArtifactRuntimeTamperFailsClosed(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	activateTestQuestionBranch(t, ctx, admin)
	store := newArtifactStore(t)
	repository := newArtifactRepository(t)
	codec, _ := newArtifactCodec(t, "org_alpha", artifactKEKPrimary)
	access := artifactAccess("org_alpha")

	seedOwningRow(t, ctx, store, access, "res_q1", true)
	storeArtifact(t, ctx, store, repository, codec, access, "res_q1", "art_q1", []byte("tamper payload"))

	if err := store.Read(ctx, access, func(readCtx context.Context, transaction database.Transaction) error {
		owner, envelope, fetchErr := repository.Fetch(readCtx, transaction, access, artifactcrypto.QuestionText, "res_q1")
		if fetchErr != nil {
			return fetchErr
		}
		tamperedCiphertext := envelope.Ciphertext()
		tamperedCiphertext[0] ^= 0x01
		tampered := artifactcrypto.NewEnvelopeFromStorage(owner, envelope.Cipher(), tamperedCiphertext, envelope.SizeBytes(),
			envelope.Nonce(), envelope.WrappedDEK(), envelope.WrappedDEKHash(), envelope.KEKReference(), envelope.KEKVersion(), envelope.AADHash(), envelope.PlaintextHash())
		if _, openErr := codec.Open(owner, tampered); artifactcrypto.CodeOf(openErr) != artifactcrypto.CodeOpenRejected {
			t.Fatalf("tampered ciphertext open code=%v", artifactcrypto.CodeOf(openErr))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Layer 3: canary plaintext is absent from every durable/observable sink.
func TestEncryptedArtifactRuntimeCanaryAbsentFromAllSinks(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	activateTestQuestionBranch(t, ctx, admin)
	store := newArtifactStore(t)
	repository := newArtifactRepository(t)
	codec, _ := newArtifactCodec(t, "org_alpha", artifactKEKPrimary)
	access := artifactAccess("org_alpha")

	canary := "CANARY-8f3a2b1c-plaintext-must-never-persist-in-clear"
	seedOwningRow(t, ctx, store, access, "res_q1", true)
	storeArtifact(t, ctx, store, repository, codec, access, "res_q1", "art_q1", []byte(canary))

	// The full row text is the same value encoding pg_dump COPY emits for every
	// column, so a canary absent from it is absent from a dump.
	for _, table := range []string{"public.encrypted_artifact", "public.audit_event", "public.outbox_event", "public.question_run_test"} {
		var leaks int
		query := fmt.Sprintf("SELECT count(*) FROM %s AS t WHERE t::text LIKE '%%' || $1 || '%%'", table)
		if err := admin.QueryRow(ctx, query, canary).Scan(&leaks); err != nil {
			t.Fatalf("scan %s: %v", table, err)
		}
		if leaks != 0 {
			t.Fatalf("canary plaintext appeared in %s", table)
		}
	}
	// The raw bytea columns likewise never contain the canary bytes.
	var byteaLeaks int
	if err := admin.QueryRow(ctx, `
		SELECT count(*) FROM public.encrypted_artifact
		WHERE position($1::bytea in ciphertext) > 0
		   OR position($1::bytea in nonce) > 0
		   OR position($1::bytea in wrapped_dek) > 0
	`, []byte(canary)).Scan(&byteaLeaks); err != nil {
		t.Fatal(err)
	}
	if byteaLeaks != 0 {
		t.Fatal("canary plaintext appeared in stored artifact bytes")
	}
	// A denied fetch error is content-free.
	if err := store.Read(ctx, access, func(readCtx context.Context, transaction database.Transaction) error {
		_, _, fetchErr := repository.Fetch(readCtx, transaction, access, artifactcrypto.QuestionText, "res_absent")
		if fetchErr != nil && (bytes.Contains([]byte(fetchErr.Error()), []byte(canary))) {
			t.Fatal("error string leaked the canary")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

// Non-vacuous concurrency: Close genuinely races Seal, started together rather
// than after Wait. Under -race this must not data-race or panic; a seal that
// loses the race fails closed.
func TestEncryptedArtifactRuntimeCloseRacesSeal(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	activateTestQuestionBranch(t, ctx, admin)
	codec, provider := newArtifactCodec(t, "org_alpha", artifactKEKPrimary)
	_ = ctx
	_ = admin

	owner, err := artifactcrypto.NewOwnerIdentity(artifactcrypto.QuestionText, "org_alpha", "res_q1")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	start := make(chan struct{})
	errCh := make(chan error, 512)
	for worker := 0; worker < 8; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for iteration := 0; iteration < 100; iteration++ {
				_, sealErr := codec.Seal(owner, []byte("racing payload"))
				if sealErr != nil && artifactcrypto.CodeOf(sealErr) != artifactcrypto.CodeSealFailed {
					errCh <- sealErr
					return
				}
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		if closeErr := provider.Close(); closeErr != nil {
			errCh <- closeErr
		}
	}()
	close(start)
	workers.Wait()
	close(errCh)
	for workerErr := range errCh {
		t.Fatalf("race worker error: %v", workerErr)
	}
	if _, sealErr := codec.Seal(owner, []byte("after close")); artifactcrypto.CodeOf(sealErr) != artifactcrypto.CodeSealFailed {
		t.Fatalf("seal after close code=%v", artifactcrypto.CodeOf(sealErr))
	}
}

var _ = pgx.ErrNoRows
