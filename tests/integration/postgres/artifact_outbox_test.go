package postgres_test

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestEncryptedArtifactCryptoShapePurgeAndRuntimeImmutability(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	insertArtifact(t, ctx, admin, "org_alpha", "usr_alice", "artifact_alpha", "a", "question_run", "question_text_artifact_id", "QUESTION_RUN", "qr_alpha", "QUESTION_TEXT")

	assertArtifactStatementRejected(t, app, "org_alpha", "usr_alice", `
		UPDATE public.encrypted_artifact
		SET plaintext_hash = 'sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
		WHERE id = 'artifact_alpha'
	`)
	assertArtifactStatementRejected(t, app, "org_alpha", "usr_alice", `
		DELETE FROM public.encrypted_artifact WHERE id = 'artifact_alpha'
	`)
	// The owner CHECK rejects an unaccepted owner tuple. The runtime has no
	// direct access after containment, so the closed-inventory CHECK is exercised
	// through the privileged role, which does not bypass table CHECK constraints.
	assertAdminStatementRejected(t, ctx, admin, `
		INSERT INTO public.encrypted_artifact (
			organization_id, id, owner_table, owner_column, resource_type, resource_id, field_name,
			ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash,
			kek_reference, kek_version, aad_hash, plaintext_hash
		) VALUES (
			'org_alpha', 'artifact_bad_owner', 'question_run', 'question_text_artifact_id',
			'BLOB', 'qr_bad', 'QUESTION_TEXT', decode(repeat('ab', 17), 'hex'), 1,
			decode(repeat('01', 12), 'hex'), decode('01', 'hex'),
			'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
			'kms://alpha', 1,
			'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
			'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc'
		)
	`)
	// The same nonce under one KEK reference/version is forbidden by the database
	// uniqueness fence even when a different wrapped-DEK hash is supplied.
	assertAdminStatementRejected(t, ctx, admin, validArtifactInsertSQL(
		"org_alpha", "artifact_nonce_reuse", "d", "qr_nonce_reuse",
	))

	if _, err := admin.Exec(ctx, `
		UPDATE public.encrypted_artifact
		SET ciphertext = NULL, wrapped_dek = NULL, purged_at = transaction_timestamp()
		WHERE organization_id = 'org_alpha' AND id = 'artifact_alpha'
	`); err != nil {
		t.Fatalf("privileged exact purge: %v", err)
	}
	if _, err := admin.Exec(ctx, `
		UPDATE public.encrypted_artifact
		SET ciphertext = decode(repeat('ab', 17), 'hex'), nonce = decode(repeat('01', 12), 'hex'),
		    wrapped_dek = decode('01', 'hex'), purged_at = NULL
		WHERE organization_id = 'org_alpha' AND id = 'artifact_alpha'
	`); err == nil {
		t.Fatal("purged artifact was resurrected")
	}
	var nonceLength int
	var wrappedDEKHash string
	if err := admin.QueryRow(ctx, `
		SELECT octet_length(nonce), wrapped_dek_hash
		FROM public.encrypted_artifact
		WHERE organization_id = 'org_alpha' AND id = 'artifact_alpha'
	`).Scan(&nonceLength, &wrappedDEKHash); err != nil {
		t.Fatal(err)
	}
	if nonceLength != 12 || wrappedDEKHash != sha256Value("a") {
		t.Fatalf("purge lost nonce uniqueness fence: nonce=%d hash=%q", nonceLength, wrappedDEKHash)
	}
}

func TestEncryptedArtifactAndOutboxRLSTenantIsolation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	insertArtifact(t, ctx, admin, "org_alpha", "usr_alice", "artifact_alpha", "a", "question_run", "question_text_artifact_id", "QUESTION_RUN", "qr_alpha", "QUESTION_TEXT")
	insertArtifact(t, ctx, admin, "org_beta", "usr_bob", "artifact_beta", "a", "question_run", "question_text_artifact_id", "QUESTION_RUN", "qr_beta", "QUESTION_TEXT")
	alphaEvent, betaEvent := outboxRef("evt", 1), outboxRef("evt", 2)
	insertOutboxEvent(t, ctx, app, "org_alpha", "usr_alice", alphaEvent, outboxRef("sv", 1))
	insertOutboxEvent(t, ctx, app, "org_beta", "usr_bob", betaEvent, outboxRef("sv", 2))

	for _, tableName := range []string{"encrypted_artifact", "outbox_sequence_head", "outbox_event"} {
		var forced bool
		if err := admin.QueryRow(ctx, `
			SELECT c.relforcerowsecurity
			FROM pg_class AS c JOIN pg_namespace AS n ON n.oid = c.relnamespace
			WHERE n.nspname = 'public' AND c.relname = $1
		`, tableName).Scan(&forced); err != nil {
			t.Fatal(err)
		}
		if !forced {
			t.Fatalf("%s RLS is not forced", tableName)
		}
		assertRLSCannotDisable(t, ctx, app, "org_alpha", "usr_alice", tableName)
	}

	// Only the outbox tables grant the runtime SELECT; a query without a tenant
	// context returns no rows. encrypted_artifact grants the runtime nothing:
	// after containment its access is through per-branch functions only.
	for _, tableName := range []string{"outbox_sequence_head", "outbox_event"} {
		var unscopedCount int
		if err := app.QueryRow(ctx, "SELECT count(*) FROM public."+tableName).Scan(&unscopedCount); err != nil {
			t.Fatal(err)
		}
		if unscopedCount != 0 {
			t.Fatalf("unscoped %s query returned %d rows", tableName, unscopedCount)
		}
	}

	for tableName, expected := range map[string]struct{ canSelect, canInsert bool }{
		"encrypted_artifact":   {canSelect: false, canInsert: false},
		"outbox_sequence_head": {canSelect: true, canInsert: false},
		"outbox_event":         {canSelect: true, canInsert: false},
	} {
		var canSelect, canInsert, canUpdate, canDelete, canTruncate, canReferences, canTrigger bool
		if err := admin.QueryRow(ctx, `
			SELECT has_table_privilege('knowvault_app', 'public.' || $1, 'SELECT'),
			       has_table_privilege('knowvault_app', 'public.' || $1, 'INSERT'),
			       has_table_privilege('knowvault_app', 'public.' || $1, 'UPDATE'),
			       has_table_privilege('knowvault_app', 'public.' || $1, 'DELETE'),
			       has_table_privilege('knowvault_app', 'public.' || $1, 'TRUNCATE'),
			       has_table_privilege('knowvault_app', 'public.' || $1, 'REFERENCES'),
			       has_table_privilege('knowvault_app', 'public.' || $1, 'TRIGGER')
		`, tableName).Scan(&canSelect, &canInsert, &canUpdate, &canDelete, &canTruncate, &canReferences, &canTrigger); err != nil {
			t.Fatal(err)
		}
		if canSelect != expected.canSelect || canInsert != expected.canInsert || canUpdate || canDelete || canTruncate || canReferences || canTrigger {
			t.Fatalf("unsafe runtime privileges on %s: select=%v insert=%v update=%v delete=%v truncate=%v references=%v trigger=%v",
				tableName, canSelect, canInsert, canUpdate, canDelete, canTruncate, canReferences, canTrigger)
		}
	}
	for functionName, expected := range map[string]bool{
		"app.enqueue_outbox_event(text,text,text,text,jsonb)": true,
		"app.outbox_event_state_guard()":                      false,
		"app.encrypted_artifact_mutation_guard()":             false,
		"app.outbox_sequence_head_delete_guard()":             false,
	} {
		var allowed bool
		if err := admin.QueryRow(ctx, "SELECT has_function_privilege('knowvault_app', $1, 'EXECUTE')", functionName).Scan(&allowed); err != nil {
			t.Fatal(err)
		}
		if allowed != expected {
			t.Fatalf("function privilege %s = %v, want %v", functionName, allowed, expected)
		}
	}

	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_alice")
	var count int
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public.outbox_event WHERE id = $1", betaEvent).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("alpha observed beta outbox event")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}

	// The runtime cannot insert an artifact for any tenant after containment.
	assertArtifactStatementRejected(t, app, "org_alpha", "usr_alice", strings.Replace(
		validArtifactInsertSQL("org_beta", "artifact_cross_tenant", "e", "qr_cross_tenant"),
		"'kms://tenant'", "'kms://cross-tenant'", 1,
	))
}

func TestOutboxRollbackGaplessAndConcurrentSequence(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	rolledBack, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	setAccessContextForPrincipal(t, ctx, rolledBack, "org_alpha", "usr_alice")
	if _, err := rolledBack.Exec(ctx, `
		SELECT app.enqueue_outbox_event(
			$1, 'SOURCE_VERSION', $2, 'search.upsert',
			jsonb_build_object('source_version_id', $2::text, 'operation', 'UPSERT'))
	`, outboxRef("evt", 100), outboxRef("sv", 100)); err != nil {
		t.Fatal(err)
	}
	if err := rolledBack.Rollback(ctx); err != nil {
		t.Fatal(err)
	}

	const eventCount = 16
	errorsChannel := make(chan error, eventCount)
	var waitGroup sync.WaitGroup
	for index := 0; index < eventCount; index++ {
		index := index
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			tx, err := app.Begin(ctx)
			if err != nil {
				errorsChannel <- err
				return
			}
			defer func() { _ = tx.Rollback(ctx) }()
			if _, err = tx.Exec(ctx, `
				SELECT set_config('app.organization_id', 'org_alpha', true),
				       set_config('app.principal_id', 'usr_alice', true),
				       set_config('app.request_id', 'req_concurrent', true)
			`); err == nil {
				_, err = tx.Exec(ctx, `
					SELECT app.enqueue_outbox_event(
						$1, 'SOURCE_VERSION', $2, 'search.upsert',
						jsonb_build_object('source_version_id', $2::text, 'operation', 'UPSERT'))
				`, outboxRef("evt", index+1), outboxRef("sv", index+1))
			}
			if err == nil {
				err = tx.Commit(ctx)
			}
			errorsChannel <- err
		}()
	}
	waitGroup.Wait()
	close(errorsChannel)
	for err := range errorsChannel {
		if err != nil {
			t.Fatalf("concurrent outbox insert: %v", err)
		}
	}

	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, "org_alpha", "usr_alice")
	rows, err := tx.Query(ctx, "SELECT sequence FROM public.outbox_event ORDER BY sequence")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	expected := int64(1)
	for rows.Next() {
		var sequence int64
		if err := rows.Scan(&sequence); err != nil {
			t.Fatal(err)
		}
		if sequence != expected {
			t.Fatalf("sequence gap: got %d, want %d", sequence, expected)
		}
		expected++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if expected != eventCount+1 {
		t.Fatalf("read %d committed sequences, want %d", expected-1, eventCount)
	}
}

func TestOutboxPublishStrictOrderServerTimeAndImmutability(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	eventOne, eventTwo := outboxRef("evt", 1), outboxRef("evt", 2)
	insertOutboxEvent(t, ctx, app, "org_alpha", "usr_alice", eventOne, outboxRef("sv", 1))
	insertOutboxEvent(t, ctx, app, "org_alpha", "usr_alice", eventTwo, outboxRef("sv", 2))

	assertOutboxStatementRejected(t, app, "org_alpha", "usr_alice", fmt.Sprintf(`
		UPDATE public.outbox_event SET published_at = transaction_timestamp()
		WHERE id = %s
	`, sqlLiteral(eventTwo)))
	assertAdminStatementRejected(t, ctx, admin, fmt.Sprintf(`
		UPDATE public.outbox_event SET published_at = transaction_timestamp()
		WHERE organization_id = 'org_alpha' AND id = %s
	`, sqlLiteral(eventTwo)))
	publishOutboxEventWithRequestedTime(t, ctx, admin, "org_alpha", eventOne, "2999-01-01T00:00:00Z")
	publishOutboxEvent(t, ctx, admin, "org_alpha", eventTwo)
	assertOutboxStatementRejected(t, app, "org_alpha", "usr_alice", fmt.Sprintf(`
		UPDATE public.outbox_event SET published_at = transaction_timestamp()
		WHERE id = %s
	`, sqlLiteral(eventOne)))
	assertOutboxStatementRejected(t, app, "org_alpha", "usr_alice", "DELETE FROM public.outbox_event WHERE id = "+sqlLiteral(eventOne))
	assertOutboxStatementRejected(t, app, "org_alpha", "usr_alice", `
		UPDATE public.outbox_sequence_head SET last_assigned_sequence = 999
		WHERE organization_id = 'org_alpha'
	`)
	assertOutboxStatementRejected(t, app, "org_alpha", "usr_alice", `
		INSERT INTO public.outbox_event (
			organization_id, id, sequence, aggregate_type, aggregate_id, event_type, payload_json
		) VALUES ('org_alpha', 'event_forged', 99, 'SOURCE_VERSION', 'version_forged',
		          'search.upsert', '{"source_version_id":"version_forged"}'::jsonb)
	`)
	assertOutboxStatementRejected(t, app, "org_alpha", "usr_alice", fmt.Sprintf(`
		SELECT app.enqueue_outbox_event(
			%s, 'SOURCE_VERSION', %s, 'search.upsert',
			'{"text":"secret source content"}'::jsonb)
	`, sqlLiteral(outboxRef("evt", 50)), sqlLiteral(outboxRef("sv", 50))))
	for _, payload := range []string{
		`{"source_version_id":"/secret/contracts/customer.pdf"}`,
		`{"artifact_id":"alice@company.com"}`,
		`{"workspace_id":"https://internal.example/path"}`,
		"{\"source_object_id\":\"\u041f\u0440\u043e\u0435\u043a\u0442 \u0410\u043b\u044c\u0444\u0430\"}",
		`{"retention_fence":9999999999999999}`,
		`{}`,
	} {
		assertOutboxStatementRejected(t, app, "org_alpha", "usr_alice", fmt.Sprintf(`
			SELECT app.enqueue_outbox_event(
				%s, 'SOURCE_VERSION', %s, 'search.upsert', %s::jsonb)
		`, sqlLiteral(outboxRef("evt", 51)), sqlLiteral(outboxRef("sv", 51)), sqlLiteral(payload)))
	}
	for _, call := range []string{
		`SELECT app.enqueue_outbox_event('/secret/event', 'SOURCE_VERSION', 'version_safe', 'search.upsert', '{"source_version_id":"version_safe"}'::jsonb)`,
		`SELECT app.enqueue_outbox_event('event_safe', 'SOURCE_VERSION', 'alice@company.com', 'search.upsert', '{"source_version_id":"version_safe"}'::jsonb)`,
		"SELECT app.enqueue_outbox_event('event_safe', 'SOURCE_VERSION', '\u041f\u0440\u043e\u0435\u043a\u0442_\u0410\u043b\u044c\u0444\u0430', 'search.upsert', '{\"source_version_id\":\"version_safe\"}'::jsonb)",
	} {
		assertOutboxStatementRejected(t, app, "org_alpha", "usr_alice", call)
	}

	var publishedAt time.Time
	if err := admin.QueryRow(ctx, `
		SELECT published_at FROM public.outbox_event
		WHERE organization_id = 'org_alpha' AND id = $1
	`, eventOne).Scan(&publishedAt); err != nil {
		t.Fatal(err)
	}
	if publishedAt.After(time.Now().Add(time.Second)) {
		t.Fatalf("publisher controlled future timestamp: %s", publishedAt)
	}
}

func TestArtifactAndOutboxHardDeleteRequiresExactLifecycleOrder(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))
	insertArtifact(t, ctx, admin, "org_alpha", "usr_alice", "artifact_alpha", "a", "question_run", "question_text_artifact_id", "QUESTION_RUN", "qr_alpha", "QUESTION_TEXT")
	eventID := outboxRef("evt", 1)
	insertOutboxEvent(t, ctx, app, "org_alpha", "usr_alice", eventID, outboxRef("sv", 1))

	assertAdminStatementRejected(t, ctx, admin, `DELETE FROM public.encrypted_artifact WHERE organization_id = 'org_alpha'`)
	assertAdminStatementRejected(t, ctx, admin, `DELETE FROM public.outbox_event WHERE organization_id = 'org_alpha'`)
	assertAdminStatementRejected(t, ctx, admin, `DELETE FROM public.outbox_sequence_head WHERE organization_id = 'org_alpha'`)

	if _, err := admin.Exec(ctx, `UPDATE public.organization SET status = 'DELETING' WHERE id = 'org_alpha'`); err != nil {
		t.Fatal(err)
	}
	// The mutation guard blocks a new artifact once the tenant leaves ACTIVE,
	// proved through the privileged role since the runtime has no insert path.
	assertAdminStatementRejected(t, ctx, admin, strings.Replace(
		validArtifactInsertSQL("org_alpha", "artifact_after_delete_started", "d", "qr_after_delete_started"),
		"'kms://tenant'", "'kms://deleting'", 1,
	))
	assertOutboxStatementRejected(t, app, "org_alpha", "usr_alice", fmt.Sprintf(`
		SELECT app.enqueue_outbox_event(
			%s, 'SOURCE_VERSION', %s, 'search.upsert',
			jsonb_build_object('source_version_id', %s::text))
	`, sqlLiteral(outboxRef("evt", 90)), sqlLiteral(outboxRef("sv", 90)), sqlLiteral(outboxRef("sv", 90))))
	assertAdminStatementRejected(t, ctx, admin, `DELETE FROM public.encrypted_artifact WHERE organization_id = 'org_alpha'`)
	// The head cannot disappear while its semantic events still exist.
	assertAdminStatementRejected(t, ctx, admin, `DELETE FROM public.outbox_sequence_head WHERE organization_id = 'org_alpha'`)

	if _, err := admin.Exec(ctx, `
		UPDATE public.encrypted_artifact
		SET ciphertext = NULL, wrapped_dek = NULL, purged_at = transaction_timestamp()
		WHERE organization_id = 'org_alpha' AND id = 'artifact_alpha'
	`); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`DELETE FROM public.encrypted_artifact WHERE organization_id = 'org_alpha' AND id = 'artifact_alpha'`,
		`DELETE FROM public.outbox_event WHERE organization_id = 'org_alpha' AND id = ` + sqlLiteral(eventID),
		`DELETE FROM public.outbox_sequence_head WHERE organization_id = 'org_alpha'`,
	} {
		if _, err := admin.Exec(ctx, statement); err != nil {
			t.Fatalf("ordered hard-delete failed: %v", err)
		}
	}
}

func TestTenantDeletionTransitionSerializesAfterArtifactAndOutboxCreation(t *testing.T) {
	ctx := context.Background()
	admin := resetStage1Database(t)
	seedOrganization(t, ctx, admin, "org_alpha", "usr_alice", "ws_alpha")
	seedOrganization(t, ctx, admin, "org_beta", "usr_bob", "ws_beta")
	app := openApplicationPool(t, ctx, testDatabaseURL(t))

	type beginner interface {
		Begin(context.Context) (pgx.Tx, error)
	}
	for _, testCase := range []struct {
		name           string
		organizationID string
		principalID    string
		writer         beginner
		write          func(pgx.Tx) error
		assertDenied   func()
	}{
		{
			// The artifact writer runs through the privileged role because the
			// runtime cannot insert after containment, but it still takes the same
			// organization FOR SHARE lock through the mutation guard.
			name:           "artifact",
			organizationID: "org_alpha",
			principalID:    "usr_alice",
			writer:         admin,
			write: func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, validArtifactInsertSQL("org_alpha", "artifact_before_delete", "a", "qr_before_delete"))
				return err
			},
			assertDenied: func() {
				assertAdminStatementRejected(t, ctx, admin, strings.Replace(
					validArtifactInsertSQL("org_alpha", "artifact_after_transition", "d", "qr_after_transition"),
					"'kms://tenant'", "'kms://after-transition'", 1,
				))
			},
		},
		{
			name:           "outbox",
			organizationID: "org_beta",
			principalID:    "usr_bob",
			writer:         app,
			write: func(tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `
					SELECT app.enqueue_outbox_event(
						$1, 'SOURCE_VERSION', $2, 'search.upsert',
						jsonb_build_object('source_version_id', $2::text))
				`, outboxRef("evt", 200), outboxRef("sv", 200))
				return err
			},
			assertDenied: func() {
				assertOutboxStatementRejected(t, app, "org_beta", "usr_bob", fmt.Sprintf(`
					SELECT app.enqueue_outbox_event(
						%s, 'SOURCE_VERSION', %s, 'search.upsert',
						jsonb_build_object('source_version_id', %s::text))
				`, sqlLiteral(outboxRef("evt", 201)), sqlLiteral(outboxRef("sv", 201)), sqlLiteral(outboxRef("sv", 201))))
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			tx, err := testCase.writer.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = tx.Rollback(ctx) }()
			setAccessContextForPrincipal(t, ctx, tx, testCase.organizationID, testCase.principalID)
			if err := testCase.write(tx); err != nil {
				t.Fatalf("writer failed before deletion transition: %v", err)
			}

			transition := make(chan error, 1)
			go func() {
				_, updateErr := admin.Exec(ctx, `
					UPDATE public.organization
					SET status = 'DELETING', updated_at = transaction_timestamp()
					WHERE id = $1
				`, testCase.organizationID)
				transition <- updateErr
			}()
			select {
			case updateErr := <-transition:
				t.Fatalf("deletion transition bypassed active writer lock: %v", updateErr)
			case <-time.After(150 * time.Millisecond):
			}
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			select {
			case updateErr := <-transition:
				if updateErr != nil {
					t.Fatalf("deletion transition after writer commit: %v", updateErr)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("deletion transition stayed blocked after writer commit")
			}
			testCase.assertDenied()
		})
	}
}

func insertArtifact(
	t *testing.T,
	ctx context.Context,
	app interface {
		Begin(context.Context) (pgx.Tx, error)
	},
	organizationID, principalID, artifactID, digestCharacter,
	ownerTable, ownerColumn, resourceType, resourceID, fieldName string,
) {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	ciphertext := []byte(strings.Repeat("x", 17))
	if _, err := tx.Exec(ctx, `
		INSERT INTO public.encrypted_artifact (
			organization_id, id, owner_table, owner_column, resource_type, resource_id, field_name,
			ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash,
			kek_reference, kek_version, aad_hash, plaintext_hash
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 1, $9, $10, $11, 'kms://tenant', 1, $12, $13)
	`, organizationID, artifactID, ownerTable, ownerColumn, resourceType, resourceID, fieldName,
		ciphertext, []byte(strings.Repeat("n", 12)), []byte("wrapped"), sha256Value(digestCharacter),
		sha256Value("b"), sha256Value("c")); err != nil {
		t.Fatalf("insert encrypted artifact: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func validArtifactInsertSQL(organizationID, artifactID, digestCharacter, resourceID string) string {
	return `
		INSERT INTO public.encrypted_artifact (
			organization_id, id, owner_table, owner_column, resource_type, resource_id, field_name,
			ciphertext, size_bytes, nonce, wrapped_dek, wrapped_dek_hash,
			kek_reference, kek_version, aad_hash, plaintext_hash
		) VALUES (` + sqlLiteral(organizationID) + `, ` + sqlLiteral(artifactID) + `,
			'question_run', 'question_text_artifact_id', 'QUESTION_RUN', ` + sqlLiteral(resourceID) + `,
			'QUESTION_TEXT', decode(repeat('ab', 17), 'hex'), 1, decode(repeat('6e', 12), 'hex'),
			decode('77726170706564', 'hex'), ` + sqlLiteral(sha256Value(digestCharacter)) + `,
			'kms://tenant', 1, ` + sqlLiteral(sha256Value("b")) + `, ` + sqlLiteral(sha256Value("c")) + `)
	`
}

func insertOutboxEvent(t *testing.T, ctx context.Context, app interface {
	Begin(context.Context) (pgx.Tx, error)
}, organizationID, principalID, eventID, versionID string) {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	if _, err := tx.Exec(ctx, `
		SELECT app.enqueue_outbox_event(
			$1, 'SOURCE_VERSION', $2, 'search.upsert',
			jsonb_build_object('source_version_id', $2::text, 'operation', 'UPSERT'))
	`, eventID, versionID); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func publishOutboxEvent(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, eventID string) {
	t.Helper()
	commandTag, err := admin.Exec(ctx, "UPDATE public.outbox_event SET published_at = transaction_timestamp() WHERE organization_id = $1 AND id = $2", organizationID, eventID)
	if err != nil {
		t.Fatal(err)
	}
	if commandTag.RowsAffected() != 1 {
		t.Fatalf("publish %s affected %d rows", eventID, commandTag.RowsAffected())
	}
}

func publishOutboxEventWithRequestedTime(t *testing.T, ctx context.Context, admin *pgxpool.Pool, organizationID, eventID, requestedTime string) {
	t.Helper()
	commandTag, err := admin.Exec(ctx, "UPDATE public.outbox_event SET published_at = $3::timestamptz WHERE organization_id = $1 AND id = $2", organizationID, eventID, requestedTime)
	if err != nil {
		t.Fatal(err)
	}
	if commandTag.RowsAffected() != 1 {
		t.Fatalf("publish %s affected %d rows", eventID, commandTag.RowsAffected())
	}
}

func assertAdminStatementRejected(t *testing.T, ctx context.Context, admin *pgxpool.Pool, statement string) {
	t.Helper()
	if _, err := admin.Exec(ctx, statement); err == nil {
		t.Fatalf("privileged statement unexpectedly succeeded: %s", statement)
	}
}

func assertOutboxSequence(t *testing.T, ctx context.Context, app interface {
	Begin(context.Context) (pgx.Tx, error)
}, organizationID, principalID, eventID string, expected int64) {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	var sequence int64
	if err := tx.QueryRow(ctx, "SELECT sequence FROM public.outbox_event WHERE id = $1", eventID).Scan(&sequence); err != nil {
		t.Fatal(err)
	}
	if sequence != expected {
		t.Fatalf("event %s sequence = %d, want %d", eventID, sequence, expected)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}

func assertArtifactStatementRejected(t *testing.T, app interface {
	Begin(context.Context) (pgx.Tx, error)
}, organizationID, principalID, statement string) {
	t.Helper()
	assertTenantStatementRejected(t, app, organizationID, principalID, statement)
}

func assertOutboxStatementRejected(t *testing.T, app interface {
	Begin(context.Context) (pgx.Tx, error)
}, organizationID, principalID, statement string) {
	t.Helper()
	assertTenantStatementRejected(t, app, organizationID, principalID, statement)
}

func assertTenantStatementRejected(t *testing.T, app interface {
	Begin(context.Context) (pgx.Tx, error)
}, organizationID, principalID, statement string) {
	t.Helper()
	ctx := context.Background()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	if _, err := tx.Exec(ctx, statement); err == nil {
		t.Fatalf("runtime statement unexpectedly succeeded: %s", statement)
	}
}

func assertRLSCannotDisable(t *testing.T, ctx context.Context, app *pgxpool.Pool, organizationID, principalID, tableName string) {
	t.Helper()
	tx, err := app.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	setAccessContextForPrincipal(t, ctx, tx, organizationID, principalID)
	if _, err := tx.Exec(ctx, "SET LOCAL row_security = off"); err != nil {
		t.Fatal(err)
	}
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM public."+tableName).Scan(new(int)); err == nil {
		t.Fatalf("runtime disabled RLS for %s", tableName)
	}
}

func sha256Value(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func sqlLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func outboxRef(prefix string, value int) string {
	return fmt.Sprintf("%s_0%025d", prefix, value)
}
