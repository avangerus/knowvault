//go:build linux

package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// workerChrootDir is the host-side path of the worker's private filesystem
// root. The worker binary pins /run/knowvault/... exactly like the server, so
// one shared container cannot feed the two binaries different mounts through
// the same path; the chroot gives the worker its own container-equivalent
// root with its own worker mount (own db_url, shared key material via
// -keys-from), trust mount and source mount, exactly as DEPLOYMENT.md §4
// prescribes for the separate worker container.
const workerChrootDir = "/e2e/worker-root"

// workerSecretsMount is the worker mount inside the chroot, as the operator
// -out target sees it from the host-side harness process.
const workerSecretsMount = workerChrootDir + "/run/knowvault/secrets"

// prepareWorkerChroot lays out everything the worker root must carry besides
// the operator-generated secret mount: the pinned trust directory with both
// bundle files, the source mount root, the CA copy for the worker's
// SSL_CERT_FILE and the worker binary. The secret mount itself is generated
// afterwards by the operator, which creates the directory with the runtime
// group and mode the product loader enforces.
func prepareWorkerChroot(ctx context.Context, cfg config) error {
	_ = ctx
	caPEM, err := os.ReadFile(filepath.Join(cfg.caDir, "ca.pem"))
	if err != nil {
		return fmt.Errorf("read ca: %w", err)
	}
	for _, dir := range []string{
		filepath.Join(workerChrootDir, "run", "knowvault"),
		filepath.Join(workerChrootDir, "run", "knowvault", "trust"),
		filepath.Join(workerChrootDir, "run", "knowvault", "sources"),
		filepath.Join(workerChrootDir, "run", "knowvault", "search"),
	} {
		mode := os.FileMode(0o755)
		if strings.HasSuffix(dir, "trust") || strings.HasSuffix(dir, "sources") || strings.HasSuffix(dir, "search") {
			mode = 0o750
		}
		if err := os.MkdirAll(dir, mode); err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			return fmt.Errorf("chmod %s: %w", dir, err)
		}
		if strings.HasSuffix(dir, "trust") || strings.HasSuffix(dir, "sources") || strings.HasSuffix(dir, "search") {
			if err := syscall.Chown(dir, 0, workerRuntimeGID); err != nil {
				return fmt.Errorf("chown %s: %w", dir, err)
			}
		}
	}
	// The same CA serves the database and OIDC bundles inside the worker root
	// as it does for the server trust mount.
	for _, name := range []string{"database-ca.pem", "oidc-ca.pem"} {
		path := filepath.Join(workerChrootDir, "run", "knowvault", "trust", name)
		if err := os.WriteFile(path, caPEM, 0o440); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
		if err := syscall.Chown(path, 0, workerRuntimeGID); err != nil {
			return fmt.Errorf("chown %s: %w", name, err)
		}
		if err := os.Chmod(path, 0o440); err != nil {
			return fmt.Errorf("chmod %s: %w", name, err)
		}
	}
	if err := copyFileMode(filepath.Join(cfg.caDir, "ca.pem"),
		filepath.Join(workerChrootDir, "ca.pem"), 0o444); err != nil {
		return fmt.Errorf("copy ca: %w", err)
	}
	// The pure-Go resolver inside the chroot reads /etc/resolv.conf and
	// /etc/hosts, and the chroot has no /etc of its own. The pinned resolver
	// files keep hostname resolution identical to the surrounding container;
	// the docker embedded DNS (127.0.0.11) stays reachable because the chroot
	// shares the network namespace.
	if err := os.MkdirAll(filepath.Join(workerChrootDir, "etc"), 0o755); err != nil {
		return fmt.Errorf("mkdir etc: %w", err)
	}
	for _, name := range []string{"resolv.conf", "hosts"} {
		if err := copyFileMode(filepath.Join("/etc", name),
			filepath.Join(workerChrootDir, "etc", name), 0o444); err != nil {
			return fmt.Errorf("copy /etc/%s: %w", name, err)
		}
	}
	if err := copyFileMode("/knowvault-worker",
		filepath.Join(workerChrootDir, "knowvault-worker"), 0o755); err != nil {
		return fmt.Errorf("copy worker binary: %w", err)
	}
	return nil
}

// copyFileMode copies one regular file and pins the target mode.
func copyFileMode(source, target string, mode os.FileMode) error {
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if err := os.WriteFile(target, raw, mode); err != nil {
		return err
	}
	return os.Chmod(target, mode)
}

// workerRootDiagnostic dumps the worker chroot tree with modes and owners so
// a failed worker startup shows exactly which mount file diverges from the
// pinned contract. No secret content is printed.
func workerRootDiagnostic() string {
	var line strings.Builder
	fmt.Fprintf(&line, "worker chroot tree (%s):", workerChrootDir)
	_ = filepath.Walk(workerChrootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Fprintf(&line, "\n  (walk %s: %v)", path, err)
			return nil
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			fmt.Fprintf(&line, "\n  %s mode=%o", strings.TrimPrefix(path, workerChrootDir), info.Mode().Perm())
			return nil
		}
		fmt.Fprintf(&line, "\n  %s mode=%o uid=%d gid=%d size=%d",
			strings.TrimPrefix(path, workerChrootDir), info.Mode().Perm(), stat.Uid, stat.Gid, info.Size())
		return nil
	})
	return line.String()
}

// workerDatabaseDiagnostic reports the runtime roles and probes a connection
// as the worker database role with the sealed worker URL, so a failed worker
// startup shows whether the failure is role-side or connection-side.
func workerDatabaseDiagnostic(ctx context.Context, cfg config) string {
	var line strings.Builder
	admin, err := pgxpool.New(ctx, cfg.adminURL)
	if err != nil {
		fmt.Fprintf(&line, "admin pool: %v\n", err)
	} else {
		defer admin.Close()
		rows, err := admin.Query(ctx, "SELECT rolname, rolcanlogin, rolsuper, rolbypassrls FROM pg_roles WHERE rolname LIKE 'knowvault%' ORDER BY rolname")
		if err != nil {
			fmt.Fprintf(&line, "pg roles query: %v\n", err)
		} else {
			defer rows.Close()
			fmt.Fprintln(&line, "pg roles:")
			for rows.Next() {
				var name string
				var canLogin, super, bypass bool
				if err := rows.Scan(&name, &canLogin, &super, &bypass); err != nil {
					fmt.Fprintf(&line, "  (scan: %v)\n", err)
					continue
				}
				fmt.Fprintf(&line, "  %s canlogin=%v super=%v bypassrls=%v\n", name, canLogin, super, bypass)
			}
		}
	}
	workerURL, err := os.ReadFile("/e2e/run/db_worker.url")
	if err != nil {
		fmt.Fprintf(&line, "db_worker.url read: %v\n", err)
		return line.String()
	}
	pool, err := pgxpool.New(ctx, string(workerURL))
	if err != nil {
		// A pgx config error embeds the raw DSN; redact it before the failure
		// report leaves the container.
		fmt.Fprintf(&line, "worker pool create: %v\n", redactRunSecrets(err.Error()))
		return line.String()
	}
	defer pool.Close()
	var currentUser string
	if err := pool.QueryRow(ctx, "SELECT current_user::text").Scan(&currentUser); err != nil {
		fmt.Fprintf(&line, "worker role connect: %v\n", err)
	} else {
		fmt.Fprintf(&line, "worker role connect: current_user=%s\n", currentUser)
	}
	// Probe the exact claim mechanics the worker drives: one transaction,
	// tenant settings local to it, then app.claim_next_job as the worker role.
	// The probe rolls back, so a successful claim cannot consume the job.
	tx, err := pool.Begin(ctx)
	if err != nil {
		fmt.Fprintf(&line, "claim probe begin: %v\n", err)
		return line.String()
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var settingOrg, settingPrincipal, settingRequest string
	if err := tx.QueryRow(ctx, `
		SELECT set_config('app.organization_id', $1, true),
		       set_config('app.principal_id', 'knowvault_worker', true),
		       set_config('app.request_id', 'worker.poll', true)`, cfg.organizationID).Scan(&settingOrg, &settingPrincipal, &settingRequest); err != nil {
		fmt.Fprintf(&line, "claim probe set_config: %v\n", err)
		return line.String()
	}
	fmt.Fprintf(&line, "claim probe settings: org=%q\n", settingOrg)
	var claimID, claimType string
	var claimEpoch, claimAttempt, claimMax int64
	err = tx.QueryRow(ctx, `SELECT job_id, job_type, lease_epoch, attempt_number, max_attempts
		FROM app.claim_next_job('probe-worker', 10)`).
		Scan(&claimID, &claimType, &claimEpoch, &claimAttempt, &claimMax)
	if err != nil {
		fmt.Fprintf(&line, "claim probe: %v\n", err)
	} else {
		fmt.Fprintf(&line, "claim probe: job=%s type=%s epoch=%d attempt=%d/%d\n",
			claimID, claimType, claimEpoch, claimAttempt, claimMax)
	}
	// Release the probe's row locks before the poll evidence window below: a
	// held FOR UPDATE lock would make the live worker's claims skip the job
	// during the 3s commit-activity measurement and corrupt the evidence.
	_ = tx.Rollback(ctx)
	// Poll liveness evidence: the commit counter of the tenant database over a
	// 3s window plus the live sessions of the worker role. A polling worker
	// commits about twice per second (reclaim + claim); a wedged one commits
	// only the pool health checks.
	{
		probeAdmin, probeErr := pgxpool.New(ctx, cfg.adminURL)
		if probeErr != nil {
			fmt.Fprintf(&line, "poll evidence admin pool: %v\n", probeErr)
			return line.String()
		}
		defer probeAdmin.Close()
		var before int64
		if err := probeAdmin.QueryRow(ctx, "SELECT xact_commit FROM pg_stat_database WHERE datname = 'knowvault'").Scan(&before); err != nil {
			fmt.Fprintf(&line, "poll evidence before: %v\n", err)
		} else {
			rows, err := probeAdmin.Query(ctx, `
				SELECT state, coalesce(left(query, 60), ''), coalesce(xact_start::text, '')
				FROM pg_stat_activity
				WHERE usename = 'knowvault_worker'
				ORDER BY pid`)
			if err != nil {
				fmt.Fprintf(&line, "poll evidence activity: %v\n", err)
			} else {
				defer rows.Close()
				fmt.Fprintln(&line, "worker sessions:")
				for rows.Next() {
					var state, query, xactStart string
					if err := rows.Scan(&state, &query, &xactStart); err != nil {
						fmt.Fprintf(&line, "  (scan: %v)\n", err)
						continue
					}
					fmt.Fprintf(&line, "  state=%s query=%q xact_start=%s\n", state, query, xactStart)
				}
			}
			time.Sleep(3 * time.Second)
			var after int64
			if err := probeAdmin.QueryRow(ctx, "SELECT xact_commit FROM pg_stat_database WHERE datname = 'knowvault'").Scan(&after); err != nil {
				fmt.Fprintf(&line, "poll evidence after: %v\n", err)
			} else {
				fmt.Fprintf(&line, "db xact_commit delta over 3s: %d\n", after-before)
			}
		}
	}
	// Canonical graph identity is hash/ID-only, so this bounded snapshot is safe
	// to include when a replay trips a uniqueness guard. It tells the operator
	// whether the duplicate is a same-object replay or a projector mismatch.
	if graphAdmin, graphErr := pgxpool.New(ctx, cfg.adminURL); graphErr == nil {
		defer graphAdmin.Close()
		var chunks, chunkFragments, pendingSearch, publishedSearch int64
		if countErr := graphAdmin.QueryRow(ctx, `
			SELECT
			 (SELECT count(*) FROM public.search_chunk WHERE organization_id=$1),
			 (SELECT count(*) FROM public.search_chunk_fragment WHERE organization_id=$1),
			 (SELECT count(*) FROM public.outbox_event WHERE organization_id=$1 AND aggregate_type='SEARCH_CHUNK' AND published_at IS NULL),
			 (SELECT count(*) FROM public.outbox_event WHERE organization_id=$1 AND aggregate_type='SEARCH_CHUNK' AND published_at IS NOT NULL)`,
			cfg.organizationID).Scan(&chunks, &chunkFragments, &pendingSearch, &publishedSearch); countErr != nil {
			fmt.Fprintf(&line, "search projection counts: %v\n", countErr)
		} else {
			fmt.Fprintf(&line, "search projection counts: chunks=%d fragments=%d pending=%d published=%d\n",
				chunks, chunkFragments, pendingSearch, publishedSearch)
		}
		var profileID, profileHash, profileStatus string
		var profileGeneration, profileFence int64
		if profileErr := graphAdmin.QueryRow(ctx, `
			SELECT embedding_profile_id, embedding_profile_hash, index_generation,
			       generation_fence, status
			  FROM public.organization_search_profile
			 WHERE organization_id=$1`, cfg.organizationID).Scan(
			&profileID, &profileHash, &profileGeneration, &profileFence, &profileStatus); profileErr != nil {
			fmt.Fprintf(&line, "search profile: %v\n", profileErr)
		} else {
			fmt.Fprintf(&line, "search profile: id=%s hash=%s generation=%d fence=%d status=%s\n",
				profileID, profileHash, profileGeneration, profileFence, profileStatus)
		}
		rows, queryErr := graphAdmin.Query(ctx, `
			SELECT workspace_id, workspace_revision, entity_type,
			       canonical_key_hash, source_object_id, source_version_id,
			       evidence_fragment_id
			  FROM public.canonical_entity
			 WHERE organization_id=$1
			 ORDER BY created_at DESC
			 LIMIT 12`, cfg.organizationID)
		if queryErr != nil {
			fmt.Fprintf(&line, "canonical graph query: %v\n", queryErr)
		} else {
			defer rows.Close()
			fmt.Fprintln(&line, "canonical graph rows:")
			for rows.Next() {
				var workspace, entityType, keyHash, objectID, versionID, fragmentID string
				var revision int64
				if scanErr := rows.Scan(&workspace, &revision, &entityType, &keyHash, &objectID, &versionID, &fragmentID); scanErr != nil {
					fmt.Fprintf(&line, "  (scan: %v)\n", scanErr)
					break
				}
				fmt.Fprintf(&line, "  workspace=%s revision=%d type=%s key=%s object=%s version=%s fragment=%s\n",
					workspace, revision, entityType, keyHash, objectID, versionID, fragmentID)
			}
			if rowsErr := rows.Err(); rowsErr != nil {
				fmt.Fprintf(&line, "canonical graph rows: %v\n", rowsErr)
			}
		}
	}
	return line.String()
}

// workerExecMain is the harness re-exec branch that runs the worker inside
// its chroot: chroot, drop to the runtime group and exec the worker binary.
// The process stays the same PID across exec, so the harness kill and wait
// bookkeeping keep working unchanged.
func workerExecMain() int {
	chrootDir := os.Getenv("E2E_WORKER_CHROOT")
	binaryPath := os.Getenv("E2E_WORKER_BINARY")
	if chrootDir == "" || binaryPath == "" {
		fmt.Fprintln(os.Stderr, "worker-exec: E2E_WORKER_CHROOT or E2E_WORKER_BINARY is empty")
		return 1
	}
	if err := syscall.Chroot(chrootDir); err != nil {
		fmt.Fprintf(os.Stderr, "worker-exec: chroot: %v\n", err)
		return 1
	}
	if err := syscall.Chdir("/"); err != nil {
		fmt.Fprintf(os.Stderr, "worker-exec: chdir: %v\n", err)
		return 1
	}
	// The worker runs under its own group, never the server group: clear every
	// supplementary group first so the worker cannot retain the invoking root
	// process's groups, then drop to the pinned worker runtime group and user.
	if err := syscall.Setgroups(nil); err != nil {
		fmt.Fprintf(os.Stderr, "worker-exec: setgroups: %v\n", err)
		return 1
	}
	if err := syscall.Setgid(workerRuntimeGID); err != nil {
		fmt.Fprintf(os.Stderr, "worker-exec: setgid: %v\n", err)
		return 1
	}
	if err := syscall.Setuid(workerRuntimeGID); err != nil {
		fmt.Fprintf(os.Stderr, "worker-exec: setuid: %v\n", err)
		return 1
	}
	environment := make([]string, 0, len(os.Environ()))
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "E2E_WORKER_") {
			continue
		}
		environment = append(environment, entry)
	}
	if err := syscall.Exec(binaryPath, []string{binaryPath}, environment); err != nil {
		fmt.Fprintf(os.Stderr, "worker-exec: exec: %v\n", err)
		return 1
	}
	return 1
}
