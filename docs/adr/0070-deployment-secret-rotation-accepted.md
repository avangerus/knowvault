# ADR-0070: Deployment secret generation, rotation and recovery procedure (D7-11)

Status: accepted.

Extends ADR-0055: the transient two-version read window during envelope
rotation is introduced by this ADR. ADR-0055 itself defines no such window —
it holds exactly one key reference/version and a readiness preflight fails
closed when active artifacts exist under a version the backend cannot provide.
ADR-0055 remains the current authority for the wrap backend except where this
ADR explicitly overrides it.

ADR-0069 fixed the deployment/operations boundary and deliberately left the
key/secret lifecycle to a separate procedure. ADR-0065 §3 made the fifth mounted
capability `source_digest_hmac` conditional on the owner confirming the
mounted-secret manifest rollout and updating the deployment secret
generation/rotation procedure. ENCRYPTION.md §1/§2/§4 still name an external
KMS/HSM, which conflicts with the owner decision ADR-P1.11 (file-based keys, no
HSM/KMS in 1.0). This ADR records that procedure. It creates no operator command
and closes no milestone until the operator implements it with the D7-11 proofs;
the same reservation ADR-0069 states for deployment tooling applies here.

## 1. Decision

1. **Secret inventory and generation.** One versioned secret manifest, owned by
   the operator binary, enumerates (a) the five mounted capabilities —
   `IdentityKey`, `SessionKey`, `OIDCTransportKey` (ADR-0041), `ArtifactWrapKey`
   (ADR-0055), `source_digest_hmac` (ADR-0065 §3) — and (b) deployment secrets
   (database role credentials, test-IdP client secret). Generation is an
   operator command writing files under the ADR-0035 mounted-secret boundary:
   each file is written to a temporary name, chmod to the exact ADR-0035 mode
   (0400; or 0440 with a root-owned dedicated server GID per ADR-0035) and
   atomically renamed into place; O_NOFOLLOW, fstat, one link and exact file
   count are re-validated after the rename. Preflight validates the all-zero
   rejection (ADR-0038), purpose typing and non-convertibility (ADR-0041) and
   the exact manifest match; any mismatch is a typed startup refusal (ADR-0069).

2. **Rotation domains.** The closeable crypto owners (ADR-0038) already give the
   operational domain — identity/session HMAC and OIDC transport AES — in-place
   rotation with close/zeroize and no data migration: provision new key files,
   drain, close the old owner, verify the zero fingerprint. `IdentityKey` is
   validated at preflight and never rotated by the operator procedure. The two
   content-bound keys rotate only through the procedures below. ADR-0055 holds
   exactly one `ArtifactWrapKey` reference/version outside the rotation window;
   the envelope rotation framework is the new part this ADR introduces.

3. **Envelope KEK rotation — two-phase (ADR-P1.11).** `begin`:
   `key_version++`; the wrap backend accepts both versions for reads and writes
   new wraps under the new version only; a fenced background re-wrap pass on the
   S1b jobs substrate (leases/heartbeat/retry/fencing/crash-recovery) rewrites
   every DEK wrapper to the new version; the pass is idempotent and resumable.
   `complete` runs only when zero wrappers remain under the old version: it
   atomically switches the single active key reference/version, archives the old
   key material encrypted with an audit event, and closes the old version.
   Unknown key version fails closed. A repeat rotation is idempotent (D7-11).
   The whole rotation window binds to NFR-B1/B2 (D8-10: ≤15 min of lost updates /
   ≤2 h restore); the re-wrap pass must fit inside the B1 window and the audit
   trail must make the window observable.

4. **Digest rotation (ADR-P1.11 + ENCRYPTION.md §2 mechanics).**
   `digest_key_version++` with a generation fence: new projections are written
   under the new version; the background recompute replays mutations to the
   watermark and re-projects the organization-scoped HMAC digests; old
   projections stay readable until recompute completes (EVD projections must not
   break citations); then the active digest version switches atomically and old
   digests are removed. Unknown version fail closed. Purge must not leave a
   usable hash oracle (IMPLEMENTATION_PLAN owner decision).

5. **Recovery bundle and drill.** The operator backup command writes an
   encrypted bundle whose key material is wrapped by a separate recovery key
   stored outside the bundle; the bundle never contains source binaries, clear
   DEK, recovery-key material or signing private keys (ENCRYPTION.md §4).
   Restore without the correct recovery key fails closed with a typed error and
   never performs a partial restore under another organization key (ADR-0069;
   ENCRYPTION.md §4). A restore drill is a mandatory procedure step: restore
   into a clean environment plus negative tests (missing key, wrong key,
   tampered bundle). The drill must demonstrate the NFR-B2 window (D8-10:
   ≤2 h restore) and record the measured time.

6. **Acceptance binding (D7-11).** When the rotation implementation lands, the
   mutation registry receives entries executed on real PostgreSQL: weakening the
   fencing or the zero-wrappers completion precondition turns the rotation test
   red; rotation → zero lost artifacts (negative); repeat rotation idempotent;
   the restore drill demonstrates the B2 window. Until then this ADR is
   normative preparation, not a claim that rotation tooling exists.

7. **Reconciliation.** ENCRYPTION.md §1 «secrets/signing private keys only in external KMS/secret provider/HSM» and §2 «Key is in external KMS» are reconciled to file-based mounted secrets per ADR-P1.11; §4 «KMS credential» / «correct KMS key» become recovery-bundle terms. This ADR updates the deployment secret generation/rotation procedure — the second conjunct of the ADR-0065 §3 condition. The first conjunct (owner confirmation of the mounted-secret manifest rollout) is not satisfied by this ADR itself and remains an owner check before `source_digest_hmac` is production-composed.

## 2. Consequences

The operator surface grows a secrets-generation, rotation and recovery contract
with typed errors and code-to-action mapping (ADR-0069). Rotation is never
silent and never a known-risk: it either follows the two-phase procedure with
audit events or fails closed. Backup/restore cannot reintroduce key material
into artifacts, and restore readiness stays gated on the negative checks of
ADR-0069. D7-11, the NFR-B1/B2 windows (D8-10) and the CRY-* mutation
expectations (ADR-P1.11) bind the rotation implementation to the
real-PostgreSQL CI. The fifth mounted capability becomes production-composed
only after both ADR-0065 §3 conjuncts hold.
