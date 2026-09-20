# S2b/S2c qualification dossier — document-parser worker (Apache POI + PDFBox)

This document preserves qualification evidence for the exact parser artifacts
identified below. It is not a current deployment checklist. The supported pilot
scope and operator activation procedure are described in [Native document
ingestion](NATIVE-INGEST.md) and [Pilot status](PILOT-STATUS.md).

The `QUALIFIED_NOT_ACTIVE` entries in `architecture/versions.json` remain the
machine-checked dependency lifecycle classification. This record neither changes
those entries nor authorizes an ACTIVE flip. That classification and the dated
checklists below must not be read as a claim that the pilot's operator-provisioned
native-ingestion path is absent. OCR, broader format fidelity and qualification
of a different artifact require their own evidence.

## 2026-09-15 candidate 2.1.0 / sandbox v3

The 2.1.0 candidate was recorded as **QUALIFIED_NOT_ACTIVE**. The older sections
below retain their original identities and results; they do not certify 2.1.0
by inheritance. Supervisor/worker installation, rollback and stand acceptance
were outside this candidate qualification run; later operational delivery must
be assessed from its own release evidence.

The 2.1.0 startup contract includes `-XX:ActiveProcessorCount=1` in the image
ENTRYPOINT itself. CPU/RAM/pids, Java library closure and observation contracts
are unchanged. The Go harness asserts and executes the same argv, image PATH
and `/app` working directory. It supplies read-only private PID-namespace proc
through bounded external `nsenter` calls before handoff, verifying its flags,
namespace, cgroup membership and non-root credentials. No hidden JVM flags or
`LD_LIBRARY_PATH` compensate for missing runtime mounts.

Two clean builds from tree `8af39acf379f70794098d8feade722456ace6aa2`
produce identical OCI archive SHA-256
`024b7e44021154a024af07caf246917b93913686a19f25a1d47a9351c75be16d`.
Their source tar timestamps differ; member contents/modes and the Git tree agree.
Manifest `sha256:bf1e580938eb62a05de1efe2cdf24d7fc8ab9339e5224be238f3794a0c9e0855`,
config `sha256:8006f7ddf504af8aee59afea5fcc719f673d7df80f6717c2ffced6b428c8d467`,
artifact `sha256:ccea6413429e0fb69d64d6065c15453fa432b9ac38e8399363ce455111eca414`.
Reproducibility receipt `.local/release/native-v3-reproducibility.json`, SHA-256
`b49abeef0b658f3655daf22821e28447fe60b14a4d274cc950cce8bc9f1e076f`.

Actual Linux/PostgreSQL tests with `KNOWVAULT_REQUIRE_REAL_V2=1` pass all four
requested roots without skips: Office format matrix (DOCX/PPTX/XLSX), Office
folder extraction, failure atomicity and PDF folder extraction. The suite
includes exact structural replay, hostile-input quarantine, deterministic
repeat sync and immutable profile upgrade. Runtime 304.132 s, 17 test/subtest
passes, zero failures/skips. Source snapshot tree
`6bc387905de9241e45a02d42eb47c5bf783e339e`, archive SHA-256
`96c2df28e6cd759fab537c7bd63cdefbe91b07b2a95de4cd99ae8c861c16cd15`.
Receipt `.local/release/native-v3-payload-proc-1789462557319/results/run-receipt.json`,
SHA-256 `cc53607c6fdd3f6f8e91e1c390f20c1dbae23aff5af07b5ad50239426173f60f`;
raw SHA-256 `5df6118ecd2b5f03054346ecc747e757b77caa6edc8ced9cddb6dabfdfa45f5c`.
This run used the test supervisor, not the then-undelivered host-service artifact.
The earlier exit-127 and namespace-check failures remain archived separately.

Syft 1.48.0 observes 20 artifacts; reconciliation checks all 17 unchanged Maven
JAR hashes and the worker JAR. Grype 0.116.0 scans the exact OCI archive and
the separately identified native libc6 PURL, with zero findings/suppressions
on database v6.1.9 built `2026-09-20T06:27:54Z`, publisher archive SHA-256
`a52051769db44825dcab6e6d4c32ffee53cdea0d456d98630b55b15ad52b16f3`.
The v2 vulnerability attestation binds OCI/config/artifact identities directly;
it makes no claim about a Docker distribution manifest. Raw image/native scan
SHA-256 values are respectively
`790ae21d73a28bcaa395171ca08234d2fac264f39dd5424cff20d19b1f19decf` and
`9e026a3f37ea79ab13fe2a98fb664aa7d58df493d98adf2574b8f269438dc926`.
Their UTC filesystem completion timestamps on the isolated scan host are
`2026-09-20T08:56:21.821693255Z` and `2026-09-20T08:56:20.346703139Z`;
the reconciled Syft JSON is
`e097a46512d116bcff428583be02b12ffad119a1976524f1ea4df8db771c2faf`
at `2026-09-20T08:56:21.637694488Z`.
The release verifier checks both scans and the shared pinned DB provenance.
The reviewed SPDX transformation documents manual identification of the
native layer and the Temurin source offer, rather than claiming auto-discovery.

## Historical qualification record — 2026-08-28 and 2026-08-29

Recorded status: **QUALIFIED_NOT_ACTIVE** — the combined Office/text-PDF worker and both
library closures passed the dependency and isolated-image qualification gates;
the production DispatcherV2 composition, ingestion lifecycle and live
Go↔Java↔PostgreSQL proof had been implemented and recorded. Release activation,
external acceptance, rollback evidence and OCR were separately gated; this
record does not authorize an ACTIVE flip. Platform lock:
`linux/amd64` only, `linux/arm64` restricted (owner 2026-07-24).

ADR-0066 applies R-16 to the qualified Office image without activating it: the
released stage is `scratch` and receives a `jlink` runtime assembled by the exact
pinned Maven/Temurin builder. The source offer, SPDX inventory and notices are
machine-checked release artifacts under `workers/document-parser/release/`.

## 1. Selected components (exact versions)

- **Apache POI `5.5.1`** — Office OOXML (DOCX/PPTX/XLSX) structure extraction.
- **Apache PDFBox `3.0.8`** — text-PDF extraction + deterministic page render.

Both confirmed as the current Maven Central `<release>` (poi-ooxml 5.5.1, pdfbox
3.0.8) on 2026-07-24.

## 2. Reproduction (offline-capable resolve)

Resolved with pinned builder
`maven:3.9-eclipse-temurin-21@sha256:8f6ac126f7810bb5549c4cd122d2bf0e9cda5bdeb0838aa928f09e779fd8bef8`
on `linux/amd64` (Maven 3.9.16, Temurin 21.0.12+8)
from a minimal POM declaring only `org.apache.poi:poi-ooxml:5.5.1` +
`org.apache.pdfbox:pdfbox:3.0.8`, via
`maven-dependency-plugin:3.8.1:copy-dependencies -DincludeScope=runtime`. The full
runtime closure is 17 artifacts; `sha256` below is of the exact resolved jar bytes.
The resolve is deterministic (fixed coordinates → fixed Central artifacts) and
re-runnable offline against a checksum-verified module cache.

## 3. Transitive runtime closure — versions, licenses, sha256

All concluded licenses are in the `architecture/licenses.yaml` `allow` set
(Apache-2.0, BSD-3-Clause). **Zero copyleft in the Java dependency closure.** The
only non-Apache node is `curvesapi` (BSD-3-Clause).

### POI (Office / OOXML) closure

| Coordinate | Version | License | sha256 (jar) |
|---|---|---|---|
| org.apache.poi:poi | 5.5.1 | Apache-2.0 | 6c52e876ca75775a11b56e4b36a7541f682827f56406725fcd87560b792ee3d8 |
| org.apache.poi:poi-ooxml | 5.5.1 | Apache-2.0 | bd7be2fdfe3fd2c1684fa813351c2798fd636b44f6236e0674500d4f8ff1c2f9 |
| org.apache.poi:poi-ooxml-lite | 5.5.1 | Apache-2.0 | e6e37adeb6d6ee8b40ec491ad955d934d8f99827ab050f105b18286e59b1d9e7 |
| org.apache.xmlbeans:xmlbeans | 5.3.0 | Apache-2.0 | 6cc69da3b4d35b83c5e477cd4daba204e44109833e34af2b9a8a2c8788289917 |
| org.apache.commons:commons-collections4 | 4.5.0 | Apache-2.0 | 00f93263c267be201b8ae521b44a7137271b16688435340bf629db1bac0a5845 |
| org.apache.commons:commons-math3 | 3.6.1 | Apache-2.0 | 1e56d7b058d28b65abd256b8458e3885b674c1d588fa43cd7d1cbb9c7ef2b308 |
| org.apache.commons:commons-compress | 1.28.0 | Apache-2.0 | e1522945218456f3649a39bc4afd70ce4bd466221519dba7d378f2141a4642ca |
| commons-codec:commons-codec | 1.20.0 | Apache-2.0 | 6af66595f9f6a7bb58ce66518d6888d40b547c366d2262f06676eee19528ff66 |
| commons-io:commons-io | 2.21.0 | Apache-2.0 | 7d643a2afea8b058b762aa6fb90e5b256f6c729739f8b3784c3370ddc609e88d |
| org.apache.commons:commons-lang3 | 3.18.0 | Apache-2.0 | 4eeeae8d20c078abb64b015ec158add383ac581571cddc45c68f0c9ae0230720 |
| com.zaxxer:SparseBitSet | 1.3 | Apache-2.0 | f76b85adb0c00721ae267b7cfde4da7f71d3121cc2160c9fc00c0c89f8c53c8a |
| com.github.virtuald:curvesapi | 1.08 | BSD-3-Clause | ad95b08b8bbf9d7d17e5e00814898fa23324f32bc5b62f1a37801e6a56ce0079 |
| org.apache.logging.log4j:log4j-api | 2.25.5 | Apache-2.0 | 64777f73ea0b3104c04eb82befbdccc30a425a19e83ad06cb2f93aa303511863 |

### PDFBox (text PDF + render) closure

| Coordinate | Version | License | sha256 (jar) |
|---|---|---|---|
| org.apache.pdfbox:pdfbox | 3.0.8 | Apache-2.0 | 97647cfbde61ebcfc06b4cf8c9b0ffcaaee073396eceb4a7f6836a9b9128903c |
| org.apache.pdfbox:pdfbox-io | 3.0.8 | Apache-2.0 | 36a0e04001010b4c764857817412b96339930b19755e728959805cc0352061b2 |
| org.apache.pdfbox:fontbox | 3.0.8 | Apache-2.0 | a1915c24e3edbe0ecec93896dfbf6d41427810b663ade97bd4e8bae86ec3fdab |
| commons-logging:commons-logging | 1.4.0 | Apache-2.0 | d175dbd751dd782a63bde28c7a039520e971f25e84b79c19b8435edc3603e0dc |

## 4. Logging surface (Log4Shell check)

POI depends on **`log4j-api` only** (the Apache-2.0 logging facade), **not
`log4j-core`**. CVE-2021-44228 (Log4Shell) and its siblings live in `log4j-core`'s
JNDI lookup, which is **absent** from this closure — no `log4j-core`, no JNDI
lookup surface. The worker binds no logging backend at all in production (the
sandbox has no network/filesystem sink); `log4j-api` without a core is inert.

## 5. Vulnerability review

**Historical scan result: no known vulnerabilities were reported for the
complete built candidate** (independent re-scan 2026-08-28). This is a dated
artifact/database result, not a claim about today's vulnerability database.

- **Scanner:** pinned `grype v0.116.0` image
  `sha256:fd4ab4d1042b522c896e73bdf09ab8bf384fa417df99d6dd0d6e1008c7e7c821`
  with a fresh database scanned the actual OCI image. Verdict:
  **"No vulnerabilities found."**
- **Coverage proof (not an empty scan):** pinned `syft v1.48.0` image
  `sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c`
  cataloged **20 components**: the worker, all **17/17** checksum-locked Java
  archives, `jrt-fs` and OpenJDK 21.0.12. The raw Syft JSON evidence hash is
  `sha256:44189102dc5f038ee9a1531e102c665433af7edf6b4c7f9d1203b0ed352b3c66`.
- The raw Grype JSON evidence hash is
  `sha256:97f3155820f1c9f91f718d689fd87483998a33be85977af22d01a8cec984e4f3`;
  the committed attestation records the exact image/database identity and the
  zero-finding result.
- **Log4Shell:** corroborated by the catalog — `log4j-api 2.25.5` present,
  **no `log4j-core`** (§4).

Re-run before the ACTIVE flip with a fresh DB and record the DB timestamp on the
lock; a new CVE against any pinned version blocks activation until triaged.

## 6. Built S2b/S2c worker image (2026-08-28)

The immutable 2.0.0 candidate supports **Office structure observation and text
PDF observation** while keeping their output contracts separate. The released
entrypoint accepts only the strict `dispatcher-once` socket contract and exits
after one lease; direct stdin/`--format` extraction is absent from the shipped
JAR and rejected as `BAD_REQUEST`. Its exact closure is the 17 artifacts in §3;
the candidate is exercised through the real DispatcherV2 and ingestion path,
but remains `QUALIFIED_NOT_ACTIVE` until release activation and external P2
acceptance are recorded.

**Lifecycle recorded for this historical candidate:** `maven.apache-poi`, `maven.apache-pdfbox` and
`oci.document-parser-worker` are `QUALIFIED_NOT_ACTIVE` in
`architecture/versions.json`, isolated to `workers/document-parser/`.
OCR was recorded as `DEFERRED`; current OCR lifecycle entries must be read from
`architecture/versions.json`, not inferred from this older Office/PDF record.

**Pinned bases (`linux/amd64`):**

| Role | Reference |
|---|---|
| Builder | `maven:3.9-eclipse-temurin-21@sha256:8f6ac126f7810bb5549c4cd122d2bf0e9cda5bdeb0838aa928f09e779fd8bef8` (Maven 3.9.16, Temurin 21.0.12+8) |
| Runtime | `scratch` with `jlink` modules `java.base,java.desktop,java.logging,java.security.jgss,java.xml.crypto` |

**Runtime closure:** verified at build time as exact digest-set equality against
`workers/document-parser/dependencies.lock.json` — **17/17 artifacts match**. The
check is set equality, not a blocklist, so an extra, missing, re-resolved or
substituted jar fails the build.

**Offline build:** only the `deps` stage has network access. Compilation,
packaging, closure verification and identity computation all run under
`RUN --network=none`, so the offline property is demonstrated by the build
failing if anything were still to be fetched, not asserted in prose.

**Deterministic rebuild:** two independent final-code `--no-cache` builds use
BuildKit's OCI exporter with `SOURCE_DATE_EPOCH=1704067200`, provenance disabled
and `rewrite-timestamp=true`. They produced the same OCI manifest
`sha256:ae99f87dc6977e206cce012a624f053e2844a77f60910126bbf185821597d9c2`,
config and eight layer digests, as well as the same `/app/artifact.sha256`.
The image lock records that single-platform `linux/amd64` manifest directly;
tag-dependent OCI-layout index metadata is deliberately not treated as a
content-addressed release identity. A rebuild with different image metadata is
a new candidate and must regenerate that lock. The
artifact identity changes when a build input changes (the POM is embedded in the
jar). `.gitattributes` pins `*.java`/`*.xml`/`*.properties` to LF so a checkout
on another platform cannot alter it.

**Artifact identity:** the image carries `/app/artifact.sha256`, computed at build
time from the digests of the exact jar set. The Go invoker refuses a result whose
declared identity is not the pinned one (proven by a negative test).
The 2.0.0 candidate identity is
`sha256:3b12599c3ada7db8174168fe0a4c685954e3068673ab1ad3e7ede63884428def`;
its locked OCI manifest/config/layer digests are recorded in `image-lock.json`.

**Hardened runtime, proven:** `--network none`, `--read-only`, tmpfs-only scratch,
non-root `65532`, `no-new-privileges`, `--memory 512m`, `--cpus 1`,
`--pids-limit 128`. Library logging is disabled at the framework level. The prior
parser-semantic candidate proved real DOCX and four-rotation PDF extraction with
0-byte stderr, deterministic output, finite in-page boxes, aggregate bounds and
content-free refusal of scanned, mixed, inline-image, active and encrypted inputs.
Because the released entrypoint is now dispatcher-only, the semantic cases are
also replayed through the real v2 Go↔Java path in the live integration matrix.
That proves the technical composition slice; the prior direct-path record alone
would not have been sufficient for release acceptance.
A hardened legacy-CLI mutation against the selected image with a live stdin canary
exited with code `2`, emitted exactly `BAD_REQUEST`, and did not echo or consume
the source-bearing canary. The same no-argument check without an external `/tmp`
mount also emitted exactly `BAD_REQUEST`; the scratch image carries an empty
mode-`1777` `/tmp`, so the JVM cannot prepend a temporary-directory warning. The
dependency-free Java subprocess harness independently
checks no-arg, legacy, mixed, duplicate and unknown argument refusal.

**Image SBOM (R-16 release artifact):** the final stage contains the worker,
the 17 checksum-locked Java archives, the stripped Temurin runtime modules and
the single native `libc6` launcher closure; it contains no Debian/Ubuntu
distribution layer. The exact SPDX package inventory is
`workers/document-parser/release/sbom.spdx.json`, and the exact image/base
construction lock is `workers/document-parser/release/image-lock.json`.
The lock binds that file by SHA-256 to both the selected OCI manifest and
`/app/artifact.sha256`. Syft `1.48.0` (image
`sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c`)
observed exactly 20 artifacts. Grype `0.116.0` (image
`sha256:fd4ab4d1042b522c896e73bdf09ab8bf384fa417df99d6dd0d6e1008c7e7c821`)
reported zero matches and zero suppressed matches using database schema `v6.1.9`,
built `2026-08-28T09:21:39Z`, archive SHA-256
`e97c0e5e87c834bde464f3039da3a142cc0874c097681d87fe8a2e910a64c5cb`.
The machine-checked record is
`workers/document-parser/release/vulnerability-attestation.json`.

### 6.1. License finding — resolved by ADR-0066; activation remains separately gated

Historical audit finding (resolved): the previous Debian JRE shipment measured
108 copyleft-declaring OS packages. That base is not copied into the final
image. The conditionally allowed shipped runtime surface is the exact OpenJDK
Classpath-exception runtime plus the one native `libc6` package, and ADR-0066 executes its
source obligation through `SOURCE-OFFER.json` and `THIRD_PARTY_NOTICES.md`.
The checker rejects a JRE-base substitution, a changed module set, a missing
source offer, a stale source commit and an SPDX closure mismatch.

This closed the JRE-base license blocker for the identified candidate. It did
not itself prove release activation, external acceptance, upgrade/rollback or
the remaining ADR-0062 §6 obligations. The present dependency classification
remains recorded in `architecture/versions.json`.

## 7. Historical qualification checklist — 2026-08-29

The checked and unchecked items preserve what that record established. They
are not a current pilot backlog; later delivery evidence does not retroactively
change this record or qualify another image. ADR-0062 §6 and ADR-0066 retain
their artifact, isolation, licensing and activation requirements.

- [x] exact versions (§1) and per-jar sha256 (§3)
- [x] full transitive runtime closure (§3)
- [x] license inventory of the Java closure — all permissive, zero copyleft (§3)
- [x] vulnerability review — selected canonical M/N scratch candidate is Grype-clean with no
      suppressed findings; Syft confirms exactly 20 runtime artifacts and both
      records are digest-bound to OCI/artifact identity (§5)
- [x] pinned builder image digest and scratch runtime strategy (`linux/amd64`) (§6, ADR-0066)
- [x] worker image build + full image SBOM (syft) (§6)
- [x] offline build/run, no network at build (§6)
- [x] non-root, read-only-fs, `--network none`, CPU/RAM/pid/input/output limits (§6)
- [x] deterministic-rebuild evidence (§6)
- [x] owner/legal decision on the base image's OS-package copyleft surface (§6.1, ADR-0066)
- [x] THIRD_PARTY_NOTICES delta and OpenJDK Classpath-exception source offer
- [ ] upgrade/rollback procedure
- [x] text-PDF worker smoke: rotation 0/90/180/270, deterministic output, bounded
      geometry, encrypted/active/scanned refusal, content-free stderr
- [x] real PostgreSQL/filesystem/image S2c qualification: `TestS2cPDFFolderExtraction`
      and `TestS2cPDFMissingOrWrongWorkerIdentityQuarantines`
- [x] re-run on the current candidate (2026-08-29): the real PostgreSQL/PDFBox
      path passed `TestS2cPDFFolderExtraction` (45.876s) and the missing-worker /
      caller-timeout quarantine proof passed `TestS2cPDFMissingOrWrongWorkerIdentityQuarantines`
      (2.670s), with `KNOWVAULT_REQUIRE_REAL_V2=1` and image
      `knowvault-document-parser:gauntlet-20260829`.
- [ ] materialize `versions.json` ACTIVE entries atomically after external P2
      acceptance, release activation and the remaining ADR-0062 §6 evidence
