# ADR-0066: Parser runtime license decoupling (R-16)

Status: accepted.

This ADR applies the owner's ADR-D decision to the already-qualified isolated
document-parser worker. It does not activate Office/PDF/OCR, change the worker's
production reachability, or close the P2 phase gate. It composes with ADR-0062;
the worker remains `QUALIFIED_NOT_ACTIVE` until that ADR's independent parser
qualification and composition gates are accepted.

## 1. Decision

The shipped parser image is built in two distinct classes of stage:

1. a linux/amd64 Maven + Eclipse Temurin builder pinned by the exact digest in
   `architecture/versions.json`; and
2. a final `scratch` stage containing only the application, its checksum-locked
   Apache POI runtime closure and a stripped `jlink` OpenJDK runtime.

The runtime module set is closed and recorded in the version lock, image lock
and source-compliance manifest:

`java.base`, `java.desktop`, `java.logging`, `java.security.jgss`,
`java.xml.crypto`.

The final image therefore does not ship the Debian JRE base or its broad OS
package surface. HotSpot still needs a dynamically linked launcher, so the
image carries the single exact amd64 `libc6` native package recorded in the
SPDX/source-compliance artifacts. The OpenJDK runtime remains under
`GPL-2.0-only WITH Classpath-exception-2.0`; the source offer is pinned to the
OpenJDK update commit recorded in
`workers/document-parser/release/source-compliance/openjdk-temurin-21.0.11+10/SOURCE-OFFER.json`.

## 2. Mechanical compliance boundary

The R-16 release package is:

- `workers/document-parser/release/image-lock.json`;
- `workers/document-parser/release/sbom.spdx.json`;
- `workers/document-parser/release/THIRD_PARTY_NOTICES.md`; and
- the OpenJDK source-offer manifest named by the image lock.

`checkParserRuntimeCompliance` requires all four artifacts, exact path and
version bindings, the pinned builder, the scratch final stage, the locked
module set, the complete Maven closure, the OpenJDK Classpath-exception record,
and the absence of Debian/Ubuntu or standalone GPL/LGPL packages. The same
check runs adversarial mutations for a runtime-base swap, image-lock strategy
drift and source-offer drift. Any missing prerequisite is a build failure.

The final Docker stage is not treated as proof merely because it says
`scratch`: the image is built and smoke-run by the mandatory parser-worker
qualification path, while the release artifacts are checked independently by
the architecture gate.

## 3. License-policy change

The conditional license allowance in `architecture/licenses.yaml` is scoped to
the pinned, jlink-stripped OpenJDK runtime used only by this isolated worker and
requires the accepted license ADR plus the third-party notice/source-offer
package. The generic GPL/LGPL deny rules remain unchanged. Apache POI's exact
runtime closure remains separately checksum-locked and permissively licensed.

## 4. Consequences and limits

Positive: the released parser layer has no Debian/Ubuntu distribution layer, the
copyleft surface is reduced to the exact OpenJDK runtime plus one native libc6
unit, and source
compliance cannot be claimed without a machine-readable offer, notices and
SPDX closure.

The builder image is build-only and is not copied into the final image. The
final image remains linux/amd64 only. The worker is still isolated and
`QUALIFIED_NOT_ACTIVE`; no production connector, enqueue path, viewer path or
Office/PDF user capability is activated by this ADR.

## 5. Acceptance evidence

- `architecture/versions.json` binds the exact builder, `scratch`, `jlink`,
  module set and compliance manifest.
- `workers/document-parser/Dockerfile` builds the JAR closure offline after the
  dependency stage and assembles the final runtime with `jlink`.
- The R-16 release package is checked by the architecture gate, including
  fail-closed mutation cases.
- The worker image is smoke-tested separately; activation and the P2 phase gate
  remain external acceptance decisions.
