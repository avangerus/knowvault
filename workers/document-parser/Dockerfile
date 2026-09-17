# Isolated document-parser worker image (ADR-0062 + ADR-0066, P2/I2/S2b+S2c).
#
# Platform lock: linux/amd64 only; linux/arm64 is explicitly restricted.
# The only external base is the pinned builder. The shipped stage is scratch and
# receives a jlink runtime assembled from that builder, so no Debian/Ubuntu
# distribution layer is copied into the released image; only the libc6 native
# launcher closure is carried explicitly.
#
# The build is offline-reproducible in a checkable way rather than by assertion:
# the `deps` stage warms the local repository with network access, and every later
# stage runs with `--network=none`, so compilation, packaging, closure verification
# and identity computation provably download nothing. If an artifact were missing
# from the warmed repository the offline stage would fail instead of reaching out.
#
# The 2.1.0 candidate supports Office and text PDF in one immutable worker image.
# Office keeps document-parser-result-v1; PDF emits pdf-parser-result-v1. What this
# image may contain is defined positively by dependencies.lock.json and enforced by
# scripts/verify-closure.sh as exact digest-set equality. Optional PDFBox crypto
# providers are not runtime dependencies and are intentionally outside the image.

# Apache Maven 3.9.16, Eclipse Temurin 21.0.12+8, linux/amd64.
# This refreshed builder is required by the current vulnerability review.
FROM maven:3.9-eclipse-temurin-21@sha256:8f6ac126f7810bb5549c4cd122d2bf0e9cda5bdeb0838aa928f09e779fd8bef8 AS deps
WORKDIR /build
COPY pom.xml ./
COPY src ./src
# Network is permitted ONLY here, to populate the local repository.
RUN mvn -B -q -Dmaven.repo.local=/m2 package

FROM deps AS build
COPY dependencies.lock.json ./
COPY scripts/verify-closure.sh /usr/local/bin/verify-closure
# Offline from here on: a download attempt fails the build.
RUN --network=none rm -rf /build/target \
    && mvn -o -B -q -Dmaven.repo.local=/m2 package
# The module deliberately has no JUnit dependency, so execute the deterministic
# Office/PackageGuard harness explicitly during the offline build. This keeps the
# valid PPTX/XLSX and hostile-package regressions as an image-build gate rather
# than relying on Maven's empty test phase.
RUN --network=none java \
    -Dlog4j2.loggerContextFactory=org.apache.logging.log4j.simple.SimpleLoggerContextFactory \
    -Dlog4j2.simplelogLevel=OFF \
    -Dlog4j2.defaultStatusLevel=OFF \
    -Dlog4j2.status.entries=0 \
    -cp /build/target/test-classes:/build/target/classes:/build/target/lib/'*' \
    local.knowvault.docparser.OfficeObserverHarness
# Keep the one-shot dispatcher registration/lease protocol harness as an offline
# image-build gate alongside the Office/package observer regression harness.
RUN --network=none java \
    -Dlog4j2.loggerContextFactory=org.apache.logging.log4j.simple.SimpleLoggerContextFactory \
    -Dlog4j2.simplelogLevel=OFF \
    -Dlog4j2.defaultStatusLevel=OFF \
    -Dlog4j2.status.entries=0 \
    -cp /build/target/test-classes:/build/target/classes:/build/target/lib/'*' \
    local.knowvault.docparser.DispatcherProtocolV2Harness
RUN --network=none sh /usr/local/bin/verify-closure /build/target/lib /build/dependencies.lock.json
# The artifact identity the worker reports: sha256 over the digests of the exact 17-jar
# set, sorted by path. It is computed from what was built, so it cannot be asserted.
RUN --network=none sh -c 'cd /build/target \
    && { sha256sum document-parser-worker.jar; sha256sum lib/*.jar; } \
    | sort -k2 | sha256sum | cut -d" " -f1 | sed "s/^/sha256:/" > artifact.sha256'

# R-16: derive the exact runtime module set from the qualified closure and ship
# only the stripped JVM modules used by the worker. The module list is locked in
# architecture/versions.json and release/image-lock.json.
RUN --network=none jlink --module-path "$JAVA_HOME/jmods" --add-modules java.base,java.desktop,java.logging,java.security.jgss,java.xml.crypto --strip-debug --no-man-pages --no-header-files --compress=2 --output /build/jre

# A HotSpot launcher is dynamically linked. Copy only the exact native loader
# closure needed by `java`; these files are the libc6 package recorded in the
# SPDX/source-compliance artifacts, not an OS distribution layer.
RUN --network=none mkdir -p /build/native/lib/x86_64-linux-gnu /build/native/lib64 /build/runtime-tmp \
    && cp -L /lib/x86_64-linux-gnu/libc.so.6 /build/native/lib/x86_64-linux-gnu/libc.so.6 \
    && cp -L /lib/x86_64-linux-gnu/libpthread.so.0 /build/native/lib/x86_64-linux-gnu/libpthread.so.0 \
    && cp -L /lib/x86_64-linux-gnu/libdl.so.2 /build/native/lib/x86_64-linux-gnu/libdl.so.2 \
    && cp -L /lib/x86_64-linux-gnu/librt.so.1 /build/native/lib/x86_64-linux-gnu/librt.so.1 \
    && cp -L /lib/x86_64-linux-gnu/libm.so.6 /build/native/lib/x86_64-linux-gnu/libm.so.6 \
    && cp -L /lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 /build/native/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 \
    && cp -L /lib64/ld-linux-x86-64.so.2 /build/native/lib64/ld-linux-x86-64.so.2 \
    && chmod 1777 /build/runtime-tmp

# R-16: the final image has no OS package base. The OpenJDK runtime and its
# source offer/notice are recorded in the release artifacts checked by CI.
FROM scratch AS runtime

COPY --from=build /build/jre /opt/jre
COPY --from=build /build/native/lib/x86_64-linux-gnu /lib/x86_64-linux-gnu
COPY --from=build /build/native/lib64 /lib64
COPY --from=build /build/target/document-parser-worker.jar /app/document-parser-worker.jar
COPY --from=build /build/target/lib /app/lib
COPY --from=build /build/target/artifact.sha256 /app/artifact.sha256
COPY --from=build /build/runtime-tmp /tmp

# Non-root. The runtime is additionally started with --network none, a read-only
# root filesystem, a tmpfs scratch, no-new-privileges and CPU/RAM/pids caps by the
# Go invoker; none of those capabilities exist inside the image to begin with.
USER 65532:65532
WORKDIR /app

# Logging is switched off at the framework level, not merely unconfigured: the
# extraction library logs through the log4j facade, and a default provider could
# write a fragment of the document to stderr. A silenced simple context factory
# keeps the content-free rule (ADR-0062 §2d) true even for library diagnostics.
ENTRYPOINT ["/opt/jre/bin/java", \
    "-XX:ActiveProcessorCount=1", \
    "-XX:MaxRAMPercentage=75.0", \
    "-XX:+ExitOnOutOfMemoryError", \
    "-Dlog4j2.loggerContextFactory=org.apache.logging.log4j.simple.SimpleLoggerContextFactory", \
    "-Dlog4j2.simplelogLevel=OFF", \
    "-Dlog4j2.defaultStatusLevel=OFF", \
    "-Dlog4j2.status.entries=0", \
    "-Djava.awt.headless=true", \
    "-Dfile.encoding=UTF-8", \
    "-Djava.io.tmpdir=/tmp", \
    "-Duser.language=en", \
    "-Duser.country=US", \
    "-cp", "/app/document-parser-worker.jar:/app/lib/*", \
    "local.knowvault.docparser.Main"]
