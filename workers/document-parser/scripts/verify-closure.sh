#!/bin/sh
# Proves the built runtime closure is EXACTLY the qualified artifact set.
#
# It compares digest sets, not file names: every jar shipped in the image must have a
# sha256 recorded in dependencies.lock.json, every recorded sha256 must be present,
# and the counts must match. An extra artifact, a missing artifact, a re-resolved
# version or a substituted jar therefore fails the build rather than silently
# changing what the image contains.
#
# Digest-set equality is deliberately the whole test rather than a list of banned
# names: an artifact that is not in the lock fails because it is not in the lock, so
# a component that must stay out of this image cannot get in by being unnamed here.
# That is also why this script does not spell the names of components whose gate is
# still closed — naming them would put their tokens in the repository for no gain.
# The one extra assertion below is the Log4Shell surface, which is worth failing on
# by name because its absence is a security property recorded in the dossier.
set -eu

LIB_DIR="$1"
LOCK_FILE="$2"

if [ ! -d "$LIB_DIR" ]; then
    echo "closure directory missing: $LIB_DIR" >&2
    exit 1
fi

expected_digests=$(grep -o '"sha256": "[0-9a-f]\{64\}"' "$LOCK_FILE" | sed 's/.*"\([0-9a-f]\{64\}\)"/\1/' | sort)
actual_digests=$(find "$LIB_DIR" -name '*.jar' -type f -exec sha256sum {} + | awk '{print $1}' | sort)

expected_count=$(printf '%s\n' "$expected_digests" | grep -c .)
actual_count=$(printf '%s\n' "$actual_digests" | grep -c .)

if [ "$expected_count" -ne "$actual_count" ]; then
    echo "runtime closure size mismatch: expected $expected_count artifacts, image has $actual_count" >&2
    exit 1
fi

if [ "$expected_digests" != "$actual_digests" ]; then
    echo "runtime closure digest mismatch against dependencies.lock.json" >&2
    printf '%s\n' "$expected_digests" > /tmp/expected.txt
    printf '%s\n' "$actual_digests" > /tmp/actual.txt
    diff /tmp/expected.txt /tmp/actual.txt >&2 || true
    exit 1
fi

for forbidden in log4j-core; do
    if find "$LIB_DIR" -name "*${forbidden}*" -type f | grep -q .; then
        echo "forbidden artifact present in the S2b runtime closure: $forbidden" >&2
        exit 1
    fi
done

echo "runtime closure verified: $actual_count artifacts match dependencies.lock.json"
