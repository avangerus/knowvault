#!/usr/bin/env bash
set -euo pipefail

image=${1:?office worker image tag is required}
verified_archive=${2:-}
if [[ $# -gt 2 ]]; then
  echo "usage: $0 IMAGE [VERIFIED_OCI_ARCHIVE_PATH]" >&2
  exit 2
fi

# This build belongs to the PostgreSQL integration harness. The resulting image
# is a qualified, isolated test prerequisite; it is never copied into or
# referenced by a production image or composition.
expected_manifest='sha256:bf1e580938eb62a05de1efe2cdf24d7fc8ab9339e5224be238f3794a0c9e0855'
expected_config='sha256:8006f7ddf504af8aee59afea5fcc719f673d7df80f6717c2ffced6b428c8d467'
expected_artifact='sha256:ccea6413429e0fb69d64d6065c15453fa432b9ac38e8399363ce455111eca414'
expected_layers=(
  'sha256:88a11acca421df58865f88d823431f52bda8175d5e6fd1692f2a487cc08f4c70'
  'sha256:17c02ca28da47e5a67ba1947fd042307e2285f94bf2d25bc0409f58337b05faf'
  'sha256:63c13e8ea6c10b81562d53428ece2363c7bb062d5d9747c2f87bbaeea22963a0'
  'sha256:36940d4560923835ac9eeccc0143ca747fe22821bc818faef116a68b7d522889'
  'sha256:6497328e1d8bf7f489b5284b656625833be2bea7f0709bb4447810c65845465a'
  'sha256:77ab5ba073fde3c4a0b3a17426a495c37713063bb59a0816dd90b3dc86a01cd2'
  'sha256:bdc0761c2529d7d054fc5c57ac1571244b5ec959f764161d846600211af80818'
  'sha256:4f4fb700ef54461cfa02571ae0db9a0dc1e0cdb5577484a6d75e68dc38e8acc1'
)

oci_archive=$(mktemp "${TMPDIR:-/tmp}/knowvault-document-parser.XXXXXX.oci")
rm -f "$oci_archive"
oci_dir=$(mktemp -d "${TMPDIR:-/tmp}/knowvault-document-parser.XXXXXX")
loaded_archive=$(mktemp "${TMPDIR:-/tmp}/knowvault-document-parser-loaded.XXXXXX.tar")
container=''
rootfs=''
cleanup() {
  if [[ -n "$container" ]]; then
    docker rm "$container" >/dev/null 2>&1 || true
  fi
  rm -f "$oci_archive" "$loaded_archive"
  if [[ -n "$rootfs" ]]; then
    rm -f "$rootfs" "${rootfs}.files"
  fi
  rm -rf "$oci_dir"
}
trap cleanup EXIT

# Build the canonical, reproducible OCI archive first. Loading an arbitrary
# Docker image and checking RootFS.Layers would only attest uncompressed
# diffIDs, not the ordered OCI layer bytes used by the release lock.
docker buildx build \
  --file workers/document-parser/Dockerfile \
  --tag "$image" \
  --pull=false \
  --no-cache \
  --provenance=false \
  --build-arg SOURCE_DATE_EPOCH=1704067200 \
  --platform linux/amd64 \
  --output="type=oci,dest=$oci_archive,rewrite-timestamp=true" \
  workers/document-parser

# Check the archive's exact platform manifest, config and ordered compressed
# layer digests before Docker can load or retag it. Python is used only as a
# JSON parser so this remains independent of jq availability.
tar -xf "$oci_archive" -C "$oci_dir"
python3 - "$oci_dir" "${expected_manifest#sha256:}" "$expected_config" "${expected_layers[@]}" <<'PY'
import hashlib
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
expected_manifest = "sha256:" + sys.argv[2]
expected_config = sys.argv[3]
expected_layers = sys.argv[4:]

def blob(digest):
    algorithm, value = digest.split(":", 1)
    if algorithm != "sha256" or len(value) != 64:
        raise SystemExit(f"invalid OCI digest: {digest!r}")
    path = root / "blobs" / algorithm / value
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != value:
        raise SystemExit(f"OCI blob hash mismatch: {digest}")
    return data

index = json.loads((root / "index.json").read_text(encoding="utf-8"))
descriptors = index.get("manifests", [])
if len(descriptors) != 1 or descriptors[0].get("digest") != expected_manifest:
    raise SystemExit(f"unexpected OCI platform manifest: {descriptors!r}")

manifest_digest = descriptors[0]["digest"].split(":", 1)[1]
manifest = json.loads(blob(expected_manifest).decode("utf-8"))
config = manifest.get("config", {}).get("digest")
if config != expected_config:
    raise SystemExit(f"unexpected OCI config: {config!r}")
blob(config)

layers = [layer.get("digest") for layer in manifest.get("layers", [])]
if layers != expected_layers:
    raise SystemExit(f"unexpected ordered OCI layers: {layers!r}")
for layer in layers:
    blob(layer)
PY

docker load --input "$oci_archive"
repo_digest=$(docker image inspect "$image" --format '{{index .RepoDigests 0}}')
case "$repo_digest" in
  *"@$expected_manifest") ;;
  *) echo "unexpected loaded image manifest: $repo_digest" >&2; exit 1 ;;
esac
# Docker's Image.Id is not stable across engine versions (some engines expose
# the OCI manifest digest there). Re-export the loaded image and mechanically
# verify the config descriptor while the RepoDigest above verifies the exact
# manifest descriptor. The pre-load OCI check remains the source of truth for
# ordered compressed layer digests.
docker save --output "$loaded_archive" "$image"
python3 - "$loaded_archive" "${expected_config#sha256:}" <<'PY'
import hashlib
import json
import pathlib
import sys
import tarfile

archive = pathlib.Path(sys.argv[1])
expected = sys.argv[2]
allowed_names = {expected + ".json", "blobs/sha256/" + expected}
max_config_bytes = 2 * 1024 * 1024
with tarfile.open(archive) as tar:
    manifests = json.loads(tar.extractfile("manifest.json").read())
if len(manifests) != 1 or manifests[0].get("Config") not in allowed_names:
    raise SystemExit(f"unexpected loaded OCI config: {manifests!r}")
config_name = manifests[0]["Config"]
with tarfile.open(archive) as tar:
    matches = [member for member in tar.getmembers() if member.name == config_name]
    if len(matches) != 1 or not matches[0].isreg():
        raise SystemExit(f"loaded OCI config is not one regular file: {config_name!r}")
    member = matches[0]
    if member.size > max_config_bytes:
        raise SystemExit(f"loaded OCI config exceeds {max_config_bytes} bytes")
    config_stream = tar.extractfile(member)
    if config_stream is None:
        raise SystemExit(f"unable to read loaded OCI config: {config_name!r}")
    config_bytes = config_stream.read(max_config_bytes + 1)
if len(config_bytes) > max_config_bytes or len(config_bytes) != member.size:
    raise SystemExit(f"loaded OCI config size mismatch: {config_name!r}")
actual = hashlib.sha256(config_bytes).hexdigest()
if actual != expected:
    raise SystemExit(f"loaded OCI config hash mismatch: expected {expected}, got {actual}")
PY

# R-16 smoke: prove the built candidate is the scratch+jlink shape, not merely a
# Dockerfile that mentions it. The actual Office integration below then exercises
# the Java process over the sandbox boundary with real documents.
container=$(docker create "$image")
rootfs=$(mktemp)
docker export --output "$rootfs" "$container"
tar -tf "$rootfs" > "${rootfs}.files"
grep -qx 'opt/jre/bin/java' "${rootfs}.files"
grep -qx 'app/artifact.sha256' "${rootfs}.files"
grep -qx 'lib/x86_64-linux-gnu/libc.so.6' "${rootfs}.files"
grep -qx 'tmp/' "${rootfs}.files"
# Docker injects /etc/{hostname,hosts,resolv.conf} at run/export time; the
# forbidden distribution trees are /usr, /bin and /sbin.
! grep -Eq '^(usr|bin|sbin)/' "${rootfs}.files"
artifact=$(tar -xOf "$rootfs" app/artifact.sha256 | tr -d '\r\n')
test "$artifact" = "$expected_artifact"

# Confirm the selected JRE is executable from the loaded image while retaining
# the release image's non-root user and scratch filesystem shape.
docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --security-opt no-new-privileges --memory 64m --cpus 0.1 --pids-limit 16 \
  --entrypoint /opt/jre/bin/java "$image" -XX:ActiveProcessorCount=1 -version >/dev/null

# The image owns its empty /tmp directory. Even under a read-only root and
# without an externally supplied tmpfs, malformed invocation must stay
# content-free and must not gain a JVM temporary-directory warning prefix.
set +e
bad_request=$(docker run --rm --network none --read-only \
  --security-opt no-new-privileges --memory 64m --cpus 0.1 --pids-limit 16 \
  "$image" 2>&1)
bad_request_status=$?
set -e
test "$bad_request_status" -eq 2
test "$bad_request" = 'BAD_REQUEST'

# The only supported image invocation is the one-shot dispatcher contract. A
# missing socket makes this smoke intentionally fail after argument validation;
# importantly, it exercises the image ENTRYPOINT with --mode=dispatcher-once and
# never opens the retired direct-stdin parser interface.
set +e
output=$(docker run --rm --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --security-opt no-new-privileges --memory 64m --cpus 0.1 --pids-limit 16 \
  "$image" --mode=dispatcher-once \
  --socket=unix:///run/knowvault/missing.sock --worker-id=prepare-smoke-office \
  --parser-type=OFFICE --supervisor-handoff-id=prepare-smoke-handoff-00000000000000000000000000000001 2>&1)
status=$?
set -e
test "$status" -ne 0

# Keep the archive used by CI scanners only after every build, archive, loaded
# image, JVM, and invocation check above has succeeded. O_EXCL prevents replacing
# a prior scan artifact; a failed copy removes only the file created here.
if [[ -n "$verified_archive" ]]; then
  python3 - "$oci_archive" "$verified_archive" <<'PY'
import os
import stat
import sys

source, destination = sys.argv[1:]
fd = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
created = os.fstat(fd)
try:
    os.fchmod(fd, 0o644)
    with os.fdopen(fd, "wb") as output, open(source, "rb") as input_file:
        while True:
            chunk = input_file.read(1024 * 1024)
            if not chunk:
                break
            output.write(chunk)
except BaseException:
    try:
        current = os.stat(destination, follow_symlinks=False)
        if stat.S_ISREG(current.st_mode) and (current.st_dev, current.st_ino) == (created.st_dev, created.st_ino):
            os.unlink(destination)
    except FileNotFoundError:
        pass
    raise
PY
fi
