#!/usr/bin/env bash
# Provision the tenant-bound reranking capability mount and its dedicated PKI.
# This script PREPARES files and one named cache volume. It starts no service,
# reads no credential, writes no database row, and sources no .env.
#
# Usage: bash reranking-bootstrap.sh --organization-id org_001 [--dry-run]
#
# Layout it owns (fixed, relative to this script's own Compose directory):
#   reranking-profile.json          fixed source profile (Compose dir literal)
#   pki/reranking/                  root:65532 0750
#   pki/reranking/ca.key            root:65532 0600  (dedicated CA private key,
#                                     stored protected on the server)
#   pki/reranking/ca.crt            root:65532 0440
#   pki/reranking/server.crt        root:65532 0440
#   pki/reranking/server.key        root:65532 0440
#   mounts/server/reranking/         root:65532 0750  (profile + mTLS mount)
#     profile.json manifest.json root-ca.pem client-cert.pem client-key.pem
#                                     root:65532 0440 each
#
# The pki/ parent directory is owned by other components; this script never
# chmods or chowns it.
#
# The server validates the full canonical profile hash at startup, so this
# script only needs a literal hash check, not a JSON parser.
set -euo pipefail

PROFILE_HASH='sha256:f49bfa0a59e197b52f371361f5203a0e928b285433b2bcf33c909426da547cec'
MOUNT_GID=65532
CACHE_VOLUME='knowvault-reranking-cache'
HELPER_IMAGE='golang:1.26.5-bookworm@sha256:e60d708a92ad26a6d61901334510d3debd23ddcba125663ecd6008d42e8ec669'
PROFILE_FILE='reranking-profile.json'
MANIFEST_SCHEMA='knowvault-reranking-manifest-v1'

die() { echo "reranking-bootstrap: $*" >&2; exit 1; }
ok()  { echo "reranking-bootstrap: $*"; }

# ---- argument parsing -----------------------------------------------------
DRY_RUN=false
ORGANIZATION_ID=''
while [ $# -gt 0 ]; do
  case "$1" in
    --organization-id) [ $# -ge 2 ] || die "--organization-id needs a value"; ORGANIZATION_ID="$2"; shift 2 ;;
    --organization-id=*) ORGANIZATION_ID="${1#*=}"; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown argument: $1 (accepted: --organization-id ID, --dry-run)" ;;
  esac
done
[ -n "$ORGANIZATION_ID" ] || die "missing --organization-id ID"
if ! printf '%s' "$ORGANIZATION_ID" | grep -Eq '^[A-Za-z0-9_-]{1,128}$'; then
  die "organization id must match ^[A-Za-z0-9_-]{1,128}\$"
fi

# ---- confine to this script's own Compose directory (realpath) ------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
BASE="$SCRIPT_DIR"
SOURCE_PROFILE="$BASE/$PROFILE_FILE"
[ -f "$SOURCE_PROFILE" ] || die "fixed source profile not found: $SOURCE_PROFILE"
grep -qF "\"profile_hash\": \"$PROFILE_HASH\"" "$SOURCE_PROFILE" \
  || die "source profile does not carry the required profile_hash literal"

PKI_DIR="$BASE/pki/reranking"
MOUNT_DIR="$BASE/mounts/server/reranking"

# Planned artefacts, shared by dry-run and the real path.
PLANNED_FILES="$(cat <<EOF
  $BASE/pki/reranking/              root:$MOUNT_GID  0750  (directory)
  $BASE/pki/reranking/ca.key        root:$MOUNT_GID  0600  (CA private key)
  $BASE/pki/reranking/ca.crt        root:$MOUNT_GID  0440
  $BASE/pki/reranking/server.crt    root:$MOUNT_GID  0440
  $BASE/pki/reranking/server.key    root:$MOUNT_GID  0440
  $BASE/mounts/server/reranking/    root:$MOUNT_GID  0750  (directory)
  $BASE/mounts/server/reranking/profile.json          root:$MOUNT_GID 0440
  $BASE/mounts/server/reranking/root-ca.pem           root:$MOUNT_GID 0440
  $BASE/mounts/server/reranking/client-cert.pem       root:$MOUNT_GID 0440
  $BASE/mounts/server/reranking/client-key.pem        root:$MOUNT_GID 0440
  $BASE/mounts/server/reranking/manifest.json         root:$MOUNT_GID 0440
  docker volume: $CACHE_VOLUME (uid 1000, /cache mode 0750)
EOF
)"

# Reject a symlinked artefact or the fixed source profile: this script never
# follows a link out of $BASE.
reject_symlink() { [ -L "$1" ] && die "refusing symlinked path: $1"; return 0; }
for p in "$BASE/pki" "$PKI_DIR" "$BASE/mounts" "$BASE/mounts/server" "$MOUNT_DIR" "$SOURCE_PROFILE"; do
  reject_symlink "$p"
done

if [ "$DRY_RUN" = "true" ]; then
  echo "DRY RUN: no file, no directory, no volume, no container will be written."
  echo "organization_id: $ORGANIZATION_ID"
  echo "compose directory: $BASE"
  echo "planned preparation:"
  printf '%s\n' "$PLANNED_FILES"
  echo "helper image (inspected, not pulled or run here): $HELPER_IMAGE"
  exit 0
fi

# ---- real preparation -----------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "actual preparation requires UID 0 (use --dry-run otherwise)"
for tool in openssl install chmod chown sha256sum mv rmdir docker; do
  command -v "$tool" >/dev/null 2>&1 || die "required tool not found: $tool"
done
openssl version >/dev/null 2>&1 || die "openssl is not usable"

# Helper image must already be provisioned: never pull, never download.
docker image inspect "$HELPER_IMAGE" >/dev/null 2>&1 \
  || die "helper image not present locally (provision it first): $HELPER_IMAGE"

# Idempotence fast path: a prepared mount must fully match, or we stop.
expected_manifest() { # emit the exact compact manifest line (with newline)
  cat <<EOF
{"schema":"$MANIFEST_SCHEMA","organization_id":"$ORGANIZATION_ID","profile_file":"profile.json","profile_hash":"$PROFILE_HASH","root_ca_file":"root-ca.pem","client_certificate_file":"client-cert.pem","client_key_file":"client-key.pem"}
EOF
}

manifest_matches_tenant() { # tenant mount manifest must equal the expected bytes
  cmp -s "$MOUNT_DIR/manifest.json" <(expected_manifest)
}

# A directory path: must be a real directory (never a symlink), with the exact
# owner:group:mode. Rejects symlinks. Directory link counts are not tested:
# a normal Linux directory legitimately has nlink >= 2 (".", "..", subdirs).
strict_dir_mode() { # path uid gid mode
  local st
  [ ! -L "$1" ] || return 1
  st="$(stat -c %u:%g:%a:%F "$1" 2>/dev/null)" || return 1
  [ "$st" = "$2:$3:$4:directory" ]
}

# A file path: must be a regular, single-link file with the exact
# owner:group:mode. Rejects symlinks (never a regular file) and hardlinks
# (st_nlink must be 1).
strict_file_mode() { # path uid gid mode
  local st
  [ ! -L "$1" ] || return 1
  st="$(stat -c '%u:%g:%a:%F:%h' "$1" 2>/dev/null)" || return 1
  case "$st" in
    "$2:$3:$4:regular file:1") return 0 ;;
    "$2:$3:$4:regular empty file:1") return 0 ;;
    *) return 1 ;;
  esac
}

# Verify the CA/leaf key material is mutually consistent without printing any
# private key: each public key must equal the public key of its private key,
# and the leaves must chain to the CA with the right extended key usage.
pki_keys_consistent() { # pki-dir
  local d="$1"
  openssl x509 -in "$d/ca.crt" -noout -checkend 0 >/dev/null 2>&1 || return 1
  openssl x509 -in "$d/server.crt" -noout -checkend 0 >/dev/null 2>&1 || return 1
  # openssl verify authenticates the issuer cryptographically; comparing the
  # textual issuer=/subject= strings is redundant (prefix formats differ).
  openssl verify -purpose sslserver -verify_hostname knowvault-reranking -CAfile "$d/ca.crt" "$d/server.crt" >/dev/null 2>&1 || return 1
  # CA public key matches CA private key
  [ "$(openssl x509 -in "$d/ca.crt" -noout -pubkey)" = "$(openssl pkey -in "$d/ca.key" -pubout 2>/dev/null)" ] || return 1
  # server public key matches server private key
  [ "$(openssl x509 -in "$d/server.crt" -noout -pubkey)" = "$(openssl pkey -in "$d/server.key" -pubout 2>/dev/null)" ] || return 1
}

validate_prepared_state() {
  local f
  strict_dir_mode "$MOUNT_DIR" 0 "$MOUNT_GID" 750 || return 1
  for f in profile.json manifest.json root-ca.pem client-cert.pem client-key.pem; do
    strict_file_mode "$MOUNT_DIR/$f" 0 "$MOUNT_GID" 440 || return 1
  done
  cmp -s "$SOURCE_PROFILE" "$MOUNT_DIR/profile.json" || return 1
  grep -qF "\"profile_hash\": \"$PROFILE_HASH\"" "$MOUNT_DIR/profile.json" || return 1
  strict_dir_mode "$PKI_DIR" 0 "$MOUNT_GID" 750 || return 1
  strict_file_mode "$PKI_DIR/ca.key" 0 "$MOUNT_GID" 600 || return 1
  strict_file_mode "$PKI_DIR/ca.crt" 0 "$MOUNT_GID" 440 || return 1
  strict_file_mode "$PKI_DIR/server.crt" 0 "$MOUNT_GID" 440 || return 1
  strict_file_mode "$PKI_DIR/server.key" 0 "$MOUNT_GID" 440 || return 1
  manifest_matches_tenant || return 1
  # Mounted CA must be byte-identical to the published PKI CA.
  cmp -s "$MOUNT_DIR/root-ca.pem" "$PKI_DIR/ca.crt" || return 1
  # The mounted client certificate/key must chain to the CA and form a pair.
  openssl verify -purpose sslclient -CAfile "$PKI_DIR/ca.crt" "$MOUNT_DIR/client-cert.pem" >/dev/null 2>&1 || return 1
  [ "$(openssl x509 -in "$MOUNT_DIR/client-cert.pem" -noout -pubkey)" = "$(openssl pkey -in "$MOUNT_DIR/client-key.pem" -pubout 2>/dev/null)" ] || return 1
  pki_keys_consistent "$PKI_DIR" || return 1
}

# Named cache volume for UID 1000 via the pinned helper image. Idempotent:
# an already-correct volume is left untouched. Never pulls/downloads (the
# pinned image must already be present locally).
ensure_cache_volume() {
  if ! docker volume inspect "$CACHE_VOLUME" >/dev/null 2>&1; then
    docker volume create "$CACHE_VOLUME" >/dev/null || die "volume create failed: $CACHE_VOLUME"
  fi
  docker run --rm \
    --read-only \
    --network none \
    --cap-drop ALL --cap-add CHOWN --cap-add DAC_OVERRIDE \
    --memory 64m --cpus 0.25 \
    -v "$CACHE_VOLUME:/cache" \
    "$HELPER_IMAGE" \
    sh -c 'chown 1000:1000 /cache && chmod 0750 /cache' \
    || die "cache volume initialization failed"
}

if [ -f "$MOUNT_DIR/manifest.json" ]; then
  if validate_prepared_state; then
    ensure_cache_volume
    docker volume inspect "$CACHE_VOLUME" >/dev/null 2>&1 \
      || die "cache volume absent after initialization: $CACHE_VOLUME"
    ok "tenant mount and PKI unchanged for $ORGANIZATION_ID (validated fast path)"
    ok "cache volume present: $CACHE_VOLUME"
    exit 0
  fi
  die "existing prepared mount is incomplete or drifted; refusing to overwrite (no retry-by-deletion)"
fi

# An empty Docker-created directory in the right place may be cleared; anything
# else existing here is unexpected state.
if [ -d "$MOUNT_DIR" ]; then
  if [ -z "$(ls -A "$MOUNT_DIR" 2>/dev/null)" ] && [ "$MOUNT_DIR" = "$BASE/mounts/server/reranking" ]; then
    rmdir "$MOUNT_DIR" || die "cannot clear empty Docker-created directory: $MOUNT_DIR"
  else
    die "unexpected existing state at $MOUNT_DIR; refusing to proceed"
  fi
fi
[ -e "$PKI_DIR" ] && die "unexpected existing PKI state at $PKI_DIR; refusing to proceed"

# ---- stage under Compose dir; publish with mv only after validation -------
umask 077
TMP_PKI="$(mktemp -d "$BASE/.reranking-pki.XXXXXX")" || die "mktemp (pki) failed"
TMP_MNT="$(mktemp -d "$BASE/.reranking-mnt.XXXXXX")" || die "mktemp (mount) failed"
cleanup_temps() {
  local f
  # Remove ONLY the exact known staged leaf files. Never recurse, never
  # rm a 'published' directory, never compute a deletion target from data.
  for f in "$TMP_MNT/profile.json" "$TMP_MNT/manifest.json" "$TMP_MNT/root-ca.pem" \
           "$TMP_MNT/client-cert.pem" "$TMP_MNT/client-key.pem"; do
    [ -e "$f" ] && [ ! -d "$f" ] && rm -f -- "$f"
  done
  for f in "$TMP_PKI/ca.key" "$TMP_PKI/ca.crt" "$TMP_PKI/server.crt" "$TMP_PKI/server.key" \
           "$TMP_PKI/client.crt" "$TMP_PKI/client.key" \
           "$TMP_PKI/ca.csr" "$TMP_PKI/ca.srl" "$TMP_PKI/.srl" \
           "$TMP_PKI/server.csr" "$TMP_PKI/server.ext" \
           "$TMP_PKI/client.csr" "$TMP_PKI/client.ext"; do
    [ -e "$f" ] && [ ! -d "$f" ] && rm -f -- "$f"
  done
  # Known staged leaf files inside the published staging dirs, then rmdir only
  # the exact known staging subdirs and the staging roots (no recursion).
  for f in "$TMP_PKI/published/ca.key" "$TMP_PKI/published/ca.crt" \
           "$TMP_PKI/published/server.crt" "$TMP_PKI/published/server.key"; do
    [ -e "$f" ] && [ ! -d "$f" ] && rm -f -- "$f"
  done
  for f in "$TMP_MNT/published/profile.json" "$TMP_MNT/published/manifest.json" \
           "$TMP_MNT/published/root-ca.pem" "$TMP_MNT/published/client-cert.pem" \
           "$TMP_MNT/published/client-key.pem"; do
    [ -e "$f" ] && [ ! -d "$f" ] && rm -f -- "$f"
  done
  rmdir "$TMP_PKI/published" "$TMP_MNT/published" 2>/dev/null || true
  rmdir "$TMP_PKI" "$TMP_MNT" 2>/dev/null || true
}
trap 'cleanup_temps' EXIT

# Dedicated CA: RSA-3072, 365 days, basicConstraints CA:TRUE (no pathlen).
openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
  -keyout "$TMP_PKI/ca.key" -out "$TMP_PKI/ca.crt" \
  -subj '/CN=knowvault reranking CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1 \
  || die "CA generation failed"
chmod 0600 "$TMP_PKI/ca.key"

sign_leaf() { # name CN days extfile-body
  local name="$1" cn="$2" days="$3" ext="$4"
  openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -keyout "$TMP_PKI/$name.key" -out "$TMP_PKI/$name.csr" \
    -subj "/CN=$cn" >/dev/null 2>&1 || return 1
  printf '%s\n' "$ext" >"$TMP_PKI/$name.ext"
  openssl x509 -req -in "$TMP_PKI/$name.csr" -CA "$TMP_PKI/ca.crt" -CAkey "$TMP_PKI/ca.key" \
    -CAcreateserial -days "$days" -sha256 -extfile "$TMP_PKI/$name.ext" \
    -out "$TMP_PKI/$name.crt" >/dev/null 2>&1 || return 1
  rm -f "$TMP_PKI/$name.csr" "$TMP_PKI/$name.ext"
}

# Proxy server certificate (used by the non-root nginx proxy over mTLS).
sign_leaf server knowvault-reranking 180 \
  'basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:knowvault-reranking' || die "server certificate signing failed"
# Client certificate (presented by the server to the reranking endpoint).
sign_leaf client knowvault-reranking-client 180 \
  'basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth' || die "client certificate signing failed"
rm -f "$TMP_PKI/.srl" "$TMP_PKI/ca.srl"

# Mount contents: the fixed profile byte-for-byte plus its exact hash in the
# manifest, the CA trust root, and the client key pair.
install -m 0440 "$SOURCE_PROFILE" "$TMP_MNT/profile.json"
install -m 0440 "$TMP_PKI/ca.crt" "$TMP_MNT/root-ca.pem"
install -m 0440 "$TMP_PKI/client.crt" "$TMP_MNT/client-cert.pem"
install -m 0440 "$TMP_PKI/client.key" "$TMP_MNT/client-key.pem"
expected_manifest > "$TMP_MNT/manifest.json"
chmod 0440 "$TMP_MNT/manifest.json"

# The CA private key is stored protected on the server (0600); leaves become
# root:65532 0440.
[ -s "$TMP_PKI/ca.key" ] && [ -s "$TMP_PKI/server.crt" ] && [ -s "$TMP_MNT/manifest.json" ] \
  || die "staged artefacts are incomplete"

# ---- verify certificate chains before publishing -------------------------
# server cert must carry serverAuth with the expected server DNS name; client
# cert must carry clientAuth; each CA/leaf key must match its cert public key.
# No private key material is ever printed.
openssl x509 -in "$TMP_PKI/server.crt" -noout -ext extendedKeyUsage \
  | grep -q 'TLS Web Server Authentication' \
  || die "server certificate lacks serverAuth"
openssl x509 -in "$TMP_PKI/server.crt" -noout -ext subjectAltName \
  | grep -q 'DNS:knowvault-reranking' \
  || die "server certificate lacks the required server DNS name"
openssl x509 -in "$TMP_PKI/client.crt" -noout -ext extendedKeyUsage \
  | grep -q 'TLS Web Client Authentication' \
  || die "client certificate lacks clientAuth"
openssl verify -purpose sslserver -verify_hostname knowvault-reranking -CAfile "$TMP_PKI/ca.crt" "$TMP_PKI/server.crt" >/dev/null 2>&1 \
  || die "server certificate does not chain to the CA"
openssl verify -purpose sslclient -CAfile "$TMP_PKI/ca.crt" "$TMP_PKI/client.crt" >/dev/null 2>&1 \
  || die "client certificate does not chain to the CA"
[ "$(openssl x509 -in "$TMP_PKI/ca.crt" -noout -pubkey)" = "$(openssl pkey -in "$TMP_PKI/ca.key" -pubout 2>/dev/null)" ] \
  || die "CA key does not match CA certificate"
[ "$(openssl x509 -in "$TMP_PKI/server.crt" -noout -pubkey)" = "$(openssl pkey -in "$TMP_PKI/server.key" -pubout 2>/dev/null)" ] \
  || die "server key does not match server certificate"
[ "$(openssl x509 -in "$TMP_PKI/client.crt" -noout -pubkey)" = "$(openssl pkey -in "$TMP_PKI/client.key" -pubout 2>/dev/null)" ] \
  || die "client key does not match client certificate"

# ---- publish protected directories via mv (no recursive deletion) ---------
# pki/ is owned by other components: create it only if absent, never chmod it.
mkdir -p "$BASE/pki" "$BASE/mounts/server"

install -d -o 0 -g "$MOUNT_GID" -m 0750 "$TMP_PKI/published"
install -m 0600 -o 0 -g "$MOUNT_GID" "$TMP_PKI/ca.key" "$TMP_PKI/published/ca.key"
install -m 0440 -o 0 -g "$MOUNT_GID" "$TMP_PKI/ca.crt" "$TMP_PKI/published/ca.crt"
install -m 0440 -o 0 -g "$MOUNT_GID" "$TMP_PKI/server.crt" "$TMP_PKI/published/server.crt"
install -m 0440 -o 0 -g "$MOUNT_GID" "$TMP_PKI/server.key" "$TMP_PKI/published/server.key"
chown 0:"$MOUNT_GID" "$TMP_PKI/published"
chmod 0750 "$TMP_PKI/published"

install -d -o 0 -g "$MOUNT_GID" -m 0750 "$TMP_MNT/published"
for f in profile.json manifest.json root-ca.pem client-cert.pem client-key.pem; do
  install -m 0440 -o 0 -g "$MOUNT_GID" "$TMP_MNT/$f" "$TMP_MNT/published/$f"
done
chown 0:"$MOUNT_GID" "$TMP_MNT/published"
chmod 0750 "$TMP_MNT/published"

# Validate staged state strictly before publishing.
TMP_PKI_SAVE="$TMP_PKI"; TMP_MNT_SAVE="$TMP_MNT"
PKI_DIR="$TMP_PKI/published"; MOUNT_DIR="$TMP_MNT/published"
validate_prepared_state || { PKI_DIR="$BASE/pki/reranking"; MOUNT_DIR="$BASE/mounts/server/reranking"; die "staged state failed validation"; }
PKI_DIR="$BASE/pki/reranking"; MOUNT_DIR="$BASE/mounts/server/reranking"

# Never overwrite existing published PKI/mount.
[ ! -e "$PKI_DIR" ] || die "unexpected existing PKI at $PKI_DIR; refusing to overwrite"
[ ! -e "$MOUNT_DIR" ] || die "unexpected existing mount at $MOUNT_DIR; refusing to overwrite"

mv "$TMP_PKI_SAVE/published" "$PKI_DIR" || die "publishing PKI failed"
mv "$TMP_MNT_SAVE/published" "$MOUNT_DIR" || die "publishing mount failed"

# ---- named cache volume for UID 1000 via the pinned helper image ----------
ensure_cache_volume

ok "prepared reranking capability for $ORGANIZATION_ID"
ok "pki:   $PKI_DIR"
ok "mount: $MOUNT_DIR"
ok "cache: $CACHE_VOLUME (uid 1000)"
