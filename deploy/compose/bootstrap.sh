#!/usr/bin/env bash
# One bootstrap for the KnowVault one-compose install (anti-SAP: one file,
# one command, README.md fits on one screen). Idempotent: safe to re-run.
#
# What it does, in order:
#   1. generates local PKI (platform CA, postgres/proxy/keycloak/embedding
#      certs) and per-install secrets, once;
#   2. builds the five images this compose file needs from
#      deploy/images/Dockerfile.* (server, worker, operator, embedding) at the
#      pinned base-image digests already in those Dockerfiles;
#   3. starts postgres/opensearch/keycloak/embedding/embedding-proxy and waits
#      for them to be healthy;
#   4. runs `knowvault-operator bootstrap` (roles + migrations),
#      `tenant-provision` (the first organization + OWNER) and
#      `provider-register` (registers this compose's Keycloak realm as the
#      OIDC provider), all idempotent (docs/DEPLOYMENT.md §§1-3);
#   5. runs `knowvault-operator secrets generate` for the server mount, then
#      the worker mount with `-keys-from` (docs/DEPLOYMENT.md §4), and writes
#      the search/embedding capability mounts alongside them;
#   6. starts server/worker/proxy.
#
# After this, open https://knowvault.local:8480 (see README.md for the
# one-time OS hosts-file line), log in as the OWNER this script created, add a
# source and create an MCP access code from the workspace's "Access" tab.
set -euo pipefail

# --dry-run: print the steps this run would perform and validate compose.yaml
# against .env, but build nothing, generate no secret, write no database row,
# start no container. Safe to run against a live install: it never mutates
# anything under $BASE (secrets/pki/mounts) or the database.
DRY_RUN=false
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=true ;;
    *) echo "unknown argument: $arg (only --dry-run is accepted)" >&2; exit 1 ;;
  esac
done

cd "$(dirname "${BASH_SOURCE[0]}")"
BASE="$(pwd)"
REPO_ROOT="$(cd ../.. && pwd)"

if [ ! -f .env ]; then
  echo ".env not found. Copy .env.example to .env, fill it in, then re-run." >&2
  exit 1
fi
set -a; source .env; set +a
: "${KNOWVAULT_ORGANIZATION_ID:?set in .env}"
: "${KNOWVAULT_OWNER_PRINCIPAL_ID:?set in .env}"
: "${KNOWVAULT_OWNER_DISPLAY_NAME:?set in .env}"
: "${KNOWVAULT_OWNER_USERNAME:?set in .env}"
: "${KNOWVAULT_WORKSPACE_ID:?set in .env}"
: "${KNOWVAULT_WORKSPACE_NAME:?set in .env}"
: "${KNOWVAULT_POSTGRES_PASSWORD:?set in .env}"
: "${KNOWVAULT_KEYCLOAK_ADMIN_PASSWORD:?set in .env}"
: "${KNOWVAULT_KEYCLOAK_DB_PASSWORD:?set in .env}"
# ADR-0087 §2 separation of duty (trust verifier != source confirmer):
# false (default) self-grants CONNECTOR_ADMIN to the OWNER, matching a
# single-operator install; true provisions a second principal/Keycloak user
# instead. See step 5c below.
KNOWVAULT_DUAL_CONTROL="${KNOWVAULT_DUAL_CONTROL:-false}"
if [ "$KNOWVAULT_DUAL_CONTROL" = "true" ]; then
  : "${KNOWVAULT_CONNECTOR_ADMIN_USERNAME:?set in .env when KNOWVAULT_DUAL_CONTROL=true}"
  : "${KNOWVAULT_CONNECTOR_ADMIN_DISPLAY_NAME:?set in .env when KNOWVAULT_DUAL_CONTROL=true}"
fi

if [ "$DRY_RUN" = "true" ]; then
  CONNECTOR_ADMIN_STEP="CONNECTOR_ADMIN self-granted to the OWNER ($KNOWVAULT_OWNER_PRINCIPAL_ID) -- single-operator install"
  if [ "$KNOWVAULT_DUAL_CONTROL" = "true" ]; then
    CONNECTOR_ADMIN_STEP="CONNECTOR_ADMIN granted to a second principal ($KNOWVAULT_CONNECTOR_ADMIN_USERNAME) with its own Keycloak user -- dual control"
  fi
  cat <<STEPS
DRY RUN for organization '$KNOWVAULT_ORGANIZATION_ID', workspace '$KNOWVAULT_WORKSPACE_ID' ($KNOWVAULT_WORKSPACE_NAME), OWNER '$KNOWVAULT_OWNER_USERNAME'.
No image will be built, no secret generated, no database row written, no container started.

Steps this run would perform, in order:
  1. generate local PKI (platform CA, postgres/proxy/keycloak/embedding/search certs) and
     per-install secrets under $BASE/{pki,secrets} (idempotent: never overwrites an existing file)
  2. build knowvault/operator:local, then the server and worker images
  3. start postgres, opensearch, keycloak, embedding, embedding-proxy and wait for them to report healthy
  4. run 'operator bootstrap' (roles + migrations), 'operator tenant-provision' (organization
     $KNOWVAULT_ORGANIZATION_ID, workspace $KNOWVAULT_WORKSPACE_ID, OWNER $KNOWVAULT_OWNER_USERNAME) and
     'operator provider-register' (Keycloak realm 'knowvault' as this organization's OIDC provider)
  5. generate the server secret mount, then the worker mount reusing the same keys, plus the
     search and embedding capability mounts
  5c. insert organization_policy_revision (revision 1); insert the OWNER's external_identity
      mapping (its Keycloak subject -> principal $KNOWVAULT_OWNER_PRINCIPAL_ID); $CONNECTOR_ADMIN_STEP
  6. start the server, worker and proxy containers

validating compose.yaml against .env ...
STEPS
  docker compose --env-file .env -f compose.yaml config >/dev/null
  echo "compose.yaml is valid for this .env."
  exit 0
fi

# ---------------------------------------------------------------------------
# 1. PKI and per-install secrets (idempotent: never overwrites an existing
#    file, mirroring the operator's own "secrets generate never overwrites"
#    contract).
# ---------------------------------------------------------------------------
install -d -m 0700 secrets pki/platform pki/keycloak pki/proxy pki/search pki/embedding keycloak \
  mounts/server/secrets mounts/server/trust mounts/server/search mounts/server/embedding \
  mounts/worker/secrets mounts/worker/trust mounts/worker/source-trust mounts/worker/source mounts/worker/search mounts/worker/embedding
install -d -m 0755 mounts/worker/source/inbox

new_secret() { openssl rand -hex 32 | tr -d '\r\n'; }
for f in app.pw worker.pw purger.pw oidc-client.secret; do
  if [ ! -s "secrets/$f" ]; then umask 077; new_secret >"secrets/$f"; fi
  chmod 0600 "secrets/$f"
done
if [ ! -s secrets/owner.password ]; then
  umask 077; new_secret >secrets/owner.password
fi
chmod 0600 secrets/owner.password

ca() {
  local name="$1" cn="$2" sans="$3"
  if [ -s "pki/$name.crt" ]; then return; fi
  cat >"/tmp/$name.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth,clientAuth
subjectAltName=$sans
EOF
  openssl req -new -newkey rsa:2048 -nodes -keyout "pki/$name.key" -out "/tmp/$name.csr" -subj "/CN=$cn" >/dev/null 2>&1
  openssl x509 -req -in "/tmp/$name.csr" -CA pki/platform/ca.crt -CAkey pki/platform/ca.key -CAcreateserial -days 397 -sha256 \
    -extfile "/tmp/$name.ext" -out "pki/$name.crt" >/dev/null 2>&1
  rm -f "/tmp/$name.csr" "/tmp/$name.ext"
}

if [ ! -s pki/platform/ca.crt ]; then
  openssl req -x509 -newkey rsa:4096 -nodes -sha256 -days 825 \
    -keyout pki/platform/ca.key -out pki/platform/ca.crt -subj '/CN=knowvault platform CA' >/dev/null 2>&1
fi
ca platform/postgres knowvault-postgres 'DNS:knowvault-postgres,DNS:localhost,IP:127.0.0.1'
ca proxy/server knowvault.local 'DNS:knowvault.local,DNS:localhost,IP:127.0.0.1'
ca keycloak/server knowvault-idp.local 'DNS:knowvault-idp.local,DNS:knowvault-idp,DNS:localhost,IP:127.0.0.1'
ca embedding/server knowvault-embedding 'DNS:knowvault-embedding,DNS:localhost,IP:127.0.0.1'
chown_ignore() { chown "$@" 2>/dev/null || true; }
chown_ignore 999:999 pki/platform/postgres.key; chmod 0600 pki/platform/postgres.key
chmod 0644 pki/platform/postgres.crt pki/platform/ca.crt
chmod 0600 pki/proxy/server.key pki/keycloak/server.key pki/embedding/server.key
chmod 0644 pki/proxy/server.crt pki/keycloak/server.crt pki/embedding/server.crt

# embedding mTLS client certificate (the server/worker side of the channel;
# the same platform CA signs both ends, exactly like the search mount below).
if [ ! -s pki/embedding/client.crt ]; then
  openssl req -new -newkey rsa:2048 -nodes -keyout pki/embedding/client.key -out /tmp/embclient.csr -subj '/CN=knowvault-embedding-client' >/dev/null 2>&1
  openssl x509 -req -in /tmp/embclient.csr -CA pki/platform/ca.crt -CAkey pki/platform/ca.key -CAcreateserial -days 397 -sha256 \
    -extfile <(printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth\n') \
    -out pki/embedding/client.crt >/dev/null 2>&1
  rm -f /tmp/embclient.csr
fi
chmod 0600 pki/embedding/client.key; chmod 0644 pki/embedding/client.crt

# opensearch security CA + node + admin client cert (search mTLS channel).
if [ ! -s pki/search/ca.crt ]; then
  openssl genrsa -out pki/search/ca.key 4096 >/dev/null 2>&1
  openssl req -x509 -new -nodes -key pki/search/ca.key -sha256 -days 825 -subj '/CN=knowvault search CA' -out pki/search/ca.crt >/dev/null 2>&1
fi
if [ ! -s pki/search/node.crt ]; then
  openssl genrsa -out pki/search/node.key 2048 >/dev/null 2>&1
  openssl req -new -key pki/search/node.key -subj '/CN=knowvault-search' -out /tmp/node.csr >/dev/null 2>&1
  openssl x509 -req -in /tmp/node.csr -CA pki/search/ca.crt -CAkey pki/search/ca.key -CAcreateserial -days 825 -sha256 \
    -extfile <(printf 'basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:knowvault-search,DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=digitalSignature,keyEncipherment\n') \
    -out pki/search/node.crt >/dev/null 2>&1
  rm -f /tmp/node.csr
fi
if [ ! -s pki/search/client.crt ]; then
  openssl genrsa -out pki/search/client.key 2048 >/dev/null 2>&1
  openssl req -new -key pki/search/client.key -subj '/CN=kirk/OU=client/O=client/L=test/C=de' -out /tmp/client.csr >/dev/null 2>&1
  openssl x509 -req -in /tmp/client.csr -CA pki/search/ca.crt -CAkey pki/search/ca.key -CAcreateserial -days 825 -sha256 \
    -extfile <(printf 'basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\nkeyUsage=digitalSignature,keyEncipherment\n') \
    -out pki/search/client.crt >/dev/null 2>&1
  rm -f /tmp/client.csr
fi
chmod 0644 pki/search/*.crt; chmod 0600 pki/search/*.key
cat >pki/search/opensearch.yml <<'EOF'
cluster.name: knowvault-search
network.host: 0.0.0.0
discovery.type: single-node
plugins.security.ssl.transport.pemcert_filepath: knowvault-node.crt
plugins.security.ssl.transport.pemkey_filepath: knowvault-node.key
plugins.security.ssl.transport.pemtrustedcas_filepath: knowvault-search-ca.crt
transport.ssl.enforce_hostname_verification: false
plugins.security.ssl.http.enabled: true
plugins.security.ssl.http.pemcert_filepath: knowvault-node.crt
plugins.security.ssl.http.pemkey_filepath: knowvault-node.key
plugins.security.ssl.http.pemtrustedcas_filepath: knowvault-search-ca.crt
plugins.security.ssl.http.clientauth_mode: REQUIRE
plugins.security.allow_default_init_securityindex: true
plugins.security.authcz.admin_dn:
  - 'C=de,L=test,O=client,OU=client,CN=kirk'
plugins.security.restapi.roles_enabled: [all_access, security_rest_api_access]
EOF

# Keycloak realm import: one client (this server), one OWNER user.
# Keycloak 26's realm-default declarative user profile marks email,
# firstName and lastName all required -- a user imported without them still
# gets created, but its first login is blocked by a server-injected
# VERIFY_PROFILE required action (found live on the acceptance stand, CONV-1
# bug #5: fixed there by hand, never here, until now). firstName/lastName
# are split off KNOWVAULT_OWNER_DISPLAY_NAME on the first space so an
# installer only has to fill in one field.
CLIENT_SECRET=$(cat secrets/oidc-client.secret)
OWNER_PASSWORD=$(cat secrets/owner.password)
OWNER_FIRST_NAME="${KNOWVAULT_OWNER_DISPLAY_NAME%% *}"
OWNER_LAST_NAME="${KNOWVAULT_OWNER_DISPLAY_NAME#* }"
[ "$OWNER_LAST_NAME" = "$KNOWVAULT_OWNER_DISPLAY_NAME" ] && OWNER_LAST_NAME="Owner"
OWNER_EMAIL="${KNOWVAULT_OWNER_USERNAME}@${KNOWVAULT_ORGANIZATION_ID}.local"
sed -e "s/__KNOWVAULT_OIDC_CLIENT_SECRET__/$CLIENT_SECRET/" \
    -e "s/__KNOWVAULT_OWNER_USERNAME__/$KNOWVAULT_OWNER_USERNAME/" \
    -e "s/__KNOWVAULT_OWNER_PRINCIPAL_ID__/$KNOWVAULT_OWNER_PRINCIPAL_ID/" \
    -e "s/__KNOWVAULT_OWNER_PASSWORD__/$OWNER_PASSWORD/" \
    -e "s/__KNOWVAULT_OWNER_EMAIL__/$OWNER_EMAIL/" \
    -e "s/__KNOWVAULT_OWNER_FIRST_NAME__/$OWNER_FIRST_NAME/" \
    -e "s/__KNOWVAULT_OWNER_LAST_NAME__/$OWNER_LAST_NAME/" \
    keycloak/knowvault-realm.json.template >keycloak/knowvault-realm.json

echo "PKI and secrets ready."

# ---------------------------------------------------------------------------
# 2. Build images. server/worker build through compose itself (each service
#    below has its own `build:` context, so `compose ... up` builds them);
#    operator is a one-shot CLI, run by `docker run` below, not a compose
#    service, so it is built directly here.
# ---------------------------------------------------------------------------
docker build -f "$REPO_ROOT/deploy/images/Dockerfile.operator" -t knowvault/operator:local "$REPO_ROOT"
docker compose --env-file .env -f compose.yaml build server worker

# ---------------------------------------------------------------------------
# 3. Start the data/identity/embedding plane and wait for health.
# ---------------------------------------------------------------------------
docker compose --env-file .env -f compose.yaml up -d postgres opensearch keycloak embedding embedding-proxy
echo "waiting for postgres/opensearch/embedding to become healthy ..."
for container in knowvault-postgres knowvault-opensearch knowvault-embedding; do
  for _ in $(seq 1 90); do
    status=$(docker inspect -f '{{.State.Health.Status}}' "$container" 2>/dev/null || echo "")
    [ "$status" = "healthy" ] && break
    sleep 2
  done
  [ "$status" = "healthy" ] || { echo "warning: $container did not report healthy in time" >&2; }
done

# ---------------------------------------------------------------------------
# 4. Roles, migrations, tenant, OIDC provider (all idempotent).
# ---------------------------------------------------------------------------
run_operator() {
  docker run --rm --network knowvault-net \
    -v "$BASE/secrets:/secrets:ro" \
    -v "$BASE/pki/platform/ca.crt:/trust/database-ca.pem:ro" \
    -e SSL_CERT_FILE=/trust/database-ca.pem \
    knowvault/operator:local "$@"
}

ADMIN_URL="postgres://postgres:${KNOWVAULT_POSTGRES_PASSWORD}@knowvault-postgres:5432/knowvault?sslmode=verify-full"

run_operator bootstrap -admin-url "$ADMIN_URL" -migrations-dir /db/migrations \
  -app-password-file /secrets/app.pw -worker-password-file /secrets/worker.pw -purger-password-file /secrets/purger.pw

run_operator tenant-provision -admin-url "$ADMIN_URL" \
  -organization "$KNOWVAULT_ORGANIZATION_ID" -organization-name "$KNOWVAULT_ORGANIZATION_ID" -region ru \
  -owner-principal "$KNOWVAULT_OWNER_PRINCIPAL_ID" -owner-display-name "$KNOWVAULT_OWNER_DISPLAY_NAME" \
  -workspace "$KNOWVAULT_WORKSPACE_ID" -workspace-name "$KNOWVAULT_WORKSPACE_NAME" -workspace-description ""

run_operator provider-register -admin-url "$ADMIN_URL" \
  -organization "$KNOWVAULT_ORGANIZATION_ID" -provider keycloak-main \
  -issuer https://knowvault-idp.local:8443/realms/knowvault \
  -client-id knowvault-server -client-secret-reference oidc-client -redirect-uri https://knowvault.local:8480/auth/callback \
  -created-by "$KNOWVAULT_OWNER_PRINCIPAL_ID"

# ---------------------------------------------------------------------------
# 5. Secret mounts (server, then worker reusing the same keys), plus the
#    search and embedding capability mounts.
# ---------------------------------------------------------------------------
# --database-url-file must name the exact runtime role's own DSN.
printf 'postgres://knowvault_app:%s@knowvault-postgres:5432/knowvault?sslmode=verify-full' "$(cat secrets/app.pw)" >secrets/server-db-url
printf 'postgres://knowvault_worker:%s@knowvault-postgres:5432/knowvault?sslmode=verify-full' "$(cat secrets/worker.pw)" >secrets/worker-db-url

if [ ! -s mounts/server/secrets/manifest.json ]; then
  docker run --rm --network knowvault-net \
    -v "$BASE/secrets:/secrets:ro" -v "$BASE/mounts/server/secrets:/out" \
    knowvault/operator:local secrets generate -out /out \
    -organization "$KNOWVAULT_ORGANIZATION_ID" -provider keycloak-main \
    -database-url-file /secrets/server-db-url -client-secret-file /secrets/oidc-client.secret -client-reference oidc-client
fi
if [ ! -s mounts/worker/secrets/manifest.json ]; then
  docker run --rm --network knowvault-net \
    -v "$BASE/secrets:/secrets:ro" -v "$BASE/mounts/server/secrets:/server-mount:ro" -v "$BASE/mounts/worker/secrets:/out" \
    knowvault/operator:local secrets generate -out /out \
    -organization "$KNOWVAULT_ORGANIZATION_ID" -provider keycloak-main \
    -database-url-file /secrets/worker-db-url -client-secret-file /secrets/oidc-client.secret -client-reference oidc-client \
    -keys-from /server-mount -consumer worker
fi
shred -u secrets/server-db-url secrets/worker-db-url 2>/dev/null || rm -f secrets/server-db-url secrets/worker-db-url

# Existing worker mounts must already match this release. Upgrade tooling
# stages a separate copy and retains the previous tree for rollback.
docker run --rm --network none -v "$BASE/mounts/worker/secrets:/mount:ro" \
  knowvault/operator:local secrets verify -mount /mount -consumer worker \
  -organization "$KNOWVAULT_ORGANIZATION_ID" -provider keycloak-main
for role in server worker; do
  mount_gid=65532
  if [ "$role" = worker ]; then mount_gid=65530; fi
  install -d -o 0 -g "$mount_gid" -m 0750 "mounts/$role/trust" "mounts/$role/search" "mounts/$role/embedding"
done
install -d -o 0 -g 65530 -m 0750 mounts/worker/source-trust mounts/worker/source

install -o 0 -g 65532 -m 0440 pki/platform/ca.crt mounts/server/trust/database-ca.pem
install -o 0 -g 65532 -m 0440 pki/keycloak/server.crt mounts/server/trust/oidc-ca.pem
install -o 0 -g 65530 -m 0440 pki/platform/ca.crt mounts/worker/trust/database-ca.pem
install -o 0 -g 65530 -m 0440 pki/keycloak/server.crt mounts/worker/trust/oidc-ca.pem
install -o 0 -g 65530 -m 0440 pki/platform/ca.crt mounts/worker/trust/git-ca.pem
install -o 0 -g 65530 -m 0440 pki/platform/ca.crt mounts/worker/trust/mail-ca.pem
install -o 0 -g 65530 -m 0440 pki/platform/ca.crt mounts/worker/source-trust/git-ca.pem
install -o 0 -g 65530 -m 0440 pki/platform/ca.crt mounts/worker/source-trust/mail-ca.pem
# Default install trusts the platform's own CA for a freshly registered
# POSTGRESQL_QUERY source too (single-CA self-hosted default, decision #9);
# an operator connecting to an external database with its own CA replaces
# this file with that database's trust bundle before registering the source.
install -o 0 -g 65530 -m 0440 pki/platform/ca.crt mounts/worker/source-trust/database-ca.pem

# search capability mount (server + worker): OpenSearch is CPU-local to this
# compose project, so both mounts point at the same in-network endpoint.
cat >/tmp/knowvault-search-manifest.json <<EOF
{"schema":"knowvault-search-manifest-v1","organization_id":"$KNOWVAULT_ORGANIZATION_ID",
 "endpoint":"https://knowvault-search:9200","index_alias":"${KNOWVAULT_ORGANIZATION_ID}-v1",
 "generation":1,"generation_fence":1,"root_ca_file":"root-ca.pem",
 "client_certificate_file":"client-cert.pem","client_key_file":"client-key.pem"}
EOF
for role in server worker; do
  mount_gid=65532
  if [ "$role" = worker ]; then mount_gid=65530; fi
  install -o 0 -g "$mount_gid" -m 0440 pki/search/ca.crt "mounts/$role/search/root-ca.pem"
  install -o 0 -g "$mount_gid" -m 0440 pki/search/client.crt "mounts/$role/search/client-cert.pem"
  install -o 0 -g "$mount_gid" -m 0440 pki/search/client.key "mounts/$role/search/client-key.pem"
  install -o 0 -g "$mount_gid" -m 0440 /tmp/knowvault-search-manifest.json "mounts/$role/search/manifest.json"
done
rm -f /tmp/knowvault-search-manifest.json

# embedding capability mount (server + worker: the server uses it for
# query-time embedding and the GENERATIVE claim verifier; the worker uses the
# exact same mounted profile for passage-time embedding at ingestion —
# internal/platform/workercomposition/runtime.go loads this mount too, and a
# server-only mount would leave newly ingested content never vectorised even
# though queries embed correctly).
cat >/tmp/knowvault-embedding-manifest.json <<EOF
{"schema":"knowvault-embedding-manifest-v1","organization_id":"$KNOWVAULT_ORGANIZATION_ID",
 "profile_file":"profile.json","profile_hash":"$(grep -o '"profile_hash": *"[^"]*"' embedding-profile.json | cut -d'"' -f4)",
 "root_ca_file":"root-ca.pem","client_certificate_file":"client-cert.pem","client_key_file":"client-key.pem"}
EOF
for role in server worker; do
  mount_gid=65532
  if [ "$role" = worker ]; then mount_gid=65530; fi
  install -o 0 -g "$mount_gid" -m 0440 /tmp/knowvault-embedding-manifest.json "mounts/$role/embedding/manifest.json"
  install -o 0 -g "$mount_gid" -m 0440 embedding-profile.json "mounts/$role/embedding/profile.json"
  install -o 0 -g "$mount_gid" -m 0440 pki/platform/ca.crt "mounts/$role/embedding/root-ca.pem"
  install -o 0 -g "$mount_gid" -m 0440 pki/embedding/client.crt "mounts/$role/embedding/client-cert.pem"
  install -o 0 -g "$mount_gid" -m 0440 pki/embedding/client.key "mounts/$role/embedding/client-key.pem"
done
rm -f /tmp/knowvault-embedding-manifest.json

# ---------------------------------------------------------------------------
# 5c. Rows the product has no admin surface for yet, but a fresh install
#     needs before its first login or its first source confirmation
#     (ADR-0087, CONV-2 -- found and, until now, only ever fixed by hand on
#     the acceptance stand's own deploy script):
#       - organization_policy_revision: ADR-0087's confirmation-grants flow
#         reads organization.policy_revision joined against this table and
#         fails REQUEST_INVALID with no matching row -- every install needs
#         one, not only a dual-control one;
#       - a public.external_identity row mapping the OWNER's Keycloak
#         subject to its principal: CompleteLogin requires one, and without
#         it the very first login fails AUTH_CALLBACK_FAILED even though the
#         token exchange itself succeeded (the exact defect CONV-2 found on
#         a second acceptance stand and fixed only there);
#       - KNOWVAULT_DUAL_CONTROL=true additionally provisions a second
#         principal, Keycloak user and CONNECTOR_ADMIN role assignment, so
#         source trust verification (ADR-0087 §2, separation of duty) is
#         never the same person who confirmed the source; the default
#         (false) instead self-grants CONNECTOR_ADMIN to the OWNER itself
#         (ADR-0053 "self-grant"), so a solo installer can still verify
#         trust without a second person.
#     Idempotent throughout: every SQL insert is WHERE NOT EXISTS, and the
#     Keycloak user create is skipped when that username already exists.
# ---------------------------------------------------------------------------
psql_exec() {
  docker exec -i knowvault-postgres env PGPASSWORD="$KNOWVAULT_POSTGRES_PASSWORD" \
    psql -U postgres -d knowvault -v ON_ERROR_STOP=1 -q
}

POLICY_HASH="sha256:$(printf '%s' "policy-${KNOWVAULT_ORGANIZATION_ID}-0001" | sha256sum | cut -d' ' -f1)"
psql_exec <<SQL
INSERT INTO public.organization_policy_revision
  (organization_id, revision, policy_revision_id, policy_hash, activated_at, activated_by)
SELECT '$KNOWVAULT_ORGANIZATION_ID', 1, 'policy-${KNOWVAULT_ORGANIZATION_ID}-0001', '$POLICY_HASH',
       to_char(now() AT TIME ZONE 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'), '$KNOWVAULT_OWNER_PRINCIPAL_ID'
WHERE NOT EXISTS (
  SELECT 1 FROM public.organization_policy_revision
   WHERE organization_id = '$KNOWVAULT_ORGANIZATION_ID' AND revision = 1
);
SQL
echo "organization_policy_revision: ready"

CONNECTOR_ADMIN_PRINCIPAL="$KNOWVAULT_OWNER_PRINCIPAL_ID"
if [ "$KNOWVAULT_DUAL_CONTROL" = "true" ]; then
  CONNECTOR_ADMIN_PRINCIPAL="$KNOWVAULT_CONNECTOR_ADMIN_USERNAME"
  if [ ! -s secrets/connector-admin.password ]; then
    umask 077; new_secret >secrets/connector-admin.password
  fi
  chmod 0600 secrets/connector-admin.password
  psql_exec <<SQL
INSERT INTO public.principal (id, organization_id, type, display_name, status, session_revision)
SELECT '$CONNECTOR_ADMIN_PRINCIPAL', '$KNOWVAULT_ORGANIZATION_ID', 'USER', '$KNOWVAULT_CONNECTOR_ADMIN_DISPLAY_NAME', 'ACTIVE', 1
WHERE NOT EXISTS (
  SELECT 1 FROM public.principal WHERE id = '$CONNECTOR_ADMIN_PRINCIPAL' AND organization_id = '$KNOWVAULT_ORGANIZATION_ID'
);
INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by)
SELECT 'ora_${KNOWVAULT_ORGANIZATION_ID}_connector_admin_verifier', '$KNOWVAULT_ORGANIZATION_ID', '$CONNECTOR_ADMIN_PRINCIPAL', 'CONNECTOR_ADMIN', 1, '$KNOWVAULT_OWNER_PRINCIPAL_ID'
WHERE NOT EXISTS (
  SELECT 1 FROM public.organization_role_assignment WHERE id = 'ora_${KNOWVAULT_ORGANIZATION_ID}_connector_admin_verifier'
);
SQL
  echo "second principal + CONNECTOR_ADMIN (dual control): $CONNECTOR_ADMIN_PRINCIPAL"
else
  psql_exec <<SQL
INSERT INTO public.organization_role_assignment (id, organization_id, principal_id, role, valid_from_revision, assigned_by)
SELECT 'ora_${KNOWVAULT_ORGANIZATION_ID}_connector_admin_owner', '$KNOWVAULT_ORGANIZATION_ID', '$KNOWVAULT_OWNER_PRINCIPAL_ID', 'CONNECTOR_ADMIN', 1, '$KNOWVAULT_OWNER_PRINCIPAL_ID'
WHERE NOT EXISTS (
  SELECT 1 FROM public.organization_role_assignment WHERE id = 'ora_${KNOWVAULT_ORGANIZATION_ID}_connector_admin_owner'
);
SQL
  echo "CONNECTOR_ADMIN self-granted to OWNER (single-operator install): $KNOWVAULT_OWNER_PRINCIPAL_ID"
fi

# Keycloak admin token (retry: a freshly (re)created keycloak container may
# still be finishing realm import even though its healthcheck is not tracked
# above -- verified on the acceptance stand: the very first call after a full
# `docker compose down` hit a TLS error because the listener was not up yet).
KC_CACERT="$BASE/pki/platform/ca.crt"
KC_RESOLVE="--resolve knowvault-idp.local:8443:127.0.0.1"
KC_TOKEN=""
for _ in $(seq 1 20); do
  KC_TOKEN=$(curl -sS --max-time 15 --cacert "$KC_CACERT" $KC_RESOLVE \
    -d client_id=admin-cli -d username=kv-admin -d "password=${KNOWVAULT_KEYCLOAK_ADMIN_PASSWORD}" -d grant_type=password \
    https://knowvault-idp.local:8443/realms/master/protocol/openid-connect/token 2>/dev/null |
    sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
  [ -n "$KC_TOKEN" ] && break
  sleep 3
done

if [ -z "$KC_TOKEN" ]; then
  echo "warning: could not obtain a Keycloak admin token -- external_identity mappings were not created; log in once, then re-run bootstrap.sh to finish this step." >&2
else
  kc_user_sub() {
    curl -sS --max-time 15 --cacert "$KC_CACERT" $KC_RESOLVE -H "Authorization: Bearer $KC_TOKEN" \
      "https://knowvault-idp.local:8443/admin/realms/knowvault/users?username=$1&exact=true" |
      sed -n 's/.*"id":"\([^"]*\)".*/\1/p' | head -1
  }

  if [ "$KNOWVAULT_DUAL_CONTROL" = "true" ] && [ -z "$(kc_user_sub "$KNOWVAULT_CONNECTOR_ADMIN_USERNAME")" ]; then
    CONNECTOR_ADMIN_PASSWORD=$(cat secrets/connector-admin.password)
    CONNECTOR_ADMIN_FIRST_NAME="${KNOWVAULT_CONNECTOR_ADMIN_DISPLAY_NAME%% *}"
    CONNECTOR_ADMIN_LAST_NAME="${KNOWVAULT_CONNECTOR_ADMIN_DISPLAY_NAME#* }"
    [ "$CONNECTOR_ADMIN_LAST_NAME" = "$KNOWVAULT_CONNECTOR_ADMIN_DISPLAY_NAME" ] && CONNECTOR_ADMIN_LAST_NAME="Admin"
    curl -sS --max-time 15 --cacert "$KC_CACERT" $KC_RESOLVE -H "Authorization: Bearer $KC_TOKEN" -H 'Content-Type: application/json' \
      -d "{\"username\":\"$KNOWVAULT_CONNECTOR_ADMIN_USERNAME\",\"enabled\":true,\"email\":\"${KNOWVAULT_CONNECTOR_ADMIN_USERNAME}@${KNOWVAULT_ORGANIZATION_ID}.local\",\"emailVerified\":true,\"firstName\":\"$CONNECTOR_ADMIN_FIRST_NAME\",\"lastName\":\"$CONNECTOR_ADMIN_LAST_NAME\",\"requiredActions\":[],\"attributes\":{\"knowvault_principal_id\":[\"$CONNECTOR_ADMIN_PRINCIPAL\"]},\"credentials\":[{\"type\":\"password\",\"value\":\"$CONNECTOR_ADMIN_PASSWORD\",\"temporary\":false}]}" \
      https://knowvault-idp.local:8443/admin/realms/knowvault/users >/dev/null
  fi

  # Compact JSON, so identity_hmac's fixed field order (internal/operator/
  # secrets.go versionedKeyWire: reference, version, filename) is matched
  # exactly rather than tolerating arbitrary whitespace/ordering.
  MANIFEST="mounts/server/secrets/manifest.json"
  IDENTITY_VERSION=$(sed -n 's/.*"identity_hmac":{"reference":"[^"]*","version":\([0-9]*\),"filename":"[^"]*".*/\1/p' "$MANIFEST")
  IDENTITY_KEY_FILE=$(sed -n 's/.*"identity_hmac":{"reference":"[^"]*","version":[0-9]*,"filename":"\([^"]*\)".*/\1/p' "$MANIFEST")
  if [ -z "$IDENTITY_VERSION" ] || [ -z "$IDENTITY_KEY_FILE" ]; then
    echo "warning: could not read identity_hmac from $MANIFEST -- external_identity mappings were not created." >&2
  else
    IDENTITY_KEY_B64URL=$(cat "mounts/server/secrets/$IDENTITY_KEY_FILE")
    # base64url (no padding, '-'/'_') -> hex, portable across GNU/BSD base64
    # (no reliance on xxd, which is not always installed): pad back to a
    # multiple of 4 and translate to standard base64 alphabet, decode with
    # openssl (present on every supported host), then hex-encode the raw
    # bytes with od (POSIX, always present).
    base64url_to_hex() {
      local input="$1" padded rem
      padded=$(printf '%s' "$input" | tr '_-' '/+')
      rem=$(( ${#padded} % 4 ))
      if [ "$rem" -ne 0 ]; then padded="${padded}$(printf '=%.0s' $(seq 1 $((4 - rem))))"; fi
      printf '%s' "$padded" | openssl base64 -d -A | od -An -tx1 | tr -d ' \n'
    }
    IDENTITY_KEY_HEX=$(base64url_to_hex "$IDENTITY_KEY_B64URL")
    identity_mapping_sql() {
      local username="$1" principal="$2"
      local sub; sub=$(kc_user_sub "$username")
      if [ -z "$sub" ]; then
        echo "warning: Keycloak has no user '$username' yet -- skipping its external_identity mapping." >&2
        return
      fi
      local digest
      digest=$(printf 'knowvault:oidc:subject:%s' "$sub" |
        openssl dgst -sha256 -mac HMAC -macopt "hexkey:$IDENTITY_KEY_HEX" |
        sed 's/^.* //')
      cat <<SQL
INSERT INTO public.external_identity
  (id, organization_id, principal_id, provider_id, external_subject_digest, digest_key_version, attributes_hash, status, last_verified_at, created_at)
SELECT 'ext-kc-${KNOWVAULT_ORGANIZATION_ID}-${username}', '$KNOWVAULT_ORGANIZATION_ID', '$principal', 'keycloak-main',
       'hmac-sha256:k${IDENTITY_VERSION}:$digest', $IDENTITY_VERSION, 'sha256:$(printf '0%.0s' $(seq 1 64))', 'ACTIVE', now(), now()
WHERE NOT EXISTS (
  SELECT 1 FROM public.external_identity
   WHERE organization_id = '$KNOWVAULT_ORGANIZATION_ID' AND principal_id = '$principal' AND provider_id = 'keycloak-main'
);
SQL
    }
    {
      identity_mapping_sql "$KNOWVAULT_OWNER_USERNAME" "$KNOWVAULT_OWNER_PRINCIPAL_ID"
      if [ "$KNOWVAULT_DUAL_CONTROL" = "true" ]; then
        identity_mapping_sql "$KNOWVAULT_CONNECTOR_ADMIN_USERNAME" "$CONNECTOR_ADMIN_PRINCIPAL"
      fi
    } | psql_exec
    echo "external_identity mappings: ready"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Start the application plane.
# ---------------------------------------------------------------------------
docker compose --env-file .env -f compose.yaml up -d server worker proxy

cat <<EOF

KnowVault is up.
  1. Add this line to your OS hosts file (once): 127.0.0.1 knowvault.local knowvault-idp.local
  2. Open https://knowvault.local:8480 and accept the local development certificate.
  3. Log in as $KNOWVAULT_OWNER_USERNAME (password: cat $BASE/secrets/owner.password).
  4. Add a source, then open the workspace's "Access" tab to create an MCP access code.
EOF
