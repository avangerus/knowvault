#!/bin/bash
# Runs once, only on a brand-new postgres data directory (the official image's
# /docker-entrypoint-initdb.d/ convention): creates Keycloak's own database and
# least-privilege role. KnowVault's own schema/roles are created separately by
# `knowvault-operator bootstrap` against the `knowvault` database, never here.
set -euo pipefail
psql -v ON_ERROR_STOP=1 --username postgres <<-EOSQL
    CREATE ROLE knowvault_keycloak LOGIN PASSWORD '${KNOWVAULT_KEYCLOAK_DB_PASSWORD}';
    CREATE DATABASE keycloak OWNER knowvault_keycloak;
EOSQL
