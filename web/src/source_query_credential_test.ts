// Card S3.2b web probe: the SQL query credential control on the Sources
// database card. The real production SourceConnectionCard renders the control
// only for an organization OWNER; the real SourceQueryCredentialControl shows
// the opaque-reference field and the Clear action only when a credential is
// currently configured. No DSN or secret input exists in the control.
//
// Plain TypeScript module under the repository's pinned esbuild + node
// toolchain (no test framework), rendering the REAL production components.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  SourceConnectionCard,
  SourceQueryCredentialControl,
  type SourceConnectionGroup,
  type SourceStatus,
} from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

function table(overrides: Partial<SourceStatus> & { source_scope_id: string }): SourceStatus {
  const { source_scope_id, ...rest } = overrides;
  return {
    workspace_source_id: `wsrc_${source_scope_id}`,
    source_scope_id,
    source_scope_revision: 1,
    access_mode: "WORKSPACE_MANAGED",
    enabled: true,
    scope_config_hash: `hash_${source_scope_id}`,
    connection_id: "conn_ops",
    connection_name: "Operations database",
    source_type: "POSTGRESQL_QUERY",
    postgresql_schema_name: "reporting",
    postgresql_relation_name: "contract",
    activation_status: "READY",
    trust_verified: true,
    sync_status: "SUCCEEDED",
    sync_error_code: null,
    sync_started_at: null,
    sync_completed_at: null,
    objects_seen: 1,
    objects_ingested: 1,
    versions_created: 1,
    evidence_published: 1,
    quarantined: 0,
    content_freshness_sla_seconds: 1800,
    last_successful_sync_at: "2026-09-12T10:02:00Z",
    freshness_state: "FRESH",
    sync_interval_seconds: 1800,
    confirmed: true,
    confirmation_state: "ACTIVE",
    can_verify_connection_trust: false,
    ...rest,
  };
}

function group(tables: SourceStatus[]): SourceConnectionGroup {
  return { connection_id: "conn_ops", connection_name: "Operations database", source_type: "POSTGRESQL_QUERY", tables };
}

function control(): ReturnType<typeof SourceQueryCredentialControl> {
  return createElement(SourceQueryCredentialControl, {
    connectionID: "conn_ops",
    sqlAvailable: false,
    onSet: () => undefined,
    onClear: () => undefined,
  });
}

function main(): void {
  const ownerMarkup = renderToStaticMarkup(createElement(SourceConnectionCard, {
    group: group([table({ source_scope_id: "scope_a" })]),
    canConfigureSQL: true,
    sqlControl: control(),
  }));
  check(ownerMarkup.includes("source-sql-control"), "an OWNER sees the SQL credential control");
  check(ownerMarkup.includes("Query credential reference"), "the control names the opaque reference field");
  check(ownerMarkup.includes('placeholder="cred_…"'), "the control asks for the opaque cred_ reference");

  const memberMarkup = renderToStaticMarkup(createElement(SourceConnectionCard, {
    group: group([table({ source_scope_id: "scope_b" })]),
    canConfigureSQL: false,
    sqlControl: control(),
  }));
  check(!memberMarkup.includes("source-sql-control"), "a non-owner never sees the SQL credential control");
  check(!memberMarkup.includes("Query credential reference"), "a non-owner never sees the reference field");

  const defaultMarkup = renderToStaticMarkup(createElement(SourceConnectionCard, {
    group: group([table({ source_scope_id: "scope_c" })]),
  }));
  check(!defaultMarkup.includes("source-sql-control"), "an omitted capability hides the control (fail closed)");

  const withoutCredential = renderToStaticMarkup(control());
  check(withoutCredential.includes(">Save<"), "the control offers Save");
  check(!withoutCredential.includes(">Clear<"), "the control hides Clear when no credential is configured");

  const withCredential = renderToStaticMarkup(createElement(SourceQueryCredentialControl, {
    connectionID: "conn_ops",
    sqlAvailable: true,
    onSet: () => undefined,
    onClear: () => undefined,
  }));
  check(withCredential.includes(">Clear<"), "the control offers Clear when a credential is configured");

  check(!/password|dsn|postgres:\/\//i.test(ownerMarkup), "the control never offers a DSN or password field");

  if (failures !== 0) throw new Error(`${failures} source query credential assertion(s) failed`);
  console.log("source query credential probe: PASS");
}

main();
