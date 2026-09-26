// Card S3.4b — batch actions probe: in-tree UI probe for the Sources card's
// "confirm all awaiting tables" control and its per-table outcome summary, plus
// the wizard's one-request-per-batch registration body.
//
// This is a plain TypeScript module exercised by the repository's pinned
// esbuild + node toolchain (no test framework, no new dependency), matching the
// pattern used by postgres_query_only_test.ts. It renders the real production
// export from main.tsx through react-dom/server and calls the real pure
// helpers:
//
//   1. the awaiting-table selection: all of a connection, or one schema;
//   2. the closed batch-confirmation body;
//   3. the operator-facing outcome summary, including a refused table's code;
//   4. the card markup: the bulk control and the summary;
//   5. the batch registration body and its 200-table bound.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  POSTGRES_REGISTRATION_BATCH_LIMIT,
  SourceConnectionCard,
  confirmBatchOutcomeSummary,
  confirmBatchRequestBody,
  postgresRegistrationBatchBody,
  sourceSchemasAwaitingConfirmation,
  sourceTablesAwaitingConfirmation,
  sourceTablesAwaitingConfirmationInSchema,
  type PostgresRegistrationRequest,
  type SourceConnectionGroup,
  type SourceDiscoveryView,
  type SourceStatus,
} from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

function table(overrides: Partial<SourceStatus> & { source_scope_id: string }): SourceStatus {
  return {
    workspace_source_id: "binding_" + overrides.source_scope_id,
    source_scope_revision: 1,
    access_mode: "WORKSPACE_MANAGED",
    enabled: true,
    scope_config_hash: "sha256:" + "a".repeat(64),
    connection_id: "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ",
    connection_name: "warehouse",
    source_type: "POSTGRESQL_QUERY",
    postgresql_schema_name: "public",
    postgresql_relation_name: "t",
    activation_status: "READY",
    trust_verified: true,
    sync_status: null,
    sync_error_code: null,
    sync_started_at: null,
    sync_completed_at: null,
    objects_seen: null,
    objects_ingested: null,
    versions_created: null,
    evidence_published: null,
    quarantined: null,
    content_freshness_sla_seconds: 3600,
    last_successful_sync_at: null,
    freshness_state: "UNKNOWN",
    sync_interval_seconds: 3600,
    confirmed: false,
    confirmation_state: "NEEDS_CONFIRMATION",
    can_verify_connection_trust: false,
    ...overrides,
  };
}

function view(overrides: Partial<SourceDiscoveryView> & { view_id: string; relation_name: string }): SourceDiscoveryView {
  return {
    schema_name: "public",
    relation_kind: "TABLE",
    approx_row_count: 10,
    status: "PREPARED",
    columns: [],
    ...overrides,
  };
}

function main(): void {
  const awaitingPublic = table({
    source_scope_id: "scope_01H9ABCDEFGHJKMNPQRSTVWXA",
    postgresql_schema_name: "public",
    postgresql_relation_name: "orders",
  });
  const awaitingBilling = table({
    source_scope_id: "scope_01H9ABCDEFGHJKMNPQRSTVWXB",
    postgresql_schema_name: "billing",
    postgresql_relation_name: "invoice",
  });
  const active = table({
    source_scope_id: "scope_01H9ABCDEFGHJKMNPQRSTVWXC",
    postgresql_schema_name: "billing",
    postgresql_relation_name: "already",
    confirmation_state: "ACTIVE",
    confirmed: true,
  });
  const group: SourceConnectionGroup = {
    connection_id: "conn_01H9ABCDEFGHJKMNPQRSTVWXYZ",
    connection_name: "warehouse",
    source_type: "POSTGRESQL_QUERY",
    tables: [awaitingPublic, awaitingBilling, active],
  };

  // --- 1. awaiting selection ----------------------------------------------
  const awaiting = sourceTablesAwaitingConfirmation(group);
  check(awaiting.length === 2 && !awaiting.some((item) => item.source_scope_id === active.source_scope_id),
    "only tables whose confirmation is not ACTIVE are awaiting confirmation");
  check(sourceSchemasAwaitingConfirmation(group).join(",") === "billing,public",
    "awaiting schemas are the distinct schemas with a pending table, sorted");
  check(sourceTablesAwaitingConfirmationInSchema(group, "billing").length === 1,
    "a schema choice selects only that schema's awaiting tables");
  check(sourceTablesAwaitingConfirmationInSchema(group, "").length === 2,
    "the all-schemas choice selects every awaiting table");

  // --- 2. the closed batch body -------------------------------------------
  const body = confirmBatchRequestBody(awaiting, 7, "sha256:" + "b".repeat(64), {
    grant_id: "grant_01H9ABCDEFGHJKMNPQRSTVWXYZ", grant_revision: 1, grant_hash: "sha256:" + "c".repeat(64),
  }, "sha256:" + "d".repeat(64), "pol_alpha");
  check(body.workspace_revision === 7 && body.tables.length === 2 &&
    body.tables[0].workspace_source_id === awaitingPublic.workspace_source_id &&
    body.tables[1].source_scope_id === awaitingBilling.source_scope_id &&
    body.confirmation_actor_grant_id === "grant_01H9ABCDEFGHJKMNPQRSTVWXYZ",
    "the batch body carries the shared tuple and one binding tuple per table");

  // --- 3. the outcome summary ---------------------------------------------
  const confirmedOnly = confirmBatchOutcomeSummary({
    confirmed_count: 3, refused_count: 0,
    results: [
      { source_scope_id: "a", outcome: "CONFIRMED" },
      { source_scope_id: "b", outcome: "CONFIRMED" },
      { source_scope_id: "c", outcome: "CONFIRMED" },
    ],
  });
  check(confirmedOnly === "3 tables confirmed.", "a clean batch reports the confirmed count");
  const mixed = confirmBatchOutcomeSummary({
    confirmed_count: 2, refused_count: 1,
    results: [
      { source_scope_id: "a", outcome: "CONFIRMED" },
      { source_scope_id: "b", outcome: "CONFIRMED" },
      { source_scope_id: "c", outcome: "REFUSED", reason_code: "WORKSPACE_CONFLICT" },
    ],
  });
  check(mixed === "2 tables confirmed, 1 refused (WORKSPACE_CONFLICT).",
    "a mixed batch reports each refused table's closed reason code");
  check(confirmBatchOutcomeSummary({ confirmed_count: 1, refused_count: 0, results: [{ source_scope_id: "a", outcome: "CONFIRMED" }] }) === "1 table confirmed.",
    "a single confirmation is reported in the singular");

  // --- 4. the card renders the control and the summary ---------------------
  const markup = renderToStaticMarkup(createElement(SourceConnectionCard, {
    group,
    confirmBatch: {
      canConfirm: true, busy: false, summary: mixed, onConfirm: () => {},
    },
  }));
  check(markup.includes("Tables awaiting confirmation"), "the card renders the bulk confirmation control");
  check(markup.includes("All schemas (2)"), "the control offers every awaiting table by default");
  check(markup.includes("billing (1)") && markup.includes("public (1)"), "the control offers one schema at a time");
  check(markup.includes("Confirm all 2"), "the action names how many tables it will confirm");
  check(markup.includes("2 tables confirmed, 1 refused (WORKSPACE_CONFLICT)."),
    "the card renders the batch outcome summary");

  const withoutConfirm = renderToStaticMarkup(createElement(SourceConnectionCard, {
    group,
    confirmBatch: { canConfirm: false, busy: false, summary: null, onConfirm: () => {} },
  }));
  check(!withoutConfirm.includes("Confirm all 2"), "a viewer who cannot confirm sees no bulk action");

  const nothingAwaiting = renderToStaticMarkup(createElement(SourceConnectionCard, {
    group: { ...group, tables: [active] },
    confirmBatch: { canConfirm: true, busy: false, summary: null, onConfirm: () => {} },
  }));
  check(!nothingAwaiting.includes("Tables awaiting confirmation"),
    "a connection with nothing awaiting confirmation shows no bulk action");

  // --- 5. the batch registration body -------------------------------------
  const requests: PostgresRegistrationRequest[] = [
    { view: view({ view_id: "sdv_" + "1".repeat(64), relation_name: "small" }), body: undefined },
    { view: view({ view_id: "sdv_" + "2".repeat(64), relation_name: "large", approx_row_count: 5_000_000 }), body: { mode: "QUERY_ONLY" } },
    { view: view({ view_id: "sdv_" + "3".repeat(64), relation_name: "narrowed" }), body: { excluded_columns: [2, 3] } },
  ];
  const registrationBody = postgresRegistrationBatchBody(requests);
  check(registrationBody.items.length === 3 &&
    JSON.stringify(registrationBody.items[0]) === JSON.stringify({ view_id: "sdv_" + "1".repeat(64) }) &&
    JSON.stringify(registrationBody.items[1]) === JSON.stringify({ view_id: "sdv_" + "2".repeat(64), mode: "QUERY_ONLY" }) &&
    JSON.stringify(registrationBody.items[2]) === JSON.stringify({ view_id: "sdv_" + "3".repeat(64), excluded_columns: [2, 3] }),
    "one batch body carries each table's own mode and exclusions");
  check(POSTGRES_REGISTRATION_BATCH_LIMIT === 200, "the wizard's batch registration bound is 200 tables");

  if (failures !== 0) throw new Error(`${failures} batch confirmation assertion(s) failed`);
  console.log("source confirm batch probe: PASS");
}

main();
