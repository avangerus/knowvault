// S1 — PostgreSQL base-table sources (ADR-0097): in-tree UI probe for the
// widened discovery catalog and the multi-select registration flow.
//
// This is a plain TypeScript module exercised by the repository's pinned
// esbuild + node toolchain (no test framework, no new dependency), matching
// the pattern used by workspace_selection_test.ts and governed_preset_test.ts.
// It renders the real production exports from main.tsx through
// react-dom/server and calls the real pure planning/filtering functions, so
// the large-database catalog surface is no longer narrative-only:
//
//   1. the new SourceDiscoveryView/SourceDiscoveryColumn fields decode and
//      render: approx_row_count (including the -1 "unknown" sentinel),
//      the widened relation_kind (TABLE/PARTITIONED_TABLE), the
//      NO_PRIMARY_KEY interpretation reason, and per-column primary_key;
//   2. ticking several tables and unticking columns per table produces one
//      register request per ticked table, each carrying only that table's
//      own excluded_columns (sorted, omitted when empty);
//   3. a primary-key column can never be toggled into excluded_columns;
//   4. the filter box and the sort control narrow and order a large catalog
//      without a second network call;
//   5. only a TABLE/PARTITIONED_TABLE selection offers column exclusion —
//      the original five-column VIEW/MATERIALIZED_VIEW contract stays as-is.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  PostgreSQLDiscoveredColumn,
  PostgreSQLDiscoveredViewCard,
  postgresFilterAndSortViews,
  postgresIsColumnExcludable,
  postgresRegistrationPlan,
  postgresToggleExcludedColumn,
  postgresViewDisplayName,
  type PostgresRegistrationRequest,
  type SourceDiscoveryColumn,
  type SourceDiscoveryView,
} from "./main";

let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}

function column(overrides: Partial<SourceDiscoveryColumn> & { ordinal: number; name: string }): SourceDiscoveryColumn {
  return {
    type_name: "text",
    logical_type: "TEXT",
    nullable: true,
    roles: [],
    primary_key: false,
    ...overrides,
  };
}

function view(overrides: Partial<SourceDiscoveryView> & { view_id: string; relation_name: string }): SourceDiscoveryView {
  return {
    schema_name: "public",
    relation_kind: "TABLE",
    approx_row_count: 0,
    status: "PREPARED",
    columns: [],
    ...overrides,
  };
}

function main(): void {
  // --- 1. decoding of new fields: row count, widened kind, key badge -----
  const idColumn = column({ ordinal: 1, name: "id", primary_key: true, roles: ["IDENTITY"] });
  const nameColumn = column({ ordinal: 2, name: "full_name", roles: ["EVIDENCE"] });
  const wasteTable = view({
    view_id: "sdv_" + "a".repeat(64),
    relation_name: "waste_site",
    relation_kind: "TABLE",
    approx_row_count: 17030,
    columns: [idColumn, nameColumn],
  });
  const preparedMarkup = renderToStaticMarkup(createElement(PostgreSQLDiscoveredViewCard, {
    disabled: false,
    excludedColumns: [],
    onToggleColumn: () => {},
    onToggleSelected: () => {},
    selected: false,
    view: wasteTable,
  }));
  check(preparedMarkup.includes("Table"), "the widened TABLE relation_kind renders its label");
  check(preparedMarkup.includes("~17,030 rows"), "approx_row_count renders as a formatted, approximate row count");
  check(preparedMarkup.includes("Key"), "a primary_key column carries a visible key badge");
  check(preparedMarkup.includes('type="checkbox"'), "a PREPARED table renders a selection checkbox");

  const partitioned = view({
    view_id: "sdv_" + "b".repeat(64),
    relation_name: "invoice_2026",
    relation_kind: "PARTITIONED_TABLE",
    approx_row_count: -1,
    columns: [idColumn],
  });
  const partitionedMarkup = renderToStaticMarkup(createElement(PostgreSQLDiscoveredViewCard, {
    disabled: false,
    excludedColumns: [],
    onToggleColumn: () => {},
    onToggleSelected: () => {},
    selected: false,
    view: partitioned,
  }));
  check(partitionedMarkup.includes("Partitioned table"), "the widened PARTITIONED_TABLE relation_kind renders its label");
  check(partitionedMarkup.includes("Row count unknown"), "an unanalyzed relation's approx_row_count of -1 never renders as a number");

  const keylessTable = view({
    view_id: "sdv_" + "c".repeat(64),
    relation_name: "legacy_dump",
    relation_kind: "TABLE",
    approx_row_count: 4,
    status: "NEEDS_INTERPRETATION",
    interpretation: "NO_PRIMARY_KEY",
    columns: [column({ ordinal: 1, name: "col_a" })],
  });
  const keylessMarkup = renderToStaticMarkup(createElement(PostgreSQLDiscoveredViewCard, {
    disabled: false,
    excludedColumns: [],
    onToggleColumn: () => {},
    onToggleSelected: () => {},
    selected: false,
    view: keylessTable,
  }));
  check(keylessMarkup.includes("table has no primary key"), "NO_PRIMARY_KEY renders its own reason, distinct from the original view-shaped reasons");
  check(!keylessMarkup.includes('type="checkbox"'), "a table that needs interpretation offers no selection checkbox");

  // --- 2. only TABLE/PARTITIONED_TABLE offer column exclusion ------------
  const viewKindRelation = view({
    view_id: "sdv_" + "d".repeat(64),
    relation_name: "v_kpi_value",
    relation_kind: "VIEW",
    approx_row_count: 200,
    columns: [idColumn, nameColumn],
  });
  const viewKindMarkup = renderToStaticMarkup(createElement(PostgreSQLDiscoveredViewCard, {
    disabled: false,
    excludedColumns: [],
    onToggleColumn: () => {},
    onToggleSelected: () => {},
    selected: false,
    view: viewKindRelation,
  }));
  const viewKindCheckboxCount = (viewKindMarkup.match(/type="checkbox"/g) ?? []).length;
  check(viewKindCheckboxCount === 1, "a VIEW relation offers exactly the row-selection checkbox, no per-column exclusion checkboxes");

  const tableColumnMarkup = renderToStaticMarkup(createElement(PostgreSQLDiscoveredColumn, {
    column: idColumn,
    disabled: false,
    excluded: false,
    onToggleExcluded: () => {},
    view: wasteTable,
  }));
  check(tableColumnMarkup.includes('type="checkbox"') && tableColumnMarkup.includes("disabled"),
    "a primary-key column's exclusion checkbox always renders disabled");

  // --- 3. key columns are never excludable --------------------------------
  check(postgresIsColumnExcludable(nameColumn), "a non-key EVIDENCE column is excludable");
  check(!postgresIsColumnExcludable(idColumn), "a primary-key column is never excludable");

  const afterKeyToggle = postgresToggleExcludedColumn([], idColumn);
  check(afterKeyToggle.length === 0, "toggling a primary-key column is a silent no-op, never adding it to excluded_columns");

  let excluded = postgresToggleExcludedColumn([], nameColumn);
  check(excluded.join(",") === "2", "toggling a non-key column excludes it");
  excluded = postgresToggleExcludedColumn(excluded, nameColumn);
  check(excluded.length === 0, "toggling an already-excluded column includes it again");

  const thirdColumn = column({ ordinal: 3, name: "note" });
  const multiExcluded = postgresToggleExcludedColumn(postgresToggleExcludedColumn([], thirdColumn), nameColumn);
  check(multiExcluded.join(",") === "2,3", "excluded ordinals stay sorted regardless of toggle order");

  // --- 4. multi-select -> one register call per table, correct bodies ----
  const readyA = view({ view_id: "sdv_" + "1".repeat(64), relation_name: "container_group", columns: [idColumn, nameColumn, thirdColumn] });
  const readyB = view({ view_id: "sdv_" + "2".repeat(64), relation_name: "contract", columns: [idColumn] });
  const needsWork = view({ view_id: "sdv_" + "3".repeat(64), relation_name: "staff", status: "NEEDS_INTERPRETATION", interpretation: "NO_PRIMARY_KEY" });
  const catalog = [readyA, readyB, needsWork];

  const selection = new Set([readyA.view_id, readyB.view_id, needsWork.view_id]); // a stale/defensive selection also names the unusable table
  const exclusions = new Map<string, readonly number[]>([
    [readyA.view_id, [3, 2]], // unsorted input must still produce a sorted, deduped-order body
    [needsWork.view_id, [1]], // exclusions recorded against an unusable table must never reach the plan
  ]);
  const plan: PostgresRegistrationRequest[] = postgresRegistrationPlan(catalog, selection, exclusions);

  check(plan.length === 2, "the plan contains exactly the ticked PREPARED tables, one entry per table");
  check(plan.every(({ view: planned }) => planned.status === "PREPARED"), "a NEEDS_INTERPRETATION table is never included in the registration plan even if it was ticked");
  const planA = plan.find(({ view: planned }) => planned.view_id === readyA.view_id);
  const planB = plan.find(({ view: planned }) => planned.view_id === readyB.view_id);
  check(!!planA && JSON.stringify(planA.body) === JSON.stringify({ excluded_columns: [2, 3] }), "excluded_columns in the request body is sorted ascending, independent of toggle/insert order");
  check(!!planB && planB.body === undefined, "a table with no excluded columns registers with no body, exactly like the original single-view flow");

  const emptyPlan = postgresRegistrationPlan(catalog, new Set(), new Map());
  check(emptyPlan.length === 0, "an empty selection produces an empty plan");

  // --- 5. filter box and sort control -------------------------------------
  const bigCatalog: SourceDiscoveryView[] = [
    view({ view_id: "sdv_" + "4".repeat(64), schema_name: "ops", relation_name: "container_group", approx_row_count: 17030 }),
    view({ view_id: "sdv_" + "5".repeat(64), schema_name: "ops", relation_name: "contract", approx_row_count: 900000 }),
    view({ view_id: "sdv_" + "6".repeat(64), schema_name: "billing", relation_name: "invoice", approx_row_count: -1 }),
    view({ view_id: "sdv_" + "7".repeat(64), schema_name: "billing", relation_name: "invoice_line", approx_row_count: 42 }),
  ];

  const filteredByPrefix = postgresFilterAndSortViews(bigCatalog, "invoice", "name");
  check(filteredByPrefix.map(postgresViewDisplayName).join(",") === "billing.invoice,billing.invoice_line",
    "the filter box narrows a large catalog by a case-insensitive schema.table substring");

  const filteredCaseInsensitive = postgresFilterAndSortViews(bigCatalog, "CONTAINER", "name");
  check(filteredCaseInsensitive.length === 1 && filteredCaseInsensitive[0]?.relation_name === "container_group",
    "the filter is case-insensitive");

  const sortedByName = postgresFilterAndSortViews(bigCatalog, "", "name");
  check(sortedByName.map(postgresViewDisplayName).join(",") === "billing.invoice,billing.invoice_line,ops.container_group,ops.contract",
    "the name sort orders the full catalog alphabetically by schema.table");

  const sortedByRows = postgresFilterAndSortViews(bigCatalog, "", "rows");
  check(sortedByRows.map((item) => item.relation_name).join(",") === "contract,container_group,invoice_line,invoice",
    "the row-count sort orders descending by approx_row_count, with an unanalyzed (-1) relation sorted last");

  if (failures !== 0) throw new Error(`${failures} postgres-table-discovery assertion(s) failed`);
  console.log("postgres table discovery probe: PASS");
}

main();
