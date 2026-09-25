// S3 card 4 — query-only ("only for SQL queries, not indexed") registration:
// in-tree UI probe for the wizard's mode offering, its large/partitioned
// default and the bulk selection surface.
//
// This is a plain TypeScript module exercised by the repository's pinned
// esbuild + node toolchain (no test framework, no new dependency), matching
// the pattern used by postgres_table_discovery_test.ts. It renders the real
// production exports from main.tsx through react-dom/server and calls the real
// pure planning functions:
//
//   1. a partitioned table, and a table whose row estimate is above
//      1,000,000, default to QUERY_ONLY; a small table defaults to INDEXED;
//   2. the register plan sends mode=QUERY_ONLY for such a table (with its own
//      excluded_columns when present) and leaves an indexed table's body
//      exactly as before;
//   3. the discovered-view card renders the mode control and its copy;
//   4. the schema selection helper exposes exactly the schemas with a ready
//      relation, sorted, so a 600-table catalog can be selected whole.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  POSTGRES_QUERY_ONLY_ROW_THRESHOLD,
  PostgreSQLDiscoveredViewCard,
  postgresDefaultRegistrationMode,
  postgresEffectiveRegistrationMode,
  postgresRegistrationPlan,
  postgresSelectableSchemas,
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
  const idColumn = column({ ordinal: 1, name: "id", primary_key: true, roles: ["IDENTITY"] });
  const nameColumn = column({ ordinal: 2, name: "name", roles: ["EVIDENCE"] });

  // --- 1. default mode by kind and row estimate ---------------------------
  const smallTable = view({ view_id: "sdv_" + "a".repeat(64), relation_name: "small_table", approx_row_count: 42, columns: [idColumn] });
  const largeTable = view({ view_id: "sdv_" + "b".repeat(64), relation_name: "trips", approx_row_count: 12_000_000, columns: [idColumn, nameColumn] });
  const thresholdTable = view({ view_id: "sdv_" + "c".repeat(64), relation_name: "at_threshold", approx_row_count: POSTGRES_QUERY_ONLY_ROW_THRESHOLD, columns: [idColumn] });
  const partitioned = view({
    view_id: "sdv_" + "d".repeat(64),
    relation_name: "weighings",
    relation_kind: "PARTITIONED_TABLE",
    approx_row_count: -1,
    columns: [idColumn, nameColumn],
  });

  check(postgresDefaultRegistrationMode(smallTable) === "INDEXED", "a small table is offered indexed by default");
  check(postgresDefaultRegistrationMode(largeTable) === "QUERY_ONLY", "a table above the row threshold is offered query-only by default");
  check(postgresDefaultRegistrationMode(thresholdTable) === "INDEXED", "a table exactly at the threshold is still offered indexed (strictly above)");
  check(postgresDefaultRegistrationMode(partitioned) === "QUERY_ONLY", "a partitioned table is offered query-only by default even without a row estimate");

  // --- 2. plan bodies ------------------------------------------------------
  const explicit = new Map<string, string>([[smallTable.view_id, "INDEXED"]]);
  check(postgresEffectiveRegistrationMode(smallTable, explicit) === "INDEXED", "an explicit choice overrides the default");
  check(postgresEffectiveRegistrationMode(largeTable, explicit) === "QUERY_ONLY", "an unset table keeps its kind/size default");

  const catalog = [smallTable, largeTable, partitioned];
  const plan = postgresRegistrationPlan(catalog, new Set(catalog.map((item) => item.view_id)), new Map());
  const planSmall = plan.find(({ view: item }) => item.view_id === smallTable.view_id);
  const planLarge = plan.find(({ view: item }) => item.view_id === largeTable.view_id);
  const planPartitioned = plan.find(({ view: item }) => item.view_id === partitioned.view_id);
  check(!!planSmall && planSmall.body === undefined, "an indexed table with no exclusions still registers with no body");
  check(!!planLarge && JSON.stringify(planLarge.body) === JSON.stringify({ mode: "QUERY_ONLY" }), "a large table's body carries mode=QUERY_ONLY");
  check(!!planPartitioned && JSON.stringify(planPartitioned.body) === JSON.stringify({ mode: "QUERY_ONLY" }), "a partitioned table's body carries mode=QUERY_ONLY");

  const narrowed = postgresRegistrationPlan(catalog, new Set([largeTable.view_id]),
    new Map([[largeTable.view_id, [2]]]), new Map([[largeTable.view_id, "QUERY_ONLY"]]));
  check(narrowed.length === 1 && JSON.stringify(narrowed[0]?.body) === JSON.stringify({ excluded_columns: [2], mode: "QUERY_ONLY" }),
    "a query-only table keeps its excluded_columns alongside the mode");

  const forcedIndexed = postgresRegistrationPlan(catalog, new Set([largeTable.view_id]),
    new Map(), new Map([[largeTable.view_id, "INDEXED"]]));
  check(forcedIndexed.length === 1 && forcedIndexed[0]?.body === undefined,
    "the administrator can force a large table back to indexed");

  // --- 3. the card renders the mode control --------------------------------
  const markup = renderToStaticMarkup(createElement(PostgreSQLDiscoveredViewCard, {
    disabled: false,
    excludedColumns: [],
    mode: "QUERY_ONLY",
    onToggleColumn: () => {},
    onToggleMode: () => {},
    onToggleSelected: () => {},
    selected: true,
    view: partitioned,
  }));
  check(markup.includes("Only for SQL queries (not indexed)"), "the card renders the query-only mode label");
  check(markup.includes("Rows are not copied into search"), "the card explains that query-only rows are not copied into search");

  const indexedMarkup = renderToStaticMarkup(createElement(PostgreSQLDiscoveredViewCard, {
    disabled: false,
    excludedColumns: [],
    mode: "INDEXED",
    onToggleColumn: () => {},
    onToggleMode: () => {},
    onToggleSelected: () => {},
    selected: false,
    view: smallTable,
  }));
  check(indexedMarkup.includes("Rows are copied into search"), "the card explains that indexed rows are searchable");

  // --- 4. schema bulk selection -------------------------------------------
  const bigCatalog: SourceDiscoveryView[] = [
    view({ view_id: "sdv_" + "1".repeat(64), schema_name: "ops", relation_name: "container_group" }),
    view({ view_id: "sdv_" + "2".repeat(64), schema_name: "ops", relation_name: "contract" }),
    view({ view_id: "sdv_" + "3".repeat(64), schema_name: "billing", relation_name: "invoice", approx_row_count: 5_000_000 }),
    view({ view_id: "sdv_" + "4".repeat(64), schema_name: "billing", relation_name: "legacy", status: "NEEDS_INTERPRETATION", interpretation: "NO_PRIMARY_KEY" }),
  ];
  check(postgresSelectableSchemas(bigCatalog).join(",") === "billing,ops",
    "only schemas with at least one ready relation are offered, sorted");

  if (failures !== 0) throw new Error(`${failures} postgres query-only assertion(s) failed`);
  console.log("postgres query-only probe: PASS");
}

main();
