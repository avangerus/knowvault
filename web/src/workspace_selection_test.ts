import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  activeWorkspaceSummaries,
  archivedWorkspaceSummaries,
  automaticWorkspaceSelection,
  WorkspaceSwitcher,
  type WorkspaceSummary,
} from "./main";
let failures = 0;

function check(condition: boolean, message: string): void {
  if (condition) return;
  failures += 1;
  console.error(`FAIL ${message}`);
}
function workspace(id: string, status: string): WorkspaceSummary {
  return { id, name: id, status, revision: 1, role: "OWNER" };
}
function main(): void {
  const summaries = [
    workspace("archived-first", "ARCHIVED"),
    workspace("active-one", "ACTIVE"),
    workspace("read-only", "READ_ONLY"),
    workspace("archived-second", "ARCHIVED"),
  ];
  check(
    activeWorkspaceSummaries(summaries).map(({ id }) => id).join(",") === "active-one",
    "primary workspace summaries contain ACTIVE workspaces only",
  );
  check(
    archivedWorkspaceSummaries(summaries).map(({ id }) => id).join(",") === "archived-first,archived-second",
    "archived workspace records remain available to the archived projection",
  );
  check(
    automaticWorkspaceSelection(summaries) === "active-one",
    "automatic selection skips an ARCHIVED first row and chooses the first ACTIVE workspace",
  );
  check(
    automaticWorkspaceSelection([workspace("archived-only", "ARCHIVED")]) === null,
    "automatic selection never chooses an ARCHIVED workspace",
  );
  const markup = renderToStaticMarkup(createElement(WorkspaceSwitcher, {
    onClose: () => {},
    onCreate: () => {},
    onSelect: () => {},
    onToggle: () => {},
    open: true,
    selectedID: "active-one",
    workspaces: summaries,
  }));
  check(markup.includes("active-one") && !markup.includes("read-only"), "the open primary list omits non-ACTIVE workspace rows");
  check(markup.includes("Archived (2)") && markup.includes("archived-first") && markup.includes("archived-second"), "archived workspaces stay reachable in a collapsed count section");

  if (failures !== 0) throw new Error(`${failures} workspace-selection assertion(s) failed`);
  console.log("workspace selection probe: PASS");
}

main();
