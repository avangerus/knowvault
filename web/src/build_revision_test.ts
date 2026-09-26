// Card W-4 — the interface shows which version is running.
//
// This is a plain TypeScript probe exercised by the repository's pinned
// esbuild + node toolchain (no test framework, no new dependency). It drives
// the real pure projection the top-bar revision mark renders and binds it to
// the server contract it depends on:
//
//   1. the interface fetches the running server's build information from the
//      exact path internal/platform/systemapi declares, and reads the exact
//      `revision` field that handler returns — the value is never typed into
//      the bundle, so a web build shipped beside a newer server cannot claim
//      its own revision;
//   2. a server revision is rendered as its short form: a full commit hash is
//      never printed whole;
//   3. a build without a known revision renders the neutral mark instead of a
//      wrong number;
//   4. the mark lives in the application header, which every screen shares.
//
// It reads production source only; it changes no payload and no product text.

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  BUILD_REVISION_NEUTRAL,
  BuildRevisionMark,
  buildRevisionFromInfo,
  shortBuildRevision,
} from "./main";

declare const require: (moduleName: string) => { readFileSync(path: string, encoding: string): string };
const fs = require("fs");
const mainSource = fs.readFileSync("src/main.tsx", "utf8");
const systemHandlerSource = fs.readFileSync("../internal/platform/systemapi/handler.go", "utf8");

let failures = 0;
const check = (ok: boolean, message: string) => { if (!ok) { failures++; console.error(`FAIL ${message}`); } };

// The server-declared build-info path and revision JSON field, read from the Go
// contract instead of hand-copied here. A rename on the server breaks this
// probe rather than silently leaving the interface pointing at nothing.
const buildInfoPath = /BuildInfoPath\s*=\s*"([^"]+)"/.exec(systemHandlerSource)?.[1] ?? "";
const revisionField = /Revision\s+string\s+`json:"([^"]+)"/.exec(systemHandlerSource)?.[1] ?? "";
check(buildInfoPath === "/api/v1/system/build-info", `server build-info path parsed as ${JSON.stringify(buildInfoPath)}`);
check(revisionField === "revision", `server revision field parsed as ${JSON.stringify(revisionField)}`);
check(
  mainSource.includes(`fetch(${JSON.stringify(buildInfoPath)}, { cache: "no-store" })`),
  `the interface fetches ${buildInfoPath} from the running server without caching`,
);

// The revision is read from the server payload, never from a bundle-time
// constant.
const fullRevision = "9c1f4a7e2b3d5f6081a2c3d4e5f60718293a4b5c";
check(shortBuildRevision(fullRevision) === "9c1f4a7", "a full commit hash is shortened to its leading characters");
check(shortBuildRevision(fullRevision)?.length === 7, "the short form is exactly seven characters");
check(
  buildRevisionFromInfo({ version: "1.2.3", revision: fullRevision, built_at: "2026-07-14T12:00:00Z" }) === fullRevision,
  `the interface reads the server's ${JSON.stringify(revisionField)} field`,
);
check(buildRevisionFromInfo({}) === "" && buildRevisionFromInfo(null) === "", "a payload without a revision reads as no revision");
check(!mainSource.includes(fullRevision), "no revision number is typed into the interface source");

const mark = (revision: string | null | undefined) => renderToStaticMarkup(createElement(BuildRevisionMark, { revision }));
const built = mark(fullRevision);
check(built.includes("9c1f4a7"), "a built server revision is rendered");
check(!built.includes(fullRevision), "the full commit hash is never rendered whole");
check(!/[0-9a-f]{8}/.test(built), "nothing longer than the short form is rendered");

// Requirement 3: a build without a known revision is neutral, not wrong.
for (const [name, revision] of [["empty", ""], ["unknown", "unknown"], ["missing", null], ["blank", "   "]] as const) {
  const neutral = mark(revision);
  check(neutral.includes(BUILD_REVISION_NEUTRAL), `a ${name} revision shows the neutral mark`);
  check(!/[0-9a-f]{4}/.test(neutral), `the ${name} neutral mark is not a number`);
}

// Requirement 2: the mark is in the header every screen shares, so it cannot
// drift between the workspace screens or disappear on the evidence page.
const headerStart = mainSource.indexOf('<header className="top-bar">');
const headerEnd = mainSource.indexOf("</header>", headerStart);
check(headerStart >= 0 && headerEnd > headerStart, "the application header was located");
const headerSource = mainSource.slice(headerStart, headerEnd);
check(headerSource.includes("<BuildRevisionMark"), "the revision mark is rendered in the shared header");

// A thrown assertion terminates node with a non-zero exit code; the probe has
// no other output on failure.
if (failures !== 0) throw new Error(`${failures} build revision probe check(s) failed`);
console.log("build revision probe: PASS");
