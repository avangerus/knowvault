import fs from "node:fs";

const input = process.argv[2];
if (!input) throw new Error("Usage: node license-tests.mjs <pnpm-licenses.json>");

const report = JSON.parse(fs.readFileSync(input, "utf8"));
const expected = new Map([
  ["ajv", "8.20.0"],
  ["ajv-formats", "3.0.1"],
  ["fast-deep-equal", "3.1.3"],
  ["fast-uri", "3.1.6"],
  ["json-schema-traverse", "1.0.0"],
  ["require-from-string", "2.0.2"]
]);
const allowedLicenses = new Set(["MIT", "BSD-3-Clause"]);
const seen = new Set();

for (const [license, packages] of Object.entries(report)) {
  if (!allowedLicenses.has(license)) throw new Error(`Disallowed or unknown license: ${license}`);
  for (const pkg of packages) {
    if (!expected.has(pkg.name)) throw new Error(`Unexpected package in contract-test dependency graph: ${pkg.name}`);
    const versions = Array.isArray(pkg.versions) ? pkg.versions : [];
    if (versions.length !== 1 || versions[0] !== expected.get(pkg.name)) {
      throw new Error(`Version mismatch for ${pkg.name}: ${versions.join(",")}`);
    }
    if (seen.has(pkg.name)) throw new Error(`Duplicate license record for ${pkg.name}`);
    seen.add(pkg.name);
  }
}

for (const name of expected.keys()) {
  if (!seen.has(name)) throw new Error(`Missing license record for ${name}`);
}

console.log(`License suite passed: ${seen.size}/${expected.size}`);
