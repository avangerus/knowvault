import fs from "node:fs";

const input = process.argv[2];
if (!input) throw new Error("Usage: node web-license-tests.mjs <pnpm-licenses.json>");

const report = JSON.parse(fs.readFileSync(input, "utf8"));
const expected = new Map([
  ["@esbuild/linux-x64", { version: "0.28.1", license: "MIT" }],
  ["@types/react", { version: "19.2.7", license: "MIT" }],
  ["@types/react-dom", { version: "19.2.3", license: "MIT" }],
  ["csstype", { version: "3.2.3", license: "MIT" }],
  ["esbuild", { version: "0.28.1", license: "MIT" }],
  ["react", { version: "19.2.6", license: "MIT" }],
  ["react-dom", { version: "19.2.6", license: "MIT" }],
  ["scheduler", { version: "0.27.0", license: "MIT" }],
  ["typescript", { version: "6.0.3", license: "Apache-2.0" }]
]);
const seen = new Set();

for (const [license, packages] of Object.entries(report)) {
  for (const pkg of packages) {
    const wanted = expected.get(pkg.name);
    if (!wanted) throw new Error(`Unexpected package in Linux UI build graph: ${pkg.name}`);
    if (license !== wanted.license || pkg.license !== wanted.license) {
      throw new Error(`License mismatch for ${pkg.name}: ${license}/${pkg.license}`);
    }
    const versions = Array.isArray(pkg.versions) ? pkg.versions : [];
    if (versions.length !== 1 || versions[0] !== wanted.version) {
      throw new Error(`Version mismatch for ${pkg.name}: ${versions.join(",")}`);
    }
    if (seen.has(pkg.name)) throw new Error(`Duplicate UI license record: ${pkg.name}`);
    seen.add(pkg.name);
  }
}

for (const name of expected.keys()) {
  if (!seen.has(name)) throw new Error(`Missing UI license record: ${name}`);
}

console.log(`Web license suite passed: ${seen.size}/${expected.size}`);
