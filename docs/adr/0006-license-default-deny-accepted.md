# ADR-0006: License default-deny

Status: `ACCEPTED`

## Solution

A new direct, transitive, container, or model dependency is prohibited until its SPDX license, source, exact version/revision, and notices are included in release artifacts and approved by `architecture/licenses.yaml`.

## Why

Enterprise/on-edge delivery distributes executable files, containers, and model weights. Checking only the original Go/npm dependencies is incomplete.

## Consequences

Unknown license breaks the build. Granular exceptions require a separate license ADR. Build-only tools, shipped OCI packages, application dependencies, and model artifacts are checked separately. Unmodified standalone GPL/LGPL OS package is not allowed automatically: package-level SBOM, legal approval, source-compliance evidence, and notices are required; copyleft-linked application library remains prohibited without a separate ADR.
