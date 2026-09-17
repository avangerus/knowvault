# ADR-0009: Supply chain for build-only tools

Status: `ACCEPTED`

## Context

Stage 0 uses JavaScript only for UI assembly and JSON Schema validation. The production runtime does not contain Node.js. Nevertheless, every package inside the builder image and every transitive test dependency is part of the licensing and reproducible surface.

## Solution

- The only project package manager is pnpm `11.4.0`, pinned by field `packageManager` along with SHA-512 and `pnpm-lock.yaml`.
- pnpm is activated by bundled Corepack `0.35.0` from the exact Node `24.18.0` builder image. Package scripts are disabled upon installation.
- Bundled npm CLI `11.16.0` and Yarn Classic `1.22.22` are not used as package managers but remain visible in the SBOM builder image. `Artistic-2.0` npm is conditionally allowed only for this exact build-only delivery; npm/Yarn are not copied into the production image.
- Ajv, ajv-formats, and all their transitive packages are fixed by lockfile integrity, pass license tests, and are absent from the production runtime.
- pgx, sqlc, oapi-codegen, and Syft are pinned to exact version/source checksum evidence in `architecture/versions.json`. The offline release bundle must contain already verified sources/binaries; runtime downloads are prohibited.

## Consequences

CI rejects `package-lock.json`, `npm install`, `npm ci` and floating package-manager activation. Any change to builder digest, package manager, bundled npm/Corepack version, dependency graph, or conditional license exception requires a version/license lock update and a new architectural review.
