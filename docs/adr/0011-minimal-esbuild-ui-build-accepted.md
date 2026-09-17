# ADR-0011: Minimal UI build with esbuild

Status: `ACCEPTED`

## Context

The direct Vite 8 license is MIT, but checking the full all-platform lock graph for pinned version 8.0.16 revealed 81 packages. The graph includes twelve variants of Lightning CSS under MPL-2.0, as well as Python-2.0, 0BSD, and `(MIT OR CC0-1.0)` expressions, which are not permitted by the current default-deny policy without a separate legal resolution. The Vite 7 variant without `openapi-typescript` reduces the graph to 67 packages and remains on the allowlist. An equivalent production React build via esbuild 0.28.1 contains 31 all-platform packages: 30 MIT and TypeScript under Apache-2.0.

HMR and the plugin ecosystem are not product 1.0 capabilities. Production receives identical static HTML, CSS, and JavaScript assets regardless of the development server's convenience.

## Solution

- UI remains on TypeScript 6.0.3, React 19.2.6, and React DOM 19.2.6.
- The only UI bundler is esbuild 0.28.1, used exclusively on the build stage.
- The lock includes the main esbuild package and all 26 of its platform-specific optional packages with exact version and SHA-512 integrity, even if a specific CI runner installs only one variant.
- `scheduler` 0.27.0 is fixed as a transitive runtime dependency of React DOM.
- Node.js, pnpm, esbuild, and TypeScript are not copied into the production image. The Go server supplies only ready-made static assets.
- `openapi-typescript` is not included in the baseline. While Web API consists of system methods, the UI uses local minimal DTOs and contract tests. Any future TypeScript generator requires a separate exact transitive lock and an architectural review.
- Installation is performed only via checksum-pinned pnpm with a frozen lockfile and disabled dependency scripts. The build invokes the pinned esbuild from the local package graph; runtime download is prohibited.
- Vite, Rollup/Rolldown, Lightning CSS, and external dev-server plugins are prohibited without a new ADR.

## Verified Alternatives

| Variant | Full all-platform graph | Licenses outside current allowlist |
|---|---:|---|
| Vite 8 + openapi-typescript | 81 | MPL-2.0, Python-2.0, 0BSD, compound expression |
| Vite 7 without openapi-typescript | 67 | none |
| esbuild without openapi-typescript | 31 | none |

Temporary comparison/proposal JSONs are not build inputs and have been removed. The source of truth consists only of `architecture/versions.json`, `architecture/licenses.yaml`, application `package.json`, and the adjacent `pnpm-lock.yaml`, which is checked by the anti-drift checker.

## Consequences

The repository owns small build/watch/serve scripts and does not receive a ready-made Vite convention. This is a conscious trade-off for a smaller supply-chain and licensing surface. Changes to the dependency graph, platform package, or package-manager metadata are blocked by the closed inventory checker and require a re-review.
