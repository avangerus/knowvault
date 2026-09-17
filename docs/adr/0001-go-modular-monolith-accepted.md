# ADR-0001: Go modular monolith

Status: `ACCEPTED`

## Solution

The applied backend, workers, and Connector Agent are implemented in Go within a single modular repository. The UI is implemented in TypeScript/React and delivered as static assets inside the server image. The initial choice of Vite for UI build was replaced by ADR-0011 with a minimal esbuild pipeline; the application form and runtime boundary remain unchanged.

Three application binaries are allowed: `knowvault-server`, `knowvault-worker`, `knowvault-connector`.

## Why

- static build and convenient on-edge delivery;
- common connector contract for server and remote agent;
- strict typing and suitable concurrency model;
- models are accessible via HTTP and do not require Python in application code;
- BSD-style Go license;
- absence of Node runtime in production.

## Consequences

Tika, OCR, and models run as isolated runtime adapters. Adding Python, Java, or C# to application modules requires a new ADR.
