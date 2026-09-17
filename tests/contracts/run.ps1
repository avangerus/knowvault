param(
    [switch]$LocalNode
)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$goImage = 'golang:1.26.5-bookworm@sha256:e60d708a92ad26a6d61901334510d3debd23ddcba125663ecd6008d42e8ec669'
$nodeImage = 'node:24.18.0-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d'

if ($LocalNode) {
    Push-Location $PSScriptRoot
    try {
        corepack pnpm install --frozen-lockfile --ignore-scripts
        if ($LASTEXITCODE -ne 0) { throw "pnpm install failed with exit code $LASTEXITCODE" }
        corepack pnpm run test:schema
        if ($LASTEXITCODE -ne 0) { throw "schema suite failed with exit code $LASTEXITCODE" }
        corepack pnpm run test:licenses
        if ($LASTEXITCODE -ne 0) { throw "license suite failed with exit code $LASTEXITCODE" }
    }
    finally {
        Pop-Location
    }
}
else {
    docker run --rm `
        -v "${repo}:/repo:ro" `
        -w /tmp/contracts `
        -e REPO_ROOT=/repo `
        $nodeImage `
        sh -ceu 'cp /repo/tests/contracts/package.json /repo/tests/contracts/pnpm-lock.yaml /repo/tests/contracts/schema-tests.mjs /repo/tests/contracts/license-tests.mjs .; corepack pnpm install --frozen-lockfile --ignore-scripts; node schema-tests.mjs; corepack pnpm licenses list --json > licenses.json; node license-tests.mjs licenses.json'
    if ($LASTEXITCODE -ne 0) { throw "pinned Node suite failed with exit code $LASTEXITCODE" }
}

docker run --rm `
    -v "${repo}:/repo:ro" `
    -w /tmp/web `
    $nodeImage `
    sh -ceu 'cp /repo/web/package.json /repo/web/pnpm-lock.yaml /repo/tests/contracts/web-license-tests.mjs .; corepack pnpm install --frozen-lockfile --ignore-scripts; corepack pnpm licenses list --json > licenses.json; node web-license-tests.mjs licenses.json'
if ($LASTEXITCODE -ne 0) { throw "pinned Web dependency license suite failed with exit code $LASTEXITCODE" }

docker run --rm `
    -v "${repo}:/repo:ro" `
    -w /repo/tests/contracts/runner `
    -e REPO_ROOT=/repo `
    -e GOTOOLCHAIN=local `
    -e GOEXPERIMENT=jsonv2 `
    $goImage `
    go test -count=1 ./...
if ($LASTEXITCODE -ne 0) { throw "pinned Go suite failed with exit code $LASTEXITCODE" }
