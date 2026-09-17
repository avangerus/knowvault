param(
    [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot ".."))
)

$ErrorActionPreference = "Stop"

if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
    Write-Error "Go is unavailable: run the same checker with the pinned builder image from architecture/versions.json."
}

& go run (Join-Path $PSScriptRoot "check-architecture.go") -root $Root
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
