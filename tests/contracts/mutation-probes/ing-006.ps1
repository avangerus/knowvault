# Dual-layer probe for ING-006: transient source bytes never reach durable sinks.
# The invariant is enforced by two independent layers:
#   (1) Go gate  — internal/jobs/jobs.go sha256Pattern on hash payload keys;
#   (2) DB gate  — db/migrations/000013 CHECK (app.job_payload_is_safe(payload_json)).
# A single-anchor mutation can weaken at most one layer; the product test
# TestFolderConnectorTransientBytesNeverReachDurableSinks must therefore stay
# GREEN under either one-layer weakening and go RED only when both are weakened.
#
# Usage (pwsh, any host with Go + a real PostgreSQL):
#   $env:KNOWVAULT_TEST_POSTGRES_URL = 'postgres://...'
#   $env:KNOWVAULT_TEST_OFFICE_WORKER_IMAGE = 'knowvault-document-parser-worker:1.0.0'
#   pwsh tests/contracts/mutation-probes/ing-006.ps1 -Root <repository>
# The script pins no local paths and no toolchain; GOENV/GOTOOLCHAIN/GOEXPERIMENT
# come from the calling environment.
param(
  [string]$Root = $env:KV_ROOT
)
$ErrorActionPreference = 'Stop'
if (-not $Root -or -not (Test-Path (Join-Path $Root 'go.mod'))) {
  throw "ING-006 probe requires -Root (or KV_ROOT) pointing at the repository root"
}
if (-not $env:KNOWVAULT_TEST_POSTGRES_URL) {
  throw "KNOWVAULT_TEST_POSTGRES_URL is required; the probe cannot skip PostgreSQL"
}
if (-not $env:KNOWVAULT_TEST_OFFICE_WORKER_IMAGE) {
  throw "KNOWVAULT_TEST_OFFICE_WORKER_IMAGE is required; the probe cannot skip the isolated parser"
}
$real = (Resolve-Path $Root).Path
$utf8 = New-Object System.Text.UTF8Encoding($false)

function Run-Test($dir) {
  Set-Location $dir
  $prevRepoRoot = $env:REPO_ROOT
  $env:REPO_ROOT = $dir
  $ErrorActionPreference = 'Continue'
  $out = & go test -mod=readonly -count=1 ./tests/integration/postgres -run '^TestFolderConnectorTransientBytesNeverReachDurableSinks$' 2>&1 | ForEach-Object { "$_" }
  $code = $LASTEXITCODE
  $ErrorActionPreference = 'Stop'
  $env:REPO_ROOT = $prevRepoRoot
  $out | Select-Object -Last 6 | Out-Host
  return $code
}

function New-Tree($suffix) {
  $tmp = Join-Path $env:TEMP ("kv-ing006-" + $suffix + "-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
  New-Item -ItemType Directory -Force $tmp | Out-Null
  foreach ($rel in @('api','architecture','cmd','db','deploy','docs','internal','scripts','tests','web','workers','go.mod','go.sum')) {
    Copy-Item (Join-Path $real $rel) (Join-Path $tmp $rel) -Recurse -Force
  }
  return $tmp
}

function Apply-Go-Weakening($tmp) {
  $target = Join-Path $tmp 'internal/jobs/jobs.go'
  $old = 'sha256Pattern        = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)'
  $new = 'sha256Pattern        = regexp.MustCompile(`^.*$`)'
  $s = [System.IO.File]::ReadAllText($target, $utf8)
  if (([regex]::Matches($s, [regex]::Escape($old))).Count -ne 1) { throw "GO anchor not unique" }
  [System.IO.File]::WriteAllText($target, $s.Replace($old, $new), $utf8)
}

function Apply-Db-Weakening($tmp) {
  $target = Join-Path $tmp 'db/migrations/000013_stage2_durable_ingestion_jobs.sql'
  $old = '        CHECK (app.job_payload_is_safe(payload_json)),'
  $new = '        CHECK (true),'
  $s = [System.IO.File]::ReadAllText($target, $utf8)
  if (([regex]::Matches($s, [regex]::Escape($old))).Count -ne 1) { throw "DB anchor not unique" }
  [System.IO.File]::WriteAllText($target, $s.Replace($old, $new), $utf8)
}

# (0) BASELINE — product test GREEN on the unmutated tree.
$base = Run-Test $real
Set-Location $real
if ($base -ne 0) { "BASELINE FAILED (exit $base)"; exit 2 }
"BASELINE: test PASSES as expected"

# (1) Go gate weakened only — DB gate still refuses the smuggled payload: GREEN.
$t1 = New-Tree 'go'
Apply-Go-Weakening $t1
$c1 = Run-Test $t1
Set-Location $real
Remove-Item $t1 -Recurse -Force
if ($c1 -ne 0) { "GO-WEAKENED: exit $c1 (UNEXPECTED — DB layer did not hold)"; exit 3 }
"GO-WEAKENED: test still PASSES (DB layer holds) as expected"

# (2) DB gate weakened only — Go gate still refuses the smuggled payload: GREEN.
$t2 = New-Tree 'db'
Apply-Db-Weakening $t2
$c2 = Run-Test $t2
Set-Location $real
Remove-Item $t2 -Recurse -Force
if ($c2 -ne 0) { "DB-WEAKENED: exit $c2 (UNEXPECTED — Go layer did not hold)"; exit 3 }
"DB-WEAKENED: test still PASSES (Go layer holds) as expected"

# (3) Both gates weakened — canary reaches a durable sink: RED. A single-anchor
# mutation cannot weaken both files, so no one-anchor mutation flips the test.
$t3 = New-Tree 'both'
Apply-Go-Weakening $t3
Apply-Db-Weakening $t3
$c3 = Run-Test $t3
Set-Location $real
Remove-Item $t3 -Recurse -Force
if ($c3 -eq 0) { "BOTH-WEAKENED: test PASSED (UNEXPECTED — invariant has no enforcement)"; exit 4 }
"BOTH-WEAKENED: test FAILS (RED) as expected"
'ING-006 DUAL-LAYER PROBE VERIFIED'
