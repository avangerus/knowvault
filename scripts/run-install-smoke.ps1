[CmdletBinding()]
param(
  [Parameter(Mandatory = $false)] [string] $EvidenceDir = '',
  [ValidateRange(5, 30)] [int] $TimeoutMinutes = 15
)

# Install/run smoke for the bounded KnowVault application slice.  This is an
# operator/control-plane adapter: it runs the repository's real Docker E2E
# harness and records an immutable, machine-readable result.  It never
# substitutes an in-memory service, fixture answer or skipped dependency for
# PostgreSQL, OpenSearch or the application containers.  A smoke PASS proves
# only this bounded slice; release_eligible is deliberately always false.
$ErrorActionPreference = 'Stop'

$RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$RunStarted = [DateTime]::UtcNow
$RunId = 'install-smoke-' + $RunStarted.ToString('yyyyMMddTHHmmssfffZ')
if ([string]::IsNullOrWhiteSpace($EvidenceDir)) {
  $EvidenceDir = Join-Path 'out' $RunId
}
$EvidencePath = if ([IO.Path]::IsPathRooted($EvidenceDir)) {
  [IO.Path]::GetFullPath($EvidenceDir)
} else {
  [IO.Path]::GetFullPath((Join-Path $RepositoryRoot $EvidenceDir))
}
if ([string]::Equals($EvidencePath.TrimEnd('\', '/'), $RepositoryRoot.TrimEnd('\', '/'), [StringComparison]::OrdinalIgnoreCase)) {
  throw 'INSTALL_SMOKE_EVIDENCE_INVALID: evidence directory cannot be repository root'
}
New-Item -ItemType Directory -Force -Path $EvidencePath | Out-Null

function Sha256Text([string] $Value) {
  $bytes = [Text.Encoding]::UTF8.GetBytes($Value)
  $hash = [Security.Cryptography.SHA256]::Create()
  try { return ([BitConverter]::ToString($hash.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
  finally { $hash.Dispose() }
}

function Sha256File([string] $Path) {
  if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) { return $null }
  return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-AtomicText([string] $Path, [string] $Value) {
  $parent = Split-Path -Parent $Path
  if ([string]::IsNullOrWhiteSpace($parent)) {
    throw 'INSTALL_SMOKE_ATOMIC_WRITE_INVALID_PATH: result path has no parent'
  }
  New-Item -ItemType Directory -Force -Path $parent | Out-Null
  $leaf = Split-Path -Leaf $Path
  $temporary = Join-Path $parent ('.' + $leaf + '.' + [Guid]::NewGuid().ToString('N') + '.tmp')
  $backup = Join-Path $parent ('.' + $leaf + '.' + [Guid]::NewGuid().ToString('N') + '.bak')
  $encoding = New-Object System.Text.UTF8Encoding($false)
  try {
    $stream = [IO.File]::Open($temporary, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read)
    try {
      $bytes = $encoding.GetBytes($Value)
      $stream.Write($bytes, 0, $bytes.Length)
      $stream.Flush($true)
    } finally {
      $stream.Dispose()
    }
    if ([IO.File]::Exists($Path)) {
      [IO.File]::Replace($temporary, $Path, $backup, $true)
      if ([IO.File]::Exists($backup)) { [IO.File]::Delete($backup) }
    } else {
      [IO.File]::Move($temporary, $Path)
    }
  } finally {
    if ([IO.File]::Exists($temporary)) { [IO.File]::Delete($temporary) }
    if ([IO.File]::Exists($backup)) { [IO.File]::Delete($backup) }
  }
}

function Write-Result([string] $Status, [Nullable[int]] $ExitCode,
  [object[]] $Blockers, [object] $Preflight, [object] $Run,
  [string] $FailureCode = $null) {
  $completed = [DateTime]::UtcNow
  $result = [ordered]@{
    schema = 'knowvault-install-smoke-v1'
    run_id = $RunId
    recorded_at = $completed.ToString('O')
    started_at = $RunStarted.ToString('O')
    completed_at = $completed.ToString('O')
    repository_root = $RepositoryRoot
    evidence_directory = $EvidencePath
    status = $Status
    failure_code = $FailureCode
    exit_code = $ExitCode
    release_eligible = $false
    preflight = $Preflight
    run = $Run
    blockers = @($Blockers)
  }
  $target = Join-Path $EvidencePath 'install-smoke-result.json'
  Write-AtomicText $target ($result | ConvertTo-Json -Depth 16)
  return $target
}

function Invoke-Preflight([string] $Executable, [string[]] $Arguments, [string] $OutputPath) {
  $started = [DateTime]::UtcNow
  $output = ''
  $exitCode = 1
  $previous = $ErrorActionPreference
  try {
    $ErrorActionPreference = 'Continue'
    $output = (& $Executable @Arguments 2>&1 | Out-String)
    $exitCode = if ($null -eq $LASTEXITCODE) { 1 } else { [int]$LASTEXITCODE }
  } finally {
    $ErrorActionPreference = $previous
  }
  Write-AtomicText $OutputPath $output
  return [ordered]@{
    command = (($Executable + ' ') + ($Arguments -join ' ')).Trim()
    started_at = $started.ToString('O')
    completed_at = [DateTime]::UtcNow.ToString('O')
    exit_code = $exitCode
    output_path = $OutputPath
    output_sha256 = Sha256File $OutputPath
    output = $output.Trim()
  }
}

function Invoke-GoJsonTest([string] $Executable, [string[]] $Arguments,
  [string] $OutputPath, [string] $PassPattern, [string] $FailPattern) {
  $started = [DateTime]::UtcNow
  $output = ''
  $exitCode = 1
  $previous = $ErrorActionPreference
  try {
    Push-Location $RepositoryRoot
    try {
      $ErrorActionPreference = 'Continue'
      $output = (& $Executable @Arguments 2>&1 | Tee-Object -FilePath $OutputPath | Out-String)
      $exitCode = if ($null -eq $LASTEXITCODE) { 1 } else { [int]$LASTEXITCODE }
    } finally {
      Pop-Location
    }
  } catch {
    $output = ($_ | Out-String)
    Write-AtomicText $OutputPath $output
    $exitCode = 1
  } finally {
    $ErrorActionPreference = $previous
  }
  $raw = if (Test-Path -LiteralPath $OutputPath -PathType Leaf) { Get-Content -LiteralPath $OutputPath -Raw } else { $output }
  $pass = $raw -match $PassPattern
  $fail = $raw -match $FailPattern
  return [ordered]@{
    command = ('go ' + ($Arguments -join ' '))
    started_at = $started.ToString('O')
    completed_at = [DateTime]::UtcNow.ToString('O')
    exit_code = $exitCode
    status = if ($exitCode -eq 0 -and $pass -and -not $fail) { 'PASS' } else { 'FAILED' }
    raw_output_path = $OutputPath
    raw_output_sha256 = Sha256File $OutputPath
    observed_pass = [bool]$pass
    observed_fail = [bool]$fail
  }
}

$preflight = [ordered]@{}
$goCommand = Get-Command go -ErrorAction SilentlyContinue
$dockerCommand = Get-Command docker -ErrorAction SilentlyContinue
$blockers = New-Object System.Collections.Generic.List[object]

if ($null -eq $goCommand) {
  $blockers.Add([ordered]@{ code = 'GO_UNAVAILABLE'; detail = 'go executable is required to run the real e2e package' })
}
if ($null -eq $dockerCommand) {
  $blockers.Add([ordered]@{ code = 'DOCKER_UNAVAILABLE'; detail = 'Docker CLI is required; no mock or host-only substitute is accepted' })
}

if ($null -ne $goCommand) {
  $preflight.go = Invoke-Preflight $goCommand.Source @('version') (Join-Path $EvidencePath 'go-version.log')
  if ($preflight.go.exit_code -ne 0) {
    $blockers.Add([ordered]@{ code = 'GO_UNAVAILABLE'; detail = 'go version probe failed' })
  }
}
if ($null -ne $dockerCommand) {
  $preflight.docker = Invoke-Preflight $dockerCommand.Source @('info', '--format', '{{.ServerVersion}}') (Join-Path $EvidencePath 'docker-preflight.log')
  if ($preflight.docker.exit_code -ne 0) {
    $blockers.Add([ordered]@{ code = 'DOCKER_DAEMON_UNAVAILABLE'; detail = 'Docker daemon probe failed; the real container path is blocked' })
  }
}
$requiredDatabaseEnvironment = @('KNOWVAULT_TEST_POSTGRES_URL', 'KNOWVAULT_TEST_EXTERNAL_POSTGRES_URL')
$databaseEnvironmentMissing = @($requiredDatabaseEnvironment | Where-Object {
    $entry = Get-Item -Path ('Env:' + $_) -ErrorAction SilentlyContinue
    [string]::IsNullOrWhiteSpace([string]$entry.Value)
  })
$preflight.database = [ordered]@{
  required_environment = $requiredDatabaseEnvironment
  require_external_pg = '1'
  all_present = ($databaseEnvironmentMissing.Count -eq 0)
  missing_environment = $databaseEnvironmentMissing
}
if ($databaseEnvironmentMissing.Count -gt 0) {
  $blockers.Add([ordered]@{ code = 'POSTGRES_INPUT_UNAVAILABLE'; detail = 'both real PostgreSQL test endpoints are required for SQL business-object isolation' })
}
if ($blockers.Count -gt 0) {
  $resultPath = Write-Result 'BLOCKED' 2 $blockers $preflight $null 'PREFLIGHT_BLOCKED'
  [Console]::Error.WriteLine(('INSTALL_SMOKE status=BLOCKED result={0}' -f $resultPath))
  exit 2
}

# Bound every child process consistently with the gauntlet policy.  These are
# process-local settings; they do not reserve the host GPU or change product
# runtime configuration.
$env:GOMAXPROCS = '2'
$env:GOMEMLIMIT = '1GiB'
$env:GOEXPERIMENT = 'jsonv2'
$env:GOENV = 'off'
$env:GOTOOLCHAIN = 'go1.26.5'

$env:KNOWVAULT_REQUIRE_EXTERNAL_PG = '1'

$e2eRawPath = Join-Path $EvidencePath 'install-smoke-e2e.jsonl'
$e2eArguments = @(
  'test', '-mod=readonly', '-tags', 'e2e', '-json', './tests/e2e',
  '-run', '^TestE2ER3FullLoop$', '-count=1', '-timeout', ($TimeoutMinutes.ToString() + 'm')
)
$sqlRawPath = Join-Path $EvidencePath 'install-smoke-sql-isolation.jsonl'
$sqlArguments = @(
  'test', '-mod=readonly', '-json', './tests/integration/postgres',
  '-run', '^TestPostgreSQLQueryQuestionWorkspaceIsolation$', '-count=1', '-timeout', ($TimeoutMinutes.ToString() + 'm')
)
$e2eStep = Invoke-GoJsonTest $goCommand.Source $e2eArguments $e2eRawPath 'E2E RESULT PASS' 'E2E RESULT FAIL'
$steps = New-Object System.Collections.Generic.List[object]
$steps.Add($e2eStep)
if ($e2eStep.status -eq 'PASS') {
  $sqlStep = Invoke-GoJsonTest $goCommand.Source $sqlArguments $sqlRawPath 'TestPostgreSQLQueryQuestionWorkspaceIsolation' 'FAIL'
} else {
  $sqlStep = [ordered]@{
    command = ('go ' + ($sqlArguments -join ' '))
    status = 'NOT_RUN_DEPENDENCY'
    reason = 'the real E2E install path failed; SQL isolation was not represented as a pass'
    raw_output_path = $null
    raw_output_sha256 = $null
  }
}
$steps.Add($sqlStep)
$runStatus = if ($e2eStep.status -eq 'PASS' -and $sqlStep.status -eq 'PASS') { 'PASS' } else { 'FAILED' }
$runExitCode = if ($runStatus -eq 'PASS') { 0 } elseif ($e2eStep.exit_code -ne 0) { $e2eStep.exit_code } else { $sqlStep.exit_code }
$runRecord = [ordered]@{
  environment_contract = [ordered]@{ GOMAXPROCS = '2'; GOMEMLIMIT = '1GiB'; GOEXPERIMENT = 'jsonv2'; GOENV = 'off'; GOTOOLCHAIN = 'go1.26.5'; KNOWVAULT_REQUIRE_EXTERNAL_PG = '1' }
  status = $runStatus
  started_at = $e2eStep.started_at
  completed_at = [DateTime]::UtcNow.ToString('O')
  steps = @($steps.ToArray())
}
$finalBlockers = New-Object System.Collections.Generic.List[object]
if ($runStatus -ne 'PASS') {
  $failedStepNames = @($steps | Where-Object { $_.status -ne 'PASS' } | ForEach-Object { $_.command })
  $finalBlockers.Add([ordered]@{ code = 'REAL_INSTALL_SMOKE_FAILED'; detail = 'one or more real install/SQL steps did not pass'; failed_steps = $failedStepNames })
}
$finalStatus = if ($runStatus -eq 'PASS') { 'PASS' } else { 'FAILED' }
$failureCode = if ($finalStatus -eq 'PASS') { $null } else { 'REAL_INSTALL_SMOKE_FAILED' }
$resultPath = Write-Result $finalStatus $runExitCode $finalBlockers $preflight $runRecord $failureCode
$summary = 'INSTALL_SMOKE status={0} release_eligible=false result={1} evidence={2}' -f $finalStatus, $resultPath, $EvidencePath
if ($finalStatus -eq 'PASS') {
  Write-Output $summary
  exit 0
}
[Console]::Error.WriteLine($summary)
exit 1
