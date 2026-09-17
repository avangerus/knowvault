# KnowVault R3a-1 Outcome 3 external-agent MCP client probe.
#
# This script is an external Model Context Protocol agent. It talks to the
# existing streamable-HTTP endpoint (POST /api/v1/mcp, JSON-RPC 2.0) with the
# deployment's own OIDC/Keycloak session token and agent access-code token; it
# adds no runtime, no dependency, no route and no migration. It never embeds a
# secret: every input comes from an environment variable.
#
# Required environment variables:
#   KNOWVAULT_MCP_ENDPOINT           full URL of the MCP endpoint, e.g.
#                                    https://knowvault.example/api/v1/mcp
#   KNOWVAULT_MCP_MEMBER_TOKEN       a human member's bearer session token
#   KNOWVAULT_MCP_SERVICE_TOKEN      a V1-C agent access-code (kva_) token
#   KNOWVAULT_MCP_WORKSPACE_ID       a workspace the tokens are members of
#   KNOWVAULT_MCP_FOREIGN_WORKSPACE_ID  a workspace they are NOT members of
#
# Optional environment variables:
#   KNOWVAULT_MCP_EXPIRED_TOKEN      an expired or foreign token; when unset the
#                                    probe uses a fixed non-member token so the
#                                    unauthorized path is still exercised
#   KNOWVAULT_MCP_QUERY              lexical query that matches at least one
#                                    document of the member workspace (default
#                                    "KnowVault")
#   KNOWVAULT_MCP_PAGE_LIMIT         search/read page size the probe drives (default
#                                    16, so a document longer than one page is
#                                    reassembled through the stable cursor)
#
# The probe prints one `ok:` line per checked outcome and exits non-zero on the
# first failed assertion. See docs/MCP-TOOLS.md ("External-agent MCP probe") for
# the run command and the expected outcome of each step.

[CmdletBinding()]
param(
  [switch] $AllowInsecureTls,
  [ValidateRange(1, 600)] [int] $TimeoutSeconds = 60,
  [ValidateRange(1, 65536)] [int] $PageLimit = 16
)

$ErrorActionPreference = 'Stop'

function Fail([string] $Message) {
  Write-Host ('[mcp-external-client] FAIL: ' + $Message) -ForegroundColor Red
  exit 1
}

function Note([string] $Message) {
  Write-Host ('[mcp-external-client] ' + $Message)
}

function Ok([string] $Message) {
  Write-Host ('[mcp-external-client] ok: ' + $Message) -ForegroundColor Green
}

function Assert-True([bool] $Condition, [string] $Message) {
  if (-not $Condition) { Fail $Message }
}

function Get-EnvOrEmpty([string] $Name) {
  $value = [Environment]::GetEnvironmentVariable($Name)
  if ($null -eq $value) { return '' }
  return $value.Trim()
}

function Get-Sha256Prefixed([byte[]] $Bytes) {
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $digest = $sha.ComputeHash($Bytes) } finally { $sha.Dispose() }
  return 'sha256:' + (($digest | ForEach-Object { $_.ToString('x2') }) -join '')
}

function Test-Property($Object, [string] $Name) {
  if ($null -eq $Object) { return $false }
  return ($Object.PSObject.Properties.Name -contains $Name)
}

function Get-HttpFailure($ErrorRecord) {
  $status = 0
  $body = ''
  $response = $ErrorRecord.Exception.Response
  if ($null -ne $response) {
    $status = [int] $response.StatusCode
    try {
      if ($response -is [System.Net.Http.HttpResponseMessage]) {
        $body = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
      } else {
        $stream = $response.GetResponseStream()
        if ($null -ne $stream) {
          $reader = New-Object System.IO.StreamReader($stream)
          try { $body = $reader.ReadToEnd() } finally { $reader.Dispose() }
        }
      }
    } catch {
      $body = ''
    }
  }
  if ([string]::IsNullOrEmpty($body) -and $null -ne $ErrorRecord.ErrorDetails) {
    $body = [string] $ErrorRecord.ErrorDetails.Message
  }
  return [pscustomobject]@{ Status = $status; Body = $body }
}

function Invoke-McpHttp([string] $Token, [string] $Body) {
  $headers = @{ 'Accept' = 'application/json'; 'Content-Type' = 'application/json' }
  if (-not [string]::IsNullOrEmpty($Token)) {
    $headers['Authorization'] = 'Bearer ' + $Token
  }
  $requestArguments = @{
    Method          = 'Post'
    Uri             = $McpEndpoint
    Headers         = $headers
    Body            = $Body
    TimeoutSec      = $TimeoutSeconds
    UseBasicParsing = $true
  }
  if ($AllowInsecureTls) {
    if ($PSVersionTable.PSVersion.Major -ge 6) {
      $requestArguments['SkipCertificateCheck'] = $true
    } else {
      [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
  }
  try {
    $response = Invoke-WebRequest @requestArguments
    return [pscustomobject]@{ Status = [int] $response.StatusCode; Body = [string] $response.Content }
  } catch {
    $failure = Get-HttpFailure $_
    if ($failure.Status -eq 0) { throw }
    return $failure
  }
}

function Invoke-McpRpc([string] $Token, [string] $Method, $Params, [string] $Id) {
  $envelope = [ordered]@{ jsonrpc = '2.0'; id = $Id; method = $Method }
  if ($null -ne $Params) { $envelope['params'] = $Params }
  $body = $envelope | ConvertTo-Json -Depth 20 -Compress
  $http = Invoke-McpHttp -Token $Token -Body $body
  $parsed = $null
  if (-not [string]::IsNullOrWhiteSpace($http.Body)) {
    try { $parsed = $http.Body | ConvertFrom-Json } catch { $parsed = $null }
  }
  return [pscustomobject]@{ Status = $http.Status; Body = $http.Body; Json = $parsed }
}

function Assert-McpSuccess($Rpc, [string] $Label) {
  if ($Rpc.Status -ne 200) { Fail ($Label + ': HTTP ' + $Rpc.Status + ' body=' + $Rpc.Body) }
  if ($null -eq $Rpc.Json) { Fail ($Label + ': response is not JSON: ' + $Rpc.Body) }
  if ($null -ne $Rpc.Json.error) {
    Fail ($Label + ': JSON-RPC error ' + [string] $Rpc.Json.error.code + ' ' + [string] $Rpc.Json.error.message)
  }
  if ($null -eq $Rpc.Json.result) { Fail ($Label + ': response has no result: ' + $Rpc.Body) }
}

function Get-ToolNames($ListJson) {
  $names = @()
  if ($null -ne $ListJson.result.tools) {
    foreach ($tool in $ListJson.result.tools) { $names += [string] $tool.name }
  }
  return $names
}

function Assert-KnowVaultToolNames([string[]] $Names, [string] $Label) {
  Assert-True ($Names.Count -gt 0) ($Label + ': tools/list advertised no tool')
  foreach ($name in $Names) {
    Assert-True ($name.StartsWith('knowvault_')) ($Label + ': tools/list advertised a non-KnowVault name: ' + $name)
  }
}

# --- Inputs -----------------------------------------------------------------

$McpEndpoint = Get-EnvOrEmpty 'KNOWVAULT_MCP_ENDPOINT'
$MemberToken = Get-EnvOrEmpty 'KNOWVAULT_MCP_MEMBER_TOKEN'
$ServiceToken = Get-EnvOrEmpty 'KNOWVAULT_MCP_SERVICE_TOKEN'
$WorkspaceId = Get-EnvOrEmpty 'KNOWVAULT_MCP_WORKSPACE_ID'
$ForeignWorkspaceId = Get-EnvOrEmpty 'KNOWVAULT_MCP_FOREIGN_WORKSPACE_ID'
$Query = Get-EnvOrEmpty 'KNOWVAULT_MCP_QUERY'
$ForeignToken = Get-EnvOrEmpty 'KNOWVAULT_MCP_EXPIRED_TOKEN'

if ([string]::IsNullOrEmpty($McpEndpoint)) { Fail 'KNOWVAULT_MCP_ENDPOINT is not set' }
if ([string]::IsNullOrEmpty($MemberToken)) { Fail 'KNOWVAULT_MCP_MEMBER_TOKEN is not set' }
if ([string]::IsNullOrEmpty($ServiceToken)) { Fail 'KNOWVAULT_MCP_SERVICE_TOKEN is not set' }
if ([string]::IsNullOrEmpty($WorkspaceId)) { Fail 'KNOWVAULT_MCP_WORKSPACE_ID is not set' }
if ([string]::IsNullOrEmpty($ForeignWorkspaceId)) { Fail 'KNOWVAULT_MCP_FOREIGN_WORKSPACE_ID is not set' }
if ([string]::IsNullOrEmpty($Query)) { $Query = 'KnowVault' }

$envPageLimit = Get-EnvOrEmpty 'KNOWVAULT_MCP_PAGE_LIMIT'
if (-not [string]::IsNullOrEmpty($envPageLimit)) {
  $parsedPageLimit = 0
  if (-not [int]::TryParse($envPageLimit, [ref] $parsedPageLimit) -or $parsedPageLimit -lt 1) {
    Fail 'KNOWVAULT_MCP_PAGE_LIMIT is not a positive integer'
  }
  $PageLimit = $parsedPageLimit
}

if ([string]::IsNullOrEmpty($ForeignToken)) {
  $ForeignToken = 'kv-probe-foreign-token-not-a-member'
  Note 'KNOWVAULT_MCP_EXPIRED_TOKEN is unset; using a fixed non-member token for the unauthorized-token control'
}

$CanonicalKnowledgeTools = @(
  'knowvault_search', 'knowvault_read', 'knowvault_list_objects', 'knowvault_related',
  'knowvault_grep', 'knowvault_sources', 'knowvault_refresh'
)
$WikiRagToolNames = @(
  'wiki_search', 'wiki_get_page', 'wiki_list_pages', 'wiki_find_related', 'code_search', 'code_get_file'
)
$AdministrativeTools = @(
  'knowvault_conversation_archive', 'knowvault_source_enable', 'knowvault_source_sync',
  'knowvault_metric_definitions_list', 'knowvault_governed_query_ask'
)

Note ('endpoint=' + $McpEndpoint + ' workspace=' + $WorkspaceId + ' foreign=' + $ForeignWorkspaceId)

# --- 1. Member session: initialize + tools/list -----------------------------

$init = Invoke-McpRpc -Token $MemberToken -Method 'initialize' -Id 'probe-init' -Params ([ordered]@{
    protocolVersion = '2025-06-18'
    capabilities    = @{}
    clientInfo      = @{ name = 'knowvault-mcp-external-client'; version = '1' }
  })
Assert-McpSuccess $init 'initialize'
Assert-True ([string] $init.Json.result.serverInfo.name -eq 'knowvault') ('initialize: unexpected serverInfo ' + $init.Body)
Ok 'member initialize returned the KnowVault MCP server info'

$memberList = Invoke-McpRpc -Token $MemberToken -Method 'tools/list' -Id 'probe-tools' -Params ([ordered]@{})
Assert-McpSuccess $memberList 'tools/list'
$memberNames = @(Get-ToolNames $memberList.Json)
Assert-KnowVaultToolNames $memberNames 'member tools/list'
foreach ($canonical in $CanonicalKnowledgeTools) {
  Assert-True ($memberNames -contains $canonical) ('member tools/list omitted the canonical tool ' + $canonical)
}
foreach ($wiki in $WikiRagToolNames) {
  Assert-True (-not ($memberNames -contains $wiki)) ('member tools/list advertised the wiki-rag name ' + $wiki)
}
Ok ('member tools/list advertised ' + $memberNames.Count + ' knowvault_* tools and no wiki-rag name')

# A wiki-rag name is not dispatched either: the call is refused with -32602 and
# no result content.
$wikiCall = Invoke-McpRpc -Token $MemberToken -Method 'tools/call' -Id 'probe-wiki' -Params ([ordered]@{
    name      = 'wiki_search'
    arguments = [ordered]@{ workspace_id = $WorkspaceId; query = $Query }
  })
Assert-True ($null -ne $wikiCall.Json.error -and [int] $wikiCall.Json.error.code -eq -32602) ('wiki_search was not refused -32602: ' + $wikiCall.Body)
Assert-True ($null -eq $wikiCall.Json.result) ('wiki_search returned a result: ' + $wikiCall.Body)
Ok 'a tools/call naming wiki_search was refused -32602 with no result content'

# --- 2. Search, address, fragment window, whole-object paging ----------------

$search = Invoke-McpRpc -Token $MemberToken -Method 'tools/call' -Id 'probe-search' -Params ([ordered]@{
    name      = 'knowvault_search'
    arguments = [ordered]@{ workspace_id = $WorkspaceId; query = $Query; limit = $PageLimit }
  })
Assert-McpSuccess $search 'knowvault_search'
$searchContent = $search.Json.result.structuredContent
Assert-True (Test-Property $searchContent 'has_more') ('knowvault_search omitted has_more: ' + $search.Body)
Assert-True (Test-Property $searchContent 'next_offset') ('knowvault_search omitted next_offset: ' + $search.Body)
$results = @($searchContent.results)
Assert-True ($results.Count -ge 1) (
  'knowvault_search returned no hit for query "' + $Query + '"; set KNOWVAULT_MCP_QUERY to a term present in the workspace')
$hit = $results[0]
$fragmentId = [string] $hit.fragment_id
$addressHash = [string] $hit.address.span.text_hash
Assert-True (-not [string]::IsNullOrEmpty($fragmentId)) ('search hit has no fragment_id: ' + $search.Body)
Assert-True (-not [string]::IsNullOrEmpty($addressHash)) ('search hit address has no span text_hash: ' + $search.Body)
Assert-True (-not [string]::IsNullOrEmpty([string] $hit.address.source.source_object_id)) 'search hit address has no source object id'
Assert-True (-not [string]::IsNullOrEmpty([string] $hit.address.version.source_version_id)) 'search hit address has no source version id'
Ok ('search returned an addressed hit ' + $fragmentId)

# Follow the hit's address (its fragment id plus the address span hash) into
# knowvault_read, one explicit byte window, no silent truncation.
$fragmentRead = Invoke-McpRpc -Token $MemberToken -Method 'tools/call' -Id 'probe-read-window' -Params ([ordered]@{
    name      = 'knowvault_read'
    arguments = [ordered]@{
      workspace_id       = $WorkspaceId
      fragment_id        = $fragmentId
      expected_span_hash = $addressHash
      limit              = $PageLimit
    }
  })
Assert-McpSuccess $fragmentRead 'knowvault_read window'
$window = $fragmentRead.Json.result.structuredContent
foreach ($field in @('offset', 'length', 'limit', 'has_more', 'next_offset', 'total_length', 'text_hash')) {
  Assert-True (Test-Property $window $field) ('knowvault_read window omitted ' + $field + ': ' + $fragmentRead.Body)
}
Assert-True ([string] $window.text_hash -eq $addressHash) 'knowvault_read window does not carry the addressed span hash'
if ([bool] $window.has_more) {
  Assert-True ($null -ne $window.next_offset) 'knowvault_read window reports has_more with a null next_offset'
  Assert-True ([int64] $window.next_offset -gt [int64] $window.offset) 'knowvault_read window next_offset does not advance'
}
Ok 'the addressed window read is explicit (offset/length/limit/has_more/next_offset) and hash-matched'

# Page the whole object through the stable cursor and prove the reassembled
# bytes hash to the whole-object hash the read reports.
$cursor = ''
$pageNumber = 0
$wholeHash = $null
$wholeTotalBytes = $null
$wholeOffset = [int64] 0
$buffer = New-Object System.Collections.Generic.List[byte]
while ($true) {
  $arguments = [ordered]@{ workspace_id = $WorkspaceId; fragment_id = $fragmentId; cursor = $cursor; limit = $PageLimit; include_text_base64 = $true }
  $pageRpc = Invoke-McpRpc -Token $MemberToken -Method 'tools/call' -Id ('probe-read-page-' + $pageNumber) -Params ([ordered]@{
      name = 'knowvault_read'; arguments = $arguments
    })
  Assert-McpSuccess $pageRpc 'knowvault_read cursor page'
  $page = $pageRpc.Json.result.structuredContent
  foreach ($field in @('offset', 'length', 'limit', 'has_more', 'complete', 'next_cursor', 'total_bytes', 'whole_hash', 'page_hash', 'text_base64')) {
    Assert-True (Test-Property $page $field) ('knowvault_read cursor page omitted ' + $field + ': ' + $pageRpc.Body)
  }
  Assert-True ([int64] $page.offset -eq $wholeOffset) ('cursor page starts at ' + $page.offset + ' but ' + $wholeOffset + ' bytes were reassembled')
  if ($pageNumber -eq 0) {
    $wholeHash = [string] $page.whole_hash
    $wholeTotalBytes = [int64] $page.total_bytes
  } else {
    Assert-True ([string] $page.whole_hash -eq $wholeHash) 'cursor pages disagree on the whole-object hash'
  }
  $pageBytes = [Convert]::FromBase64String([string] $page.text_base64)
  $buffer.AddRange([byte[]] $pageBytes)
  $wholeOffset += $pageBytes.Length
  $pageNumber++
  if (-not [bool] $page.has_more) {
    Assert-True ([bool] $page.complete) 'final cursor page is not marked complete'
    Assert-True ($null -eq $page.next_cursor) 'final cursor page still offers next_cursor'
    break
  }
  Assert-True (-not [string]::IsNullOrEmpty([string] $page.next_cursor)) 'a non-final cursor page offers no next_cursor'
  $cursor = [string] $page.next_cursor
  if ($pageNumber -ge 100000) { Fail 'cursor pagination did not terminate' }
}
Assert-True ($buffer.Count -eq $wholeTotalBytes) ('reassembled ' + $buffer.Count + ' bytes but the read reported ' + $wholeTotalBytes)
$reassembled = $buffer.ToArray()
$computedHash = Get-Sha256Prefixed $reassembled
Assert-True ($computedHash -eq $wholeHash) ('reassembled hash ' + $computedHash + ' != whole_hash ' + $wholeHash)
Ok ('reassembled ' + $pageNumber + ' page(s), ' + $buffer.Count + ' bytes, hash ' + $wholeHash)

# --- 3. Cross-workspace content-free denial ----------------------------------

function Test-CrossWorkspaceDenial([string] $ToolName, $Arguments, [string] $Label) {
  $rpc = Invoke-McpRpc -Token $MemberToken -Method 'tools/call' -Id ('probe-deny-' + $ToolName) -Params ([ordered]@{
      name = $ToolName; arguments = $Arguments
    })
  Assert-True ($rpc.Status -eq 200) ($Label + ': expected an HTTP 200 JSON-RPC denial, got ' + $rpc.Status + ' body=' + $rpc.Body)
  Assert-True ($null -ne $rpc.Json.error) ($Label + ': cross-workspace call was not denied: ' + $rpc.Body)
  Assert-True ([int] $rpc.Json.error.code -eq -32004) ($Label + ': denial code is not -32004: ' + $rpc.Body)
  Assert-True ($null -eq $rpc.Json.result) ($Label + ': denial carried a result: ' + $rpc.Body)
  if ($rpc.Body.IndexOf($ForeignWorkspaceId, [System.StringComparison]::Ordinal) -ge 0) {
    Fail ($Label + ': denial echoed the foreign workspace id: ' + $rpc.Body)
  }
  if ($rpc.Body.IndexOf('structuredContent', [System.StringComparison]::Ordinal) -ge 0) {
    Fail ($Label + ': denial carried structured content: ' + $rpc.Body)
  }
  Ok ($Label + ' denied -32004 with an empty, workspace-echo-free payload')
}

Test-CrossWorkspaceDenial 'knowvault_search' ([ordered]@{ workspace_id = $ForeignWorkspaceId; query = $Query }) 'knowvault_search'
Test-CrossWorkspaceDenial 'knowvault_read' ([ordered]@{ workspace_id = $ForeignWorkspaceId; fragment_id = $fragmentId }) 'knowvault_read'
Test-CrossWorkspaceDenial 'knowvault_list_objects' ([ordered]@{ workspace_id = $ForeignWorkspaceId }) 'knowvault_list_objects'
Test-CrossWorkspaceDenial 'knowvault_related' ([ordered]@{ workspace_id = $ForeignWorkspaceId; fragment_id = $fragmentId }) 'knowvault_related'
Test-CrossWorkspaceDenial 'knowvault_grep' ([ordered]@{ workspace_id = $ForeignWorkspaceId; pattern = $Query }) 'knowvault_grep'
Test-CrossWorkspaceDenial 'knowvault_sources' ([ordered]@{ workspace_id = $ForeignWorkspaceId }) 'knowvault_sources'
Test-CrossWorkspaceDenial 'knowvault_refresh' ([ordered]@{ workspace_id = $ForeignWorkspaceId }) 'knowvault_refresh'

# --- 4. Service-principal member session -------------------------------------

$serviceInit = Invoke-McpRpc -Token $ServiceToken -Method 'initialize' -Id 'probe-service-init' -Params ([ordered]@{})
Assert-McpSuccess $serviceInit 'service initialize'
$serviceList = Invoke-McpRpc -Token $ServiceToken -Method 'tools/list' -Id 'probe-service-tools' -Params ([ordered]@{})
Assert-McpSuccess $serviceList 'service tools/list'
$serviceNames = @(Get-ToolNames $serviceList.Json)
Assert-KnowVaultToolNames $serviceNames 'service tools/list'
foreach ($canonical in $CanonicalKnowledgeTools) {
  Assert-True ($serviceNames -contains $canonical) ('service tools/list omitted the knowledge tool ' + $canonical)
}
foreach ($administrative in $AdministrativeTools) {
  Assert-True (-not ($serviceNames -contains $administrative)) ('service tools/list advertised the administrative tool ' + $administrative)
}
Ok ('service-principal tools/list maps the token to workspace membership and shows only the ' + $serviceNames.Count + ' knowledge tools')

$serviceDenied = Invoke-McpRpc -Token $ServiceToken -Method 'tools/call' -Id 'probe-service-deny' -Params ([ordered]@{
    name      = 'knowvault_sources'
    arguments = [ordered]@{ workspace_id = $ForeignWorkspaceId }
  })
Assert-True ($null -ne $serviceDenied.Json.error -and [int] $serviceDenied.Json.error.code -eq -32004) (
  'service-principal cross-workspace sources call was not denied -32004: ' + $serviceDenied.Body)
Assert-True ($null -eq $serviceDenied.Json.result) ('service-principal denial carried a result: ' + $serviceDenied.Body)
Assert-True ($serviceDenied.Body.IndexOf($ForeignWorkspaceId, [System.StringComparison]::Ordinal) -lt 0) (
  'service-principal denial echoed the foreign workspace id: ' + $serviceDenied.Body)
Ok 'the service principal was denied the foreign workspace without content or workspace echo'

# --- 5. Expired / foreign token ----------------------------------------------

$rejected = Invoke-McpRpc -Token $ForeignToken -Method 'tools/list' -Id 'probe-expired' -Params ([ordered]@{})
Assert-True ($rejected.Status -eq 401) ('an expired/foreign token got HTTP ' + $rejected.Status + ' instead of 401: ' + $rejected.Body)
Assert-True ($rejected.Body.IndexOf('UNAUTHENTICATED', [System.StringComparison]::Ordinal) -ge 0) (
  'the 401 body does not carry the documented UNAUTHENTICATED error: ' + $rejected.Body)
foreach ($leaked in @('knowvault_', 'inputSchema', '"tools"', 'result')) {
  Assert-True ($rejected.Body.IndexOf($leaked, [System.StringComparison]::Ordinal) -lt 0) (
    'the rejected token response disclosed ' + $leaked + ': ' + $rejected.Body)
}
Ok 'an expired/foreign token got 401 UNAUTHENTICATED with no tool-list content beyond names'

Write-Host '[mcp-external-client] PASS: external-agent MCP probe satisfied every R3a-1 Outcome 3 control' -ForegroundColor Green
exit 0
