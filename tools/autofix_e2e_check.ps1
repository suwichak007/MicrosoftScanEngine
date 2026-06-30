param(
  [string]$BackendUrl = "http://127.0.0.1:8000",
  [string]$AdminToken = $env:SMOKE_ADMIN_TOKEN,
  [string]$ViewerToken = $env:SMOKE_VIEWER_TOKEN,
  [int]$ScanId = $(if ($env:SMOKE_SCAN_ID) { [int]$env:SMOKE_SCAN_ID } else { 0 }),
  [string[]]$CheckIds = @(),
  [string]$AutofixValuesJson = "{}",
  [string]$AgentId = "agent-WIN-50F5TDGIP70",
  [string]$Version = "auto",
  [string]$Role = "Member Server",
  [int]$TimeoutSeconds = 300,
  [int]$PollSeconds = 2,
  [switch]$Execute,
  [switch]$Rescan,
  [switch]$Rollback
)

$ErrorActionPreference = "Stop"

function Get-AuthHeaders {
  param([string]$Token)
  if (-not $Token) { throw "SMOKE_ADMIN_TOKEN is required" }
  return @{ Authorization = "Bearer $Token" }
}

function Invoke-JsonApi {
  param(
    [string]$Method,
    [string]$Url,
    [string]$Token,
    [object]$Body = $null
  )
  $params = @{
    Method = $Method
    Uri = $Url
    Headers = Get-AuthHeaders $Token
    TimeoutSec = 30
  }
  if ($null -ne $Body) {
    $params.ContentType = "application/json"
    $params.Body = $Body | ConvertTo-Json -Depth 12 -Compress
  }
  return Invoke-RestMethod @params
}

function ConvertTo-Hashtable {
  param([object]$Value)
  $result = @{}
  if ($null -eq $Value) { return $result }
  foreach ($property in $Value.PSObject.Properties) {
    $result[$property.Name] = $property.Value
  }
  return $result
}

function Wait-AgentJob {
  param([string]$JobId)
  $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
  do {
    $status = Invoke-JsonApi -Method Get -Url "$BackendUrl/api/scan/status/$JobId" -Token $AdminToken
    Write-Host ("[{0}] {1} - {2}" -f $status.status, $JobId, $status.message)
    if ($status.status -in @("done", "error")) { return $status }
    Start-Sleep -Seconds $PollSeconds
  } while ((Get-Date) -lt $deadline)
  throw "Timed out waiting for job $JobId"
}

if ($ScanId -le 0) { throw "Provide -ScanId or set SMOKE_SCAN_ID" }
if (-not $AdminToken) { throw "Set SMOKE_ADMIN_TOKEN before running this script" }

$me = Invoke-JsonApi -Method Get -Url "$BackendUrl/api/me" -Token $AdminToken
if ($me.role -notin @("admin", "owner")) {
  throw "SMOKE_ADMIN_TOKEN must belong to an admin or owner"
}
Write-Host "Authenticated as $($me.username) ($($me.role))"

$scan = Invoke-JsonApi -Method Get -Url "$BackendUrl/api/scan/history/$ScanId" -Token $AdminToken
$findings = @($scan.findings)
$selected = @($findings | Where-Object { $CheckIds -contains $_.check_id })
if ($CheckIds.Count -eq 0) {
  $coverage = $findings |
    Where-Object { $_.status -match "^Fail" } |
    Group-Object { if ($_.autofix_supported) { $_.autofix_action } else { "manual" } } |
    Sort-Object Name
  Write-Host "Autofix coverage for scan $ScanId"
  $coverage | Select-Object Name, Count | Format-Table -AutoSize
  exit 0
}

$missing = @($CheckIds | Where-Object { $_ -notin @($selected.check_id) })
if ($missing.Count) { throw "Checks not found in scan: $($missing -join ', ')" }
foreach ($row in $selected) {
  Write-Host ("{0} | {1} | supported={2} | action={3} | current={4} | target={5}" -f `
    $row.check_id, $row.check_name, $row.autofix_supported, $row.autofix_action, $row.current_value, $row.expected_value)
  if (-not $row.autofix_supported) { throw "Unsupported Autofix check: $($row.check_id) - $($row.autofix_reason)" }
}

if (-not $Execute) {
  Write-Host "Preview only. Add -Execute to change target settings." -ForegroundColor Yellow
  exit 0
}

$autofixValues = ConvertTo-Hashtable ($AutofixValuesJson | ConvertFrom-Json)
$queued = Invoke-JsonApi -Method Post -Url "$BackendUrl/api/scan/history/$ScanId/autofix" -Token $AdminToken -Body @{
  check_ids = $CheckIds
  autofix_values = $autofixValues
}
Write-Host "Queued Autofix job $($queued.job_id)"
$autofixStatus = Wait-AgentJob $queued.job_id
$autofixRows = @($autofixStatus.result.autofix_results)
$autofixRows | Select-Object check_id, check_name, fix_type, status, old_value, new_value, error | Format-Table -Wrap
if ($autofixStatus.status -ne "done" -or @($autofixRows | Where-Object status -ne "done").Count) {
  throw "Autofix job did not complete successfully"
}

if ($Rescan) {
  $scanJob = Invoke-JsonApi -Method Post -Url "$BackendUrl/api/scan/agent" -Token $AdminToken -Body @{
    agent_id = $AgentId
    version = $Version
    role = $Role
  }
  Write-Host "Queued verification scan $($scanJob.job_id)"
  $scanStatus = Wait-AgentJob $scanJob.job_id
  if ($scanStatus.status -ne "done") { throw "Verification scan failed" }
  Write-Host "Verification scan completed. scan_id=$($scanStatus.result.scan_id)"
}

if ($Rollback) {
  $rollbackJob = Invoke-JsonApi -Method Post -Url "$BackendUrl/api/scan/history/$ScanId/autofix/$($queued.job_id)/rollback" -Token $AdminToken
  Write-Host "Queued rollback job $($rollbackJob.job_id)"
  $rollbackStatus = Wait-AgentJob $rollbackJob.job_id
  $rollbackRows = @($rollbackStatus.result.autofix_results)
  $rollbackRows | Select-Object check_id, check_name, fix_type, status, old_value, new_value, error | Format-Table -Wrap
  if ($rollbackStatus.status -ne "done" -or @($rollbackRows | Where-Object status -ne "done").Count) {
    throw "Rollback job did not complete successfully"
  }
}

$history = Invoke-JsonApi -Method Get -Url "$BackendUrl/api/scan/history/$ScanId/autofix-jobs" -Token $AdminToken
Write-Host "Autofix history entries for scan ${ScanId}: $(@($history).Count)"

if ($ViewerToken) {
  try {
    Invoke-JsonApi -Method Get -Url "$BackendUrl/api/scan/history/$ScanId/autofix-jobs" -Token $ViewerToken | Out-Null
    throw "Viewer unexpectedly accessed Autofix history"
  } catch {
    if ($_.Exception.Response.StatusCode.value__ -ne 403) { throw }
    Write-Host "Viewer permission check: 403"
  }
}

Write-Host "Autofix E2E check completed"
