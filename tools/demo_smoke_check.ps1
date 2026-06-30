param(
  [string]$BackendUrl = "http://127.0.0.1:8000",
  [string]$FrontendUrl = "http://127.0.0.1:5173",
  [string]$AgentExe = "C:\MicrosoftScanEngine\MicrosoftScanAgent.exe",
  [string]$AdminToken = $env:SMOKE_ADMIN_TOKEN,
  [string]$ViewerToken = $env:SMOKE_VIEWER_TOKEN,
  [int]$ScanId = $(if ($env:SMOKE_SCAN_ID) { [int]$env:SMOKE_SCAN_ID } else { 0 })
)

$ErrorActionPreference = "Stop"

function Test-HttpEndpoint {
  param(
    [string]$Name,
    [string]$Url,
    [int[]]$AcceptedStatus = @(200)
  )

  try {
    $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 8 -ErrorAction Stop
    $status = [int]$response.StatusCode
  } catch {
    if ($_.Exception.Response) {
      $status = [int]$_.Exception.Response.StatusCode
    } else {
      Write-Host "[FAIL] $Name - $($_.Exception.Message)" -ForegroundColor Red
      return $false
    }
  }

  if ($AcceptedStatus -contains $status) {
    Write-Host "[OK]   $Name ($status)" -ForegroundColor Green
    return $true
  }

  Write-Host "[FAIL] $Name returned $status" -ForegroundColor Red
  return $false
}

function Test-AuthEndpoint {
  param(
    [string]$Name,
    [string]$Url,
    [string]$Token,
    [int[]]$AcceptedStatus = @(200)
  )

  if (-not $Token) {
    Write-Host "[SKIP] $Name - token not provided" -ForegroundColor Yellow
    return $true
  }

  try {
    $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 8 -Headers @{ Authorization = "Bearer $Token" } -ErrorAction Stop
    $status = [int]$response.StatusCode
  } catch {
    if ($_.Exception.Response) {
      $status = [int]$_.Exception.Response.StatusCode
    } else {
      Write-Host "[FAIL] $Name - $($_.Exception.Message)" -ForegroundColor Red
      return $false
    }
  }

  if ($AcceptedStatus -contains $status) {
    Write-Host "[OK]   $Name ($status)" -ForegroundColor Green
    return $true
  }

  Write-Host "[FAIL] $Name returned $status" -ForegroundColor Red
  return $false
}

function Test-DockerContainer {
  param([string]$Name)
  try {
    $line = docker ps --filter "name=^$Name$" --format "{{.Names}} {{.Status}}" 2>$null
    if ($line) {
      Write-Host "[OK]   Container $line" -ForegroundColor Green
      return $true
    }
    Write-Host "[WARN] Container $Name is not running" -ForegroundColor Yellow
    return $false
  } catch {
    Write-Host "[WARN] Docker check skipped: $($_.Exception.Message)" -ForegroundColor Yellow
    return $false
  }
}

Write-Host "===== MicrosoftScanEngine Demo Smoke Check ====="
Write-Host "Backend:  $BackendUrl"
Write-Host "Frontend: $FrontendUrl"
Write-Host ""

$checks = @()
$checks += Test-HttpEndpoint -Name "Frontend login page" -Url "$FrontendUrl/login" -AcceptedStatus @(200)
$checks += Test-HttpEndpoint -Name "Frontend home route" -Url "$FrontendUrl/home" -AcceptedStatus @(200)
$checks += Test-HttpEndpoint -Name "Backend auth guard" -Url "$BackendUrl/api/agents" -AcceptedStatus @(401, 403)
$checks += Test-DockerContainer -Name "scanner-backend"
$checks += Test-DockerContainer -Name "scanner-frontend"

$checks += Test-AuthEndpoint -Name "Admin token /api/me" -Url "$BackendUrl/api/me" -Token $AdminToken -AcceptedStatus @(200)
$checks += Test-AuthEndpoint -Name "Admin baselines" -Url "$BackendUrl/api/admin/baselines" -Token $AdminToken -AcceptedStatus @(200)
$checks += Test-AuthEndpoint -Name "Admin schedules" -Url "$BackendUrl/api/admin/schedules" -Token $AdminToken -AcceptedStatus @(200)
$checks += Test-AuthEndpoint -Name "Admin activity log" -Url "$BackendUrl/api/admin/activity?limit=5" -Token $AdminToken -AcceptedStatus @(200)
$checks += Test-AuthEndpoint -Name "Viewer blocked from baselines" -Url "$BackendUrl/api/admin/baselines" -Token $ViewerToken -AcceptedStatus @(403)
$checks += Test-AuthEndpoint -Name "Viewer blocked from schedules" -Url "$BackendUrl/api/admin/schedules" -Token $ViewerToken -AcceptedStatus @(403)
if ($ScanId -gt 0) {
  $checks += Test-AuthEndpoint -Name "Viewer blocked from autofix history" -Url "$BackendUrl/api/scan/history/$ScanId/autofix-jobs" -Token $ViewerToken -AcceptedStatus @(403)
}

if (Test-Path -LiteralPath $AgentExe) {
  $agent = Get-Item -LiteralPath $AgentExe
  Write-Host "[OK]   Installed agent exe: $($agent.FullName) ($([math]::Round($agent.Length / 1MB, 2)) MB, modified $($agent.LastWriteTime))" -ForegroundColor Green
  $checks += $true
} else {
  Write-Host "[WARN] Installed agent exe not found at $AgentExe" -ForegroundColor Yellow
  $checks += $false
}

$envPath = Join-Path (Resolve-Path ".") ".env"
if (Test-Path -LiteralPath $envPath) {
  $databaseLine = Get-Content -LiteralPath $envPath | Where-Object { $_ -match "^\s*DATABASE_URL\s*=" } | Select-Object -First 1
  if ($databaseLine -and $databaseLine -notmatch "^\s*DATABASE_URL\s*=\s*$") {
    Write-Host "[OK]   DATABASE_URL is configured in .env" -ForegroundColor Green
  } else {
    Write-Host "[WARN] DATABASE_URL is empty; backend will use SQLite fallback" -ForegroundColor Yellow
  }
} else {
  Write-Host "[WARN] .env not found; deploy will use environment variables or SQLite fallback" -ForegroundColor Yellow
}

$passed = ($checks | Where-Object { $_ }).Count
$total = $checks.Count
Write-Host ""
Write-Host "Smoke check: $passed/$total checks passed"
Write-Host "Set SMOKE_ADMIN_TOKEN, SMOKE_VIEWER_TOKEN, and SMOKE_SCAN_ID for authenticated validation."
Write-Host "Use docs/DEMO_READY_CHECKLIST.md for full manual flow validation."

if ($passed -lt 3) {
  exit 1
}
