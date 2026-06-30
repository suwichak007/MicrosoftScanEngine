param(
  [switch]$BackendOnly,
  [switch]$FrontendOnly,
  [switch]$NoCache,
  [int]$MinFreeGB = 6,
  [switch]$SkipDockerPrune
)

# =========================
# Deploy Script (Docker)
# =========================

$ErrorActionPreference = "Stop"

Write-Host "===== START DEPLOY ====="

if ($BackendOnly -and $FrontendOnly) {
  throw "Use only one of -BackendOnly or -FrontendOnly."
}

function Remove-TargetContainers {
  Write-Host "===== PREPARE TARGET CONTAINERS ====="
  if (-not $FrontendOnly) {
    $existingBackend = docker ps -aq --filter "name=^scanner-backend$"
    if ($existingBackend) {
      Write-Host "Removing scanner-backend before disk preflight so old backend image can be pruned..."
      docker rm -f scanner-backend
    }
  }
  if (-not $BackendOnly) {
    $existingFrontend = docker ps -aq --filter "name=^scanner-frontend$"
    if ($existingFrontend) {
      Write-Host "Removing scanner-frontend before disk preflight so old frontend image can be pruned..."
      docker rm -f scanner-frontend
    }
  }
}

function Get-FreeGB {
  param([string]$DriveName)
  $drive = Get-PSDrive -Name $DriveName
  return [math]::Round($drive.Free / 1GB, 2)
}

function Invoke-SafeDockerCleanup {
  if ($SkipDockerPrune) {
    Write-Host "Skip Docker prune requested."
    return
  }

  Write-Host "===== DOCKER SAFE CLEANUP ====="
  try { docker container prune -f | Out-Host } catch { Write-Host "container prune skipped: $($_.Exception.Message)" }
  try { docker image prune -a -f | Out-Host } catch { Write-Host "image prune skipped: $($_.Exception.Message)" }
  try { docker builder prune -f | Out-Host } catch { Write-Host "builder prune skipped: $($_.Exception.Message)" }
  try { docker system df | Out-Host } catch { Write-Host "docker system df skipped: $($_.Exception.Message)" }
}

$driveName = (Split-Path -Qualifier $PSScriptRoot).TrimEnd(":")
Remove-TargetContainers
Invoke-SafeDockerCleanup

$freeGB = Get-FreeGB -DriveName $driveName
if ($freeGB -lt $MinFreeGB) {
  Write-Host "===== DISK PREFLIGHT FAILED ====="
  Write-Host "Free disk on $driveName`: ${freeGB}GB"
  Write-Host "Required minimum: ${MinFreeGB}GB"
  try { docker system df | Out-Host } catch {}
  throw "Not enough free disk space on $driveName`: ${freeGB}GB available, ${MinFreeGB}GB required. Free disk space before Docker build."
}

$DockerBuildCacheArgs = @()
if ($NoCache) {
  $DockerBuildCacheArgs += "--no-cache"
}

# =========================
# 0. Show current commit
# =========================
Write-Host "Current Commit:"
git rev-parse HEAD
git log -1 --oneline

# Load root .env
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvPath = Join-Path $RootDir ".env"
$DockerEnvArgs = @()
$EnvMap = @{}
if (Test-Path $EnvPath) {
  $DockerEnvArgs = @("--env-file", $EnvPath)
  Get-Content $EnvPath | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
      $name, $value = $line.Split("=", 2)
      $envName = $name.Trim()
      $envValue = $value.Trim()
      [System.Environment]::SetEnvironmentVariable($envName, $envValue, "Process")
      if ($envValue -ne "") {
        $EnvMap[$envName] = $envValue
      }
    }
  }
}

$RuntimeDir = Join-Path $RootDir "runtime"
$RuntimeDb = Join-Path $RuntimeDir "sql_app.db"
$LegacyBackendDb = Join-Path $RootDir "backend\sql_app.db"
$SqliteFallbackDatabaseUrl = "sqlite:///C:/MicrosoftScanEngine/runtime/sql_app.db"
$EffectiveDatabaseUrl = $null
if ($EnvMap.ContainsKey("DATABASE_URL")) {
  $EffectiveDatabaseUrl = $EnvMap["DATABASE_URL"]
} else {
  $processDatabaseUrl = [System.Environment]::GetEnvironmentVariable("DATABASE_URL", "Process")
  if ($null -ne $processDatabaseUrl -and $processDatabaseUrl.Trim() -ne "") {
    $EffectiveDatabaseUrl = $processDatabaseUrl.Trim()
  }
}

$UsingSqliteFallback = [string]::IsNullOrWhiteSpace($EffectiveDatabaseUrl)
if ($UsingSqliteFallback) {
  $EffectiveDatabaseUrl = $SqliteFallbackDatabaseUrl
  $EnvMap["DATABASE_URL"] = $EffectiveDatabaseUrl
}

$DatabaseMode = if ($EffectiveDatabaseUrl.StartsWith("postgresql") -or $EffectiveDatabaseUrl.StartsWith("postgres")) { "postgresql" } elseif ($EffectiveDatabaseUrl.StartsWith("sqlite")) { "sqlite" } else { "custom" }
Write-Host "Database mode: $DatabaseMode"
Write-Host "Database URL source: $(if ($UsingSqliteFallback) { 'SQLite fallback' } else { 'DATABASE_URL environment' })"

if (-not (Test-Path $RuntimeDir)) {
  New-Item -ItemType Directory -Path $RuntimeDir | Out-Null
}

if ($UsingSqliteFallback -and -not (Test-Path $RuntimeDb) -and (Test-Path $LegacyBackendDb)) {
  Write-Host "Initialize runtime DB from backend/sql_app.db"
  Copy-Item -Path $LegacyBackendDb -Destination $RuntimeDb
}

# =========================
# 1. Baselines
# =========================
Write-Host "===== BASELINES ====="
Write-Host "Baselines จะ generate ระหว่าง Docker build (multi-stage)"

# =========================
# 2. Backend
# =========================
Write-Host "===== BACKEND ====="

if (-not $FrontendOnly) {
  $existingBackend = docker ps -aq --filter "name=^scanner-backend$"
  if ($existingBackend) {
    docker rm -f scanner-backend
  }

  docker build @DockerBuildCacheArgs -f backend/dockerfile -t scan-api .

  $backendRunArgs = @(
  "run", "-d",
  "--name", "scanner-backend",
  "-p", "8000:8000"
  )
  $backendRunArgs += $DockerEnvArgs
  foreach ($envName in @(
  "AGENT_INSTALL_TOKEN",
  "SECRET_KEY",
  "AUTH_PROVIDER",
  "LDAP_SERVER_URI",
  "LDAP_DOMAIN",
  "LDAP_BIND_DN",
  "LDAP_BIND_PASSWORD",
  "LDAP_USER_BASE_DN",
  "LDAP_USER_FILTER",
  "LDAP_DEFAULT_ROLE",
  "LDAP_ADMIN_GROUP_DN",
  "LDAP_MOCK_ENABLED",
  "LDAP_MOCK_USERS",
  "ACCESS_TOKEN_EXPIRE_MINUTES",
  "BASELINES_DIR",
  "DATABASE_URL",
  "WINRM_USER",
  "WINRM_PASS",
  "GROQ_API_KEY",
  "GROQ_MODEL"
  )) {
    if ($EnvMap.ContainsKey($envName)) {
      $backendRunArgs += @("-e", "$envName=$($EnvMap[$envName])")
    } else {
      $envValue = [System.Environment]::GetEnvironmentVariable($envName, "Process")
      if ($null -ne $envValue -and $envValue -ne "") {
        $backendRunArgs += @("-e", "$envName=$envValue")
      }
    }
  }
  $backendRunArgs += @(
  "-e", "BASELINES_DIR=C:\MicrosoftScanEngine\baselines\generated",
  "-v", "C:\MicrosoftScanEngine\baselines:C:\MicrosoftScanEngine\baselines",
  "-v", "C:\MicrosoftScanEngine\tools:C:\MicrosoftScanEngine\backend\tools"
  )
  if ($UsingSqliteFallback) {
    $backendRunArgs += @("-v", "C:\MicrosoftScanEngine\runtime:C:\MicrosoftScanEngine\runtime")
  }
  $backendRunArgs += @(
  "--restart", "always",
  "scan-api"
  )

  docker @backendRunArgs

  Write-Host "Backend container:"
  docker ps | Select-String "scanner-backend"
}

# =========================
# 3. Frontend
# =========================
Write-Host "===== FRONTEND ====="
if (-not $BackendOnly) {
  cd frontend

  $existingFrontend = docker ps -aq --filter "name=^scanner-frontend$"
  if ($existingFrontend) {
    docker rm -f scanner-frontend
  }

  docker build @DockerBuildCacheArgs -t scan-web .

  docker run -d `
  --name scanner-frontend `
  -p 5173:5173 `
  --restart always `
  scan-web

  Write-Host "Frontend container:"
  docker ps | Select-String "scanner-frontend"
  cd $RootDir
}

# =========================
# 4. Image Info
# =========================
Write-Host "===== IMAGE INFO ====="
docker images scan-api
docker images scan-web

# =========================
# 5. Logs
# =========================
Write-Host "===== BACKEND LOG (last 20) ====="
if (-not $FrontendOnly) { docker logs scanner-backend --tail 20 }

Write-Host "===== FRONTEND LOG (last 20) ====="
if (-not $BackendOnly) { docker logs scanner-frontend --tail 20 }

# =========================
# 6. Cleanup
# =========================
Write-Host "===== CLEANUP ====="
docker image prune -f

Write-Host "===== DEPLOY COMPLETE ====="
cd $RootDir
