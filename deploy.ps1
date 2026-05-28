# =========================
# Deploy Script (Docker)
# =========================

$ErrorActionPreference = "Stop"

Write-Host "===== START DEPLOY ====="

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

# =========================
# 1. Baselines
# =========================
Write-Host "===== BASELINES ====="
Write-Host "Baselines จะ generate ระหว่าง Docker build (multi-stage)"

# =========================
# 2. Backend
# =========================
Write-Host "===== BACKEND ====="

$existingBackend = docker ps -aq --filter "name=^scanner-backend$"
if ($existingBackend) {
  docker rm -f scanner-backend
}

docker build --no-cache -f backend/dockerfile -t scan-api .

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
  "ACCESS_TOKEN_EXPIRE_MINUTES",
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
  "--restart", "always",
  "scan-api"
)

docker @backendRunArgs

Write-Host "Backend container:"
docker ps | Select-String "scanner-backend"

# =========================
# 3. Frontend
# =========================
Write-Host "===== FRONTEND ====="
cd frontend

$existingFrontend = docker ps -aq --filter "name=^scanner-frontend$"
if ($existingFrontend) {
  docker rm -f scanner-frontend
}

docker build --no-cache -t scan-web .

docker run -d `
  --name scanner-frontend `
  -p 5173:5173 `
  --restart always `
  scan-web

Write-Host "Frontend container:"
docker ps | Select-String "scanner-frontend"

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
docker logs scanner-backend --tail 20

Write-Host "===== FRONTEND LOG (last 20) ====="
docker logs scanner-frontend --tail 20

# =========================
# 6. Cleanup
# =========================
Write-Host "===== CLEANUP ====="
docker image prune -f

Write-Host "===== DEPLOY COMPLETE ====="
cd $RootDir
