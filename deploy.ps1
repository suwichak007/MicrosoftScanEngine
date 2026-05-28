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
if (Test-Path $EnvPath) {
  $DockerEnvArgs = @("--env-file", $EnvPath)
  Get-Content $EnvPath | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
      $name, $value = $line.Split("=", 2)
      [System.Environment]::SetEnvironmentVariable($name.Trim(), $value.Trim(), "Process")
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
$backendRunArgs += @(
  "-e", "AGENT_INSTALL_TOKEN=$env:AGENT_INSTALL_TOKEN",
  "-e", "SECRET_KEY=$env:SECRET_KEY",
  "-e", "AUTH_PROVIDER=$env:AUTH_PROVIDER",
  "-e", "ACCESS_TOKEN_EXPIRE_MINUTES=$env:ACCESS_TOKEN_EXPIRE_MINUTES",
  "-e", "WINRM_USER=$env:WINRM_USER",
  "-e", "WINRM_PASS=$env:WINRM_PASS",
  "-e", "GROQ_API_KEY=$env:GROQ_API_KEY",
  "-e", "GROQ_MODEL=$env:GROQ_MODEL",
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
