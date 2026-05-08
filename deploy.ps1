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

# Load root .env so docker run receives the same settings as docker-compose.
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$EnvPath = Join-Path $RootDir ".env"
if (Test-Path $EnvPath) {
  Get-Content $EnvPath | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith("#") -and $line.Contains("=")) {
      $name, $value = $line.Split("=", 2)
      [System.Environment]::SetEnvironmentVariable($name.Trim(), $value.Trim(), "Process")
    }
  }
}

# =========================
# 1. Backend
# =========================
Write-Host "===== BACKEND ====="
cd backend

# Stop & Remove old container
docker rm -f scanner-backend 2>$null

# Build (no cache กันโค้ดไม่เปลี่ยน)
docker build --no-cache -t scan-api .

# Run container
docker run -d `
  --name scanner-backend `
  -p 8000:8000 `
  -e WINRM_USER=$env:WINRM_USER `
  -e WINRM_PASS=$env:WINRM_PASS `
  -e GROQ_API_KEY=$env:GROQ_API_KEY `
  -e GROQ_MODEL=$env:GROQ_MODEL `
  -v "${PWD}/data:C:/MicrosoftScanEngine/backend/data" `
  -v "${PWD}/../agent/dist:C:/MicrosoftScanEngine/agent/dist" `
  --restart always `
  scan-api

# Verify backend
Write-Host "Backend container:"
docker ps | Select-String "scanner-backend"

# =========================
# 2. Frontend
# =========================
Write-Host "===== FRONTEND ====="
cd ../frontend

docker rm -f scanner-frontend 2>$null

docker build --no-cache -t scan-web .

docker run -d `
  --name scanner-frontend `
  -p 5173:5173 `
  --restart always `
  scan-web

# Verify frontend
Write-Host "Frontend container:"
docker ps | Select-String "scanner-frontend"

# =========================
# 3. Check Image Info
# =========================
Write-Host "===== IMAGE INFO ====="
docker images scan-api
docker images scan-web

# =========================
# 4. Logs (debug)
# =========================
Write-Host "===== BACKEND LOG (last 20) ====="
docker logs scanner-backend --tail 20

Write-Host "===== FRONTEND LOG (last 20) ====="
docker logs scanner-frontend --tail 20

# =========================
# 5. Cleanup
# =========================
Write-Host "===== CLEANUP ====="
docker image prune -f

Write-Host "===== DEPLOY COMPLETE ====="
