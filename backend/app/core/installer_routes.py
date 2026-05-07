# installer_routes.py
import os
import secrets
from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse, StreamingResponse


router = APIRouter(tags=["installer"])

BACKEND_URL = os.getenv("BACKEND_URL", "http://192.168.105.11:8000")
AGENT_DIR   = r"C:\MicrosoftScanEngine"
EXE_PATH    = r"C:\MicrosoftScanEngine\agent\dist\MicrosoftScanAgent.exe"
XLSX_PATH   = r"C:\MicrosoftScanEngine\backend\data"
NSSM_PATH   = r"C:\MicrosoftScanEngine\backend\data\nssm.exe"


def _file_stream(path: str, chunk_size: int = 1024 * 1024):
    """Generator stream ไฟล์ทีละ 1MB"""
    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            yield chunk


@router.get("/install", response_class=PlainTextResponse)
def get_install_script():
    script = f"""
$ErrorActionPreference = 'Stop'
$AgentDir   = '{AGENT_DIR}'
$BackendUrl = '{BACKEND_URL}'

Write-Host "===== MicrosoftScanAgent Installer =====" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/5] สร้าง folder $AgentDir"
New-Item -ItemType Directory -Force -Path $AgentDir | Out-Null
New-Item -ItemType Directory -Force -Path "$AgentDir\\data" | Out-Null

Write-Host "[2/5] ลงทะเบียนกับ backend..."
$hostname = $env:COMPUTERNAME
$resp     = Invoke-RestMethod "$BackendUrl/agent/register?hostname=$hostname" -Method POST
$token    = $resp.token
$agentId  = $resp.agent_id
Write-Host "      agent_id = $agentId" -ForegroundColor Green

Write-Host "[3/5] สร้าง agent_config.json"
$config = @{{
    backend_url   = $BackendUrl
    agent_token   = $token
    poll_interval = 10
    data_path     = "$AgentDir\\data"
}} | ConvertTo-Json
$config | Out-File "$AgentDir\\agent_config.json" -Encoding UTF8

Write-Host "[4/5] ดาวน์โหลดไฟล์..."

Write-Host "      - MicrosoftScanAgent.exe (อาจใช้เวลาสักครู่...)"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile("$BackendUrl/install/agent.exe", "$AgentDir\\MicrosoftScanAgent.exe")

Write-Host "      - nssm.exe"
$wc.DownloadFile("$BackendUrl/install/nssm.exe", "$AgentDir\\nssm.exe")

Write-Host "      - baseline xlsx"
$wc.DownloadFile("$BackendUrl/install/baseline.xlsx", "$AgentDir\\data\\MS Security Baseline Windows 11 v24H2.xlsx")

Write-Host "[5/5] ติดตั้ง Windows Service..."
$nssm = "$AgentDir\\nssm.exe"
$exe  = "$AgentDir\\MicrosoftScanAgent.exe"

& $nssm install MicrosoftScanAgent $exe
& $nssm set MicrosoftScanAgent AppDirectory   $AgentDir
& $nssm set MicrosoftScanAgent AppStdout      "$AgentDir\\agent.log"
& $nssm set MicrosoftScanAgent AppStderr      "$AgentDir\\agent_err.log"
& $nssm set MicrosoftScanAgent AppRotateFiles 1
& $nssm set MicrosoftScanAgent AppRotateBytes 10485760
& $nssm set MicrosoftScanAgent Start          SERVICE_AUTO_START
& $nssm start MicrosoftScanAgent

Write-Host ""
Write-Host "===== ติดตั้งเสร็จเรียบร้อย =====" -ForegroundColor Green
Write-Host "Agent ID : $agentId" -ForegroundColor Yellow
Write-Host "Log      : $AgentDir\\agent.log"
""".strip()
    return PlainTextResponse(content=script)


@router.get("/install/agent.exe")
def download_agent_exe():
    if not os.path.exists(EXE_PATH):
        raise HTTPException(404, f"ไม่พบ exe ที่ {EXE_PATH} — กรุณา build ก่อน")
    file_size = os.path.getsize(EXE_PATH)
    return StreamingResponse(
        _file_stream(EXE_PATH),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": "attachment; filename=MicrosoftScanAgent.exe",
            "Content-Length": str(file_size),
        },
    )


@router.get("/install/nssm.exe")
def download_nssm():
    if not os.path.exists(NSSM_PATH):
        raise HTTPException(404, "ไม่พบ nssm.exe — วางไว้ที่ backend/data/nssm.exe")
    file_size = os.path.getsize(NSSM_PATH)
    return StreamingResponse(
        _file_stream(NSSM_PATH),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": "attachment; filename=nssm.exe",
            "Content-Length": str(file_size),
        },
    )


@router.get("/install/baseline.xlsx")
def download_baseline():
    path = os.path.join(
        XLSX_PATH,
        "MS Security Baseline Windows 11 v24H2.xlsx"
    )
    if not os.path.exists(path):
        raise HTTPException(404, "ไม่พบไฟล์ baseline")
    file_size = os.path.getsize(path)
    return StreamingResponse(
        _file_stream(path),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": "attachment; filename=baseline.xlsx",
            "Content-Length": str(file_size),
        },
    )