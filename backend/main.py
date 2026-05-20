"""
main.py  (updated — config-driven multi-OS support)

เปลี่ยนหลักๆ:
  - BASELINE_FILE_MAP ถูกแทนที่ด้วย baseline_config.BASELINE_CONFIGS
  - resolve_baseline_path() ใช้ get_config() แทน
  - _run_scan_job() ส่ง baseline_config ให้ SecurityScanner
  - /api/scan/versions คืนข้อมูลจาก list_versions()
"""

import os
import uuid
import datetime
import asyncio

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if load_dotenv:
    load_dotenv(os.path.join(ROOT_DIR, ".env"))

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.core.database import SessionLocal, Base, engine
from app.models.user import User
from app.models.scan import ScanResult
from app.schemas.user import UserCreate, UserResponse
from app.schemas.scan import ScanResultResponse
from app.core.security import get_password_hash, verify_password, create_access_token
from app.core.config import AUTH_PROVIDER
from app.core.ldap_auth import authenticate_ldap
from app.core.scan.scanner.security_scanner import SecurityScanner as SecurityBaselineScanner
from app.core.scan.scanner.baseline_config import (
    get_config,
    list_versions,
    load_configs,
)
from app.core.scan.scanner.executors.remote_executor import RemoteExecutor
from fastapi.concurrency import run_in_threadpool

from app.core.security import get_current_user
from app.core.summary_route import router as summary_router
from app.core.installer_routes import router as installer_router
from app.core.agent_routes import router as agent_router, enqueue
from app.models.agent import AgentToken
from app.core.job_store import _jobs
from app.core.export_routes import router as export_router
from app.core.admin_routes import router as admin_router

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.include_router(installer_router)
app.include_router(agent_router)
app.include_router(export_router)
app.include_router(admin_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(summary_router)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_PATH = os.environ.get(
    "DATA_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
)
SCAN_TIMEOUT_SECONDS = 120

@app.on_event("startup")
async def startup_event():
    """โหลด baseline configs จาก data directory ตอนเริ่ม"""
    load_configs(DATA_PATH)
    print(f"[startup] loaded baselines: {list_versions()}")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def resolve_baseline_path(version_id: str) -> tuple[str, object]:
    try:
        cfg = get_config(version_id, data_path=DATA_PATH)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
 
    path = os.path.join(DATA_PATH, cfg.filename)
    if not os.path.exists(path):
        raise HTTPException(
            status_code=400,
            detail=f"ไม่พบไฟล์ baseline: {path}"
        )
    return path, cfg


# ---------------------------------------------------------------------------
# In-memory Job Store
# ---------------------------------------------------------------------------

class ScanJob:
    def __init__(self):
        self.status   = "pending"
        self.progress = 0
        self.message  = ""
        self.result   = None
        self.error    = ""

def _new_job() -> tuple[str, ScanJob]:
    job_id        = str(uuid.uuid4())
    job           = ScanJob()
    _jobs[job_id] = job
    return job_id, job


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RemoteScanRequest(BaseModel):
    host:          str  = Field(...,  example="192.168.1.50")
    username:      str  = Field(...,  example=".\\Administrator")
    password:      str  = Field(...,  example="P@ssw0rd")
    version:       str  = Field("Windows 11 v24H2")
    role:          str  = Field("Member Server")   # ← เพิ่ม
    use_ssl:       bool = Field(False)
    skip_ca_check: bool = Field(True)
    target_name:   str  = Field("")

class LocalScanRequest(BaseModel):
    version: str = Field("Windows 11 v24H2")

class AgentScanRequest(BaseModel):
    host:    str = Field(..., example="192.168.1.50")
    version: str = Field("Windows 11 v24H2")

class ConnectionTestRequest(BaseModel):
    host:          str
    username:      str
    password:      str
    use_ssl:       bool = False
    skip_ca_check: bool = True

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str


# ---------------------------------------------------------------------------
# DB Dependency
# ---------------------------------------------------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Background scan worker
# ---------------------------------------------------------------------------

async def _run_scan_job(
    job, baseline_path, baseline_cfg, version, target_label,
    role: str = "Member Server",   # ← เพิ่ม
    executor=None, user_id=None,
):
    job.status   = "running"
    job.progress = 5
    job.message  = "กำลังเตรียม scanner..."

    try:
        scanner = SecurityBaselineScanner(
            data_path=DATA_PATH,
            executor=executor,
            baseline_config=baseline_cfg,   # ← ส่ง config เข้า scanner
            role=role,        
        )
        scanner.target_file = baseline_path

        job.progress = 15
        job.message  = "กำลังสแกน Security Policy..."

        try:
            score, details = await asyncio.wait_for(
                run_in_threadpool(scanner.run_baseline_scan),
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            job.status = "error"
            job.error  = f"Scan timeout หลังจาก {SCAN_TIMEOUT_SECONDS}s — ตรวจสอบการเชื่อมต่อ WinRM"
            return

        if "Error" in details:
            job.status = "error"
            job.error  = details["Error"]
            return

        job.progress = 90
        job.message  = "กำลังบันทึกผล..."

        def _save():
            db = SessionLocal()
            try:
                new_scan = ScanResult(
                    target_name=target_label,
                    score=score,
                    details=details,
                    scan_date=datetime.datetime.now(),
                    version=version,
                    hostname=executor.host if executor else "localhost",
                    user_id=user_id,
                )
                db.add(new_scan)
                db.commit()
                db.refresh(new_scan)
                return new_scan.id
            finally:
                db.close()

        scan_id = await run_in_threadpool(_save)

        job.status   = "done"
        job.progress = 100
        job.message  = "เสร็จสิ้น"
        job.result   = {
            "scan_id":       scan_id,
            "target_name":   target_label,
            "version":       version,
            "baseline_file": os.path.basename(baseline_path),
            "score":         score,
            "items_scanned": len(details),
            "details":       details,
        }

    except Exception as e:
        job.status = "error"
        job.error  = str(e)


# ---------------------------------------------------------------------------
# Auth Routes
# ---------------------------------------------------------------------------

@app.post("/register", response_model=UserResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user_data.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_pwd = get_password_hash(user_data.password)
    new_user   = User(username=user_data.username, hashed_password=hashed_pwd, role="viewer")
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = None

    if AUTH_PROVIDER in ("ldap", "hybrid"):
        try:
            ldap_user = authenticate_ldap(form_data.username, form_data.password)
            user = db.query(User).filter(User.username == ldap_user.username).first()
            if not user:
                user = User(
                    username=ldap_user.username,
                    hashed_password="",
                    role=ldap_user.role,
                    is_active=True,
                )
                db.add(user)
            else:
                user.role = ldap_user.role
                user.is_active = True
            db.commit()
            db.refresh(user)
        except HTTPException:
            if AUTH_PROVIDER == "ldap":
                raise

    if user is None:
        user = db.query(User).filter(User.username == form_data.username).first()
        if not user or not user.hashed_password or not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Username or password incorrect")
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {
        "access_token": access_token,
        "token_type":   "bearer",
        "username":     user.username,
        "role":         user.role,
    }


@app.post("/api/user/change-password")
def change_password(
    body:         ChangePasswordRequest,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    if not current_user.hashed_password:
        raise HTTPException(status_code=400, detail="LDAP users cannot change password here")
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="รหัสผ่านเดิมไม่ถูกต้อง")
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="รหัสผ่านใหม่ต้องมีอย่างน้อย 6 ตัวอักษร")
    current_user.hashed_password = get_password_hash(body.new_password)
    db.add(current_user)
    db.commit()
    return {"ok": True, "message": "เปลี่ยนรหัสผ่านสำเร็จ"}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    latest = db.query(ScanResult).order_by(ScanResult.scan_date.desc()).first()
    count  = db.query(func.count(ScanResult.id)).scalar()
    if not latest:
        return {"total_scans": 0, "latest_score": 0, "target": "No Data", "details": {}}
    return {
        "total_scans":  count,
        "latest_score": latest.score,
        "target":       latest.target_name,
        "details":      latest.details,
    }


# ---------------------------------------------------------------------------
# Local Scan
# ---------------------------------------------------------------------------

@app.post("/api/scan/run")
async def run_security_scan(
    req:              LocalScanRequest,
    background_tasks: BackgroundTasks,
):
    baseline_path, baseline_cfg = resolve_baseline_path(req.version)
    job_id, job  = _new_job()
    target_label = f"localhost ({req.version})"

    background_tasks.add_task(
        _run_scan_job,
        job=job,
        baseline_path=baseline_path,
        baseline_cfg=baseline_cfg,
        version=req.version,
        target_label=target_label,
    )
    return {"job_id": job_id, "status": "pending"}


# ---------------------------------------------------------------------------
# Remote Scan
# ---------------------------------------------------------------------------

@app.post("/api/scan/test-connection")
async def test_remote_connection(req: ConnectionTestRequest):
    try:
        executor = RemoteExecutor(
            host=req.host, username=req.username, password=req.password,
            use_ssl=req.use_ssl, skip_ca_check=req.skip_ca_check,
        )
        result = await asyncio.wait_for(
            run_in_threadpool(executor.test_connection), timeout=15,
        )
        return result
    except asyncio.TimeoutError:
        raise HTTPException(status_code=408, detail="Connection timeout (15s)")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/remote")
async def run_remote_security_scan(
    req:              RemoteScanRequest,
    background_tasks: BackgroundTasks,
    current_user:     User = Depends(get_current_user),
):
    baseline_path, baseline_cfg = resolve_baseline_path(req.version)

    executor = RemoteExecutor(
        host=req.host, username=req.username, password=req.password,
        use_ssl=req.use_ssl, skip_ca_check=req.skip_ca_check,
    )
    try:
        conn_test = await asyncio.wait_for(
            run_in_threadpool(executor.test_connection), timeout=15,
        )
    except asyncio.TimeoutError:
        raise HTTPException(status_code=408, detail=f"ไม่สามารถเชื่อมต่อ {req.host}: timeout 15s")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if not conn_test["success"]:
        raise HTTPException(
            status_code=400,
            detail=f"ไม่สามารถเชื่อมต่อ {req.host}: {conn_test['message']}"
        )

    hostname     = conn_test.get("hostname") or req.host
    target_label = req.target_name.strip() or f"{hostname} ({req.version})"
    job_id, job  = _new_job()

    background_tasks.add_task(
        _run_scan_job,
        job=job,
        baseline_path=baseline_path,
        baseline_cfg=baseline_cfg,
        version=req.version,
        role=req.role,             # ← เพิ่ม
        target_label=target_label,
        executor=executor,
        user_id=current_user.id,
    )
    return {
        "job_id":      job_id,
        "status":      "pending",
        "host":        req.host,
        "hostname":    hostname,
        "target_name": target_label,
    }


# ---------------------------------------------------------------------------
# Job Status Polling
# ---------------------------------------------------------------------------

@app.get("/api/scan/status/{job_id}")
async def get_scan_status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="ไม่พบ job นี้")

    resp = {
        "job_id":   job_id,
        "status":   job.status,
        "progress": job.progress,
        "message":  job.message,
    }
    if job.status == "done":
        resp["result"] = job.result
        async def _cleanup():
            await asyncio.sleep(60)
            _jobs.pop(job_id, None)
        asyncio.create_task(_cleanup())
    elif job.status == "error":
        resp["error"] = job.error
        async def _cleanup_err():
            await asyncio.sleep(60)
            _jobs.pop(job_id, None)
        asyncio.create_task(_cleanup_err())
    return resp


# ---------------------------------------------------------------------------
# History & Versions
# ---------------------------------------------------------------------------

@app.get("/api/scan/history")
async def get_scan_history(
    limit:        int     = 20,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    query = db.query(ScanResult)
    if current_user.role != "admin":
        query = query.filter(ScanResult.user_id == current_user.id)
    scans = query.order_by(ScanResult.scan_date.desc()).limit(limit).all()
    return [
        {
            "id":            s.id,
            "target_name":   s.target_name,
            "score":         s.score,
            "scan_date":     s.scan_date.isoformat(),
            "version":       s.version or "",
            "hostname":      s.hostname or "",
            "items_scanned": len(s.details) if s.details else 0,
            "pass_count":    sum(1 for v in (s.details or {}).values() if str(v) == "Pass"),
            "fail_count":    sum(1 for v in (s.details or {}).values() if str(v).startswith("Fail")),
        }
        for s in scans
    ]


@app.get("/api/scan/history/{scan_id}")
async def get_scan_detail(
    scan_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    query = db.query(ScanResult).filter(ScanResult.id == scan_id)
    if current_user.role != "admin":
        query = query.filter(ScanResult.user_id == current_user.id)
    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="ไม่พบผลการสแกนนี้หรือไม่มีสิทธิ์เข้าถึง")
    return {
        "id":            scan.id,
        "target_name":   scan.target_name,
        "score":         scan.score,
        "scan_date":     scan.scan_date.isoformat(),
        "version":       scan.version or "",
        "hostname":      scan.hostname or "",
        "items_scanned": len(scan.details) if scan.details else 0,
        "details":       scan.details,
    }


@app.delete("/api/scan/history/{scan_id}")
async def delete_scan(
    scan_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    query = db.query(ScanResult).filter(ScanResult.id == scan_id)
    if current_user.role != "admin":
        query = query.filter(ScanResult.user_id == current_user.id)
    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="ไม่พบผลการสแกนหรือไม่มีสิทธิ์ลบ")
    db.delete(scan)
    db.commit()
    return {"ok": True}


@app.get("/api/scan/versions")
async def get_supported_versions():
    # force_reload=True ทำให้ detect ไฟล์ใหม่ที่เพิ่งวางได้เสมอ
    load_configs(DATA_PATH, force_reload=True)
    return [
        {
            "version_id":   v["version_id"],
            "display_name": v["display_name"],
            "filename":     v["filename"],
            "os_family":    v["os_family"],
            "available":    os.path.exists(os.path.join(DATA_PATH, v["filename"])),
        }
        for v in list_versions(data_path=DATA_PATH)
    ]

# ---------------------------------------------------------------------------
# Agent Scan
# ---------------------------------------------------------------------------

@app.post("/api/scan/agent")
async def run_agent_scan(
    req:              AgentScanRequest,
    background_tasks: BackgroundTasks,
    current_user:     User = Depends(get_current_user),
):
    baseline_path, baseline_cfg = resolve_baseline_path(req.version)
    agent_id    = f"agent-{req.host}"
    job_id, job = _new_job()
    job.status  = "running"
    job.message = "รอ agent รับงาน..."
    enqueue(agent_id, job_id, req.version, baseline_path)
    return {
        "job_id":   job_id,
        "status":   "pending",
        "host":     req.host,
        "agent_id": agent_id,
    }


@app.get("/api/agents")
async def list_agents(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    agents = db.query(AgentToken).order_by(AgentToken.last_seen.desc()).all()
    return [
        {
            "agent_id":   a.agent_id,
            "hostname":   a.hostname,
            "registered": a.registered.isoformat() if a.registered else None,
            "last_seen":  a.last_seen.isoformat() if a.last_seen else None,
        }
        for a in agents
    ]
