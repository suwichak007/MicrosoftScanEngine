"""
main.py  (updated — config-driven multi-OS support via JSON baselines)

เปลี่ยนหลักๆ:
  - ถอดการโหลดและแกะไฟล์ Excel/XLSX ตัวเก่าออกทั้งหมด
  - ใช้ load_checks() และ list_available_versions() เพื่อดึงข้อมูลตรงจาก JSON แทน
  - ปรับปรุง _run_scan_job ให้ส่งฟังก์ชัน checks เข้า run_baseline_scan()
  - ปรับปรุงทุก Endpoint (/run, /remote, /versions, /agent) ให้รองรับโครงสร้างใหม่
"""

import os
import uuid
import datetime
import asyncio
import time

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
    load_checks,               # ← ใหม่: load checks จาก JSON
    list_available_versions,   # ← ใหม่: list จาก JSON files
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
from app.core.baseline_metadata import enrich_scan_details, summarize_findings

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
SCAN_TIMEOUT_SECONDS = int(os.environ.get("SCAN_TIMEOUT_SECONDS", "600"))

@app.on_event("startup")
async def startup_event():
    """ตรวจสอบหรือแสดงผลระบบจัดเก็บ Baseline แบบใหม่ตอนเริ่มต้นระบบ"""
    try:
        versions = list_available_versions()
        print(f"[startup] Available JSON baselines detected: {versions}")
    except Exception as e:
        print(f"[startup] Warning during baseline detection: {str(e)}")


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
    host:          str  = Field(...,   example="192.168.1.50")
    username:      str  = Field(...,   example=".\\Administrator")
    password:      str  = Field(...,   example="P@ssw0rd")
    version:       str  = Field("Windows 11 v24H2")
    role:          str  = Field("Member Server")   
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
# Background scan worker (จุดที่ 2 ตามหลักการแก้โค้ดใหม่)
# ---------------------------------------------------------------------------

async def _run_scan_job(
    job, version, target_label,
    role: str = "Member Server",
    executor=None, user_id=None,
):
    started_at = time.perf_counter()

    def _log_stage(stage: str, detail: str = ""):
        suffix = f" ({detail})" if detail else ""
        print(f"[scan-timing] {stage}: {time.perf_counter() - started_at:.2f}s{suffix}")

    job.status   = "running"
    job.progress = 5
    job.message  = "กำลังโหลด check definitions..."
    _log_stage("job_started", f"version={version} role={role} target={target_label}")

    # ── โหลด checks จาก JSON แทนการแกะไฟล์ตัวเก่า ──────────────────
    try:
        checks = load_checks(version, role=role)
    except FileNotFoundError as e:
        job.status = "error"
        job.error  = str(e)
        _log_stage("load_checks_failed", str(e))
        return

    if not checks:
        job.status = "error"
        job.error  = f"ไม่พบ check definitions สำหรับ version '{version}'"
        _log_stage("load_checks_empty")
        return

    job.progress = 10
    job.message  = "กำลังเตรียมข้อมูล Registry..."
    _log_stage("checks_loaded", f"count={len(checks)}")

    if executor and hasattr(executor, "prefetch_registry_bulk"):
        registry_keys = []
        for c in checks:
            rp = c.get("registry_path", "")
            if rp and "!" in rp:
                path_part, key_name = rp.split("!", 1)
                # normalize hive
                import re as _re
                path_upper = path_part.upper()
                if path_upper.startswith("HKLM\\") or path_upper.startswith("HKEY_LOCAL_MACHINE\\"):
                    sub = _re.sub(r"^(HKEY_LOCAL_MACHINE|HKLM)\\", "", path_part, flags=_re.IGNORECASE)
                    registry_keys.append(("HKLM", sub, key_name))
                elif path_upper.startswith("HKCU\\") or path_upper.startswith("HKEY_CURRENT_USER\\"):
                    sub = _re.sub(r"^(HKEY_CURRENT_USER|HKCU)\\", "", path_part, flags=_re.IGNORECASE)
                    registry_keys.append(("HKCU", sub, key_name))
                elif path_upper.startswith("MACHINE\\"):  # ← เพิ่มนี้
                    sub = _re.sub(r"^MACHINE\\", "", path_part, flags=_re.IGNORECASE)
                    registry_keys.append(("HKLM", sub, key_name))
                elif path_upper.startswith("SOFTWARE\\"):  # ← เพิ่มนี้
                    registry_keys.append(("HKLM", path_part, key_name))
        if registry_keys:
            batch_size = 100
            total_batches = (len(registry_keys) + batch_size - 1) // batch_size
            _log_stage("prefetch_registry_start", f"keys={len(registry_keys)} batches={total_batches}")
            for index in range(0, len(registry_keys), batch_size):
                batch_number = index // batch_size + 1
                batch = registry_keys[index:index + batch_size]
                job.progress = 10 + int(4 * (batch_number - 1) / max(total_batches, 1))
                job.message = f"กำลังเตรียมข้อมูล Registry... ({batch_number}/{total_batches})"
                _log_stage("prefetch_registry_batch_start", f"batch={batch_number}/{total_batches} keys={len(batch)}")
                # ใช้ timeout รอบการ prefetch แต่ละ batch เพื่อป้องกันการค้างทั้งหมด
                try:
                    batch_timeout = getattr(executor, "_REGISTRY_PREFETCH_TIMEOUT", 25)
                    # cap timeout to a reasonable upper bound
                    batch_timeout = int(batch_timeout or 25)
                    await asyncio.wait_for(
                        run_in_threadpool(executor.prefetch_registry_bulk, batch),
                        timeout=batch_timeout,
                    )
                    _log_stage("prefetch_registry_batch_done", f"batch={batch_number}/{total_batches} keys={len(batch)}")
                except asyncio.TimeoutError:
                    # ถ้าบาง batch timeout ให้บันทึกแล้วยุติการ prefetch ทั้งหมด
                    # (การรอให้ timeout ซ้ำหลาย batch ทำให้เสียเวลาเป็นจำนวนมาก)
                    _log_stage("prefetch_registry_batch_timeout", f"batch={batch_number}/{total_batches}")
                    job.message = f"กำลังเตรียมข้อมูล Registry... (ยกเลิกการ prefetch เนื่องจาก timeout ที่ batch {batch_number})"
                    prefetch_failed = True
                    break
                except Exception as e:
                    _log_stage("prefetch_registry_batch_error", f"batch={batch_number}/{total_batches} err={type(e).__name__}: {e}")
                    job.message = f"เกิดข้อผิดพลาดขณะเตรียม Registry (batch {batch_number})"
                    prefetch_failed = True
                    break
            # end for batches
            if 'prefetch_failed' in locals() and prefetch_failed:
                _log_stage("prefetch_registry_aborted", f"after batch={batch_number}")
            else:
                _log_stage("prefetch_registry_done", f"keys={len(registry_keys)} batches={total_batches}")
            

    job.progress = 15
    job.message  = "กำลังสแกน Security Policy..."
    _log_stage("scan_phase_start", f"checks={len(checks)}")

    try:
        # ── สร้าง scanner ไม่ต้องส่ง baseline_config / data_path อีกแล้ว ──
        from app.core.scan.scanner.security_scanner import SecurityScanner as SecurityBaselineScanner
        scanner = SecurityBaselineScanner(
            executor=executor,
            role=role,
        )
        
        try:
            _log_stage("scanner_run_start")
            score, details = await asyncio.wait_for(
                run_in_threadpool(scanner.run_baseline_scan, checks),  # ← ส่งตัวแปร checks เข้าไปตรงๆ
                timeout=SCAN_TIMEOUT_SECONDS,
            )
            _log_stage("scanner_run_done", f"score={score} details={len(details)}")
        except asyncio.TimeoutError:
            job.status = "error"
            job.error  = f"Scan timeout หลังจาก {SCAN_TIMEOUT_SECONDS}s"
            _log_stage("scanner_run_timeout", f"timeout={SCAN_TIMEOUT_SECONDS}s")
            return

        job.progress = 90
        job.message  = "กำลังบันทึกผล..."
        _log_stage("save_phase_start")

        findings        = enrich_scan_details(details, version=version, role=role)
        finding_summary = summarize_findings(findings)

        import datetime
        from app.core.database import SessionLocal
        from app.models.scan import ScanResult

        def _save():
            db = SessionLocal()
            try:
                new_scan = ScanResult(
                    target_name=target_label,
                    score=score,
                    details=details,          # เก็บ dict ครบ metadata
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
        _log_stage("save_phase_done", f"scan_id={scan_id}")

        job.status   = "done"
        job.progress = 100
        job.message  = "เสร็จสิ้น"
        job.result   = {
            "scan_id":       scan_id,
            "target_name":   target_label,
            "version":       version,
            "score":         score,
            "items_scanned": len(details),
            "details":       details,
            "findings":      findings,
            "summary":       finding_summary,
        }
        _log_stage("job_done", f"score={score} items={len(details)}")

    except Exception as e:
        job.status = "error"
        job.error  = str(e)
        _log_stage("job_error", f"{type(e).__name__}: {e}")


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
async def get_dashboard_stats(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    query = db.query(ScanResult)
    if current_user.role != "admin":
        query = query.filter(ScanResult.user_id == current_user.id)

    latest = query.order_by(ScanResult.scan_date.desc()).first()
    count  = query.with_entities(func.count(ScanResult.id)).scalar()
    if not latest:
        return {"total_scans": 0, "latest_score": 0, "target": "No Data", "details": {}}
    return {
        "total_scans":  count,
        "latest_score": latest.score,
        "target":       latest.target_name,
        "details":      latest.details,
    }


# ---------------------------------------------------------------------------
# Local Scan (จุดที่ 4 - แก้ไข Local Scan เอา resolve_baseline_path ออก)
# ---------------------------------------------------------------------------

@app.post("/api/scan/run")
async def run_security_scan(
    req:              LocalScanRequest,
    background_tasks: BackgroundTasks,
    current_user:     User = Depends(get_current_user),
):
    job_id, job  = _new_job()
    target_label = f"localhost ({req.version})"

    background_tasks.add_task(
        _run_scan_job,
        job=job,
        version=req.version,
        target_label=target_label,
        user_id=current_user.id,
    )
    return {"job_id": job_id, "status": "pending"}


# ---------------------------------------------------------------------------
# Remote Scan (จุดที่ 4 - แก้ไข Remote Scan เอา resolve_baseline_path ออก)
# ---------------------------------------------------------------------------

@app.post("/api/scan/test-connection")
async def test_remote_connection(
    req:          ConnectionTestRequest,
    current_user: User = Depends(get_current_user),
):
    try:
        executor = RemoteExecutor(
            host=req.host, username=req.username, password=req.password,
            use_ssl=req.use_ssl, skip_ca_check=req.skip_ca_check,
            timeout=SCAN_TIMEOUT_SECONDS,
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
    from app.core.scan.scanner.executors.remote_executor import RemoteExecutor
    import asyncio
    from fastapi.concurrency import run_in_threadpool

    executor = RemoteExecutor(
        host=req.host, username=req.username, password=req.password,
        use_ssl=req.use_ssl, skip_ca_check=req.skip_ca_check,
        timeout=SCAN_TIMEOUT_SECONDS,
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
        version=req.version,
        role=req.role,            
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
async def get_scan_status(
    job_id:       str,
    current_user: User = Depends(get_current_user),
):
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
            "pass_count": sum(
                1 for v in (s.details or {}).values()
                if isinstance(v, dict) and v.get("status") == "Pass"
            ),
            "fail_count": sum(
                1 for v in (s.details or {}).values()
                if isinstance(v, dict) and str(v.get("status", "")).startswith("Fail")
            ),
            "na_count": sum(
                1 for v in (s.details or {}).values()
                if isinstance(v, dict) and "Manual" in str(v.get("status", ""))
            ),
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
    role = "Domain Controller" if "Domain Controller" in (scan.target_name or "") else "Member Server"
    findings = enrich_scan_details(scan.details, version=scan.version or "", role=role)
    return {
        "id":            scan.id,
        "target_name":   scan.target_name,
        "score":         scan.score,
        "scan_date":     scan.scan_date.isoformat(),
        "version":       scan.version or "",
        "hostname":      scan.hostname or "",
        "items_scanned": len(scan.details) if scan.details else 0,
        "details":       scan.details,
        "findings":      findings,
        "summary":       summarize_findings(findings),
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


# ── จุดที่ 3 - แก้ไขเวอร์ชันให้อ่านจาก /baselines/generated/*.json แทน ──
@app.get("/api/scan/versions")
async def get_supported_versions(current_user: User = Depends(get_current_user)):
    return list_available_versions()


# ---------------------------------------------------------------------------
# Agent Scan (ปรับตัวแปรตามสถาปัตยกรรม JSON ใหม่)
# ---------------------------------------------------------------------------

@app.post("/api/scan/agent")
async def run_agent_scan(
    req:              AgentScanRequest,
    background_tasks: BackgroundTasks,
    current_user:     User = Depends(get_current_user),
):
    # ปรับเปลี่ยนให้ชี้ไปยัง Path ของไฟล์ JSON ในระบบใหม่แทน
    baseline_path = os.path.join(ROOT_DIR, "baselines", "generated", f"{req.version}.json")
    
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