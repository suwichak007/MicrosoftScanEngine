import os
import uuid
import datetime
import asyncio

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
from app.core.scan.scanner.security_scanner import SecurityScanner as SecurityBaselineScanner
from app.core.scan.scanner.executors.remote_executor import RemoteExecutor
from fastapi.concurrency import run_in_threadpool

from app.core.security import get_current_user
from app.core.summary_route import router as summary_router


Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(summary_router)

# ---------------------------------------------------------------------------
# Version → Baseline file mapping
# ---------------------------------------------------------------------------

DATA_PATH = r"C:\MicrosoftScanEngine\backend\data"

BASELINE_FILE_MAP = {
    "Windows 11 v24H2": "MS Security Baseline Windows 11 v24H2.xlsx",
    "Windows 11 v25H2": "MS Security Baseline Windows 11 v25H2.xlsx",
}

# scan timeout รวม (วินาที) — ถ้าเกินนี้ถือว่า timeout
SCAN_TIMEOUT_SECONDS = 120


def resolve_baseline_path(version: str) -> str:
    filename = BASELINE_FILE_MAP.get(version)
    if not filename:
        raise ValueError(
            f"ไม่รองรับ version '{version}' "
            f"รองรับเฉพาะ: {list(BASELINE_FILE_MAP.keys())}"
        )
    path = os.path.join(DATA_PATH, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"ไม่พบไฟล์ baseline: {path}")
    return path


# ---------------------------------------------------------------------------
# In-memory Job Store  (scan job status)
# ---------------------------------------------------------------------------

class ScanJob:
    def __init__(self):
        self.status   = "pending"   # pending | running | done | error
        self.progress = 0           # 0-100
        self.message  = ""
        self.result   = None        # dict ผลลัพธ์เมื่อสำเร็จ
        self.error    = ""

# job_id → ScanJob
_jobs: dict[str, ScanJob] = {}

def _new_job() -> tuple[str, ScanJob]:
    job_id = str(uuid.uuid4())
    job    = ScanJob()
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
    use_ssl:       bool = Field(False)
    skip_ca_check: bool = Field(True)
    target_name:   str  = Field("")

class LocalScanRequest(BaseModel):
    version: str = Field("Windows 11 v24H2")

class ConnectionTestRequest(BaseModel):
    host:          str
    username:      str
    password:      str
    use_ssl:       bool = False
    skip_ca_check: bool = True


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
    job:           ScanJob,
    baseline_path: str,
    version:       str,
    target_label:  str,
    executor=None,       # None = local scan
    user_id: int = None,
):
    """Worker ที่รันใน background โดยไม่บล็อก event loop"""
    job.status   = "running"
    job.progress = 5
    job.message  = "กำลังเตรียม scanner..."

    try:
        scanner = SecurityBaselineScanner(
            data_path=DATA_PATH,
            executor=executor,
        )
        scanner.target_file = baseline_path

        job.progress = 15
        job.message  = "กำลังสแกน Security Policy..."

        # รัน blocking scan ใน thread pool พร้อม timeout รวม
        try:
            score, details = await asyncio.wait_for(
                run_in_threadpool(scanner.run_baseline_scan),
                timeout=SCAN_TIMEOUT_SECONDS,
            )
        except asyncio.TimeoutError:
            job.status  = "error"
            job.error   = f"Scan timeout หลังจาก {SCAN_TIMEOUT_SECONDS}s — ตรวจสอบการเชื่อมต่อ WinRM"
            return

        if "Error" in details:
            job.status = "error"
            job.error  = details["Error"]
            return

        job.progress = 90
        job.message  = "กำลังบันทึกผล..."

        # บันทึก DB ใน thread pool
        def _save():
            db = SessionLocal()
            try:
                new_scan = ScanResult(
                    target_name=target_label,
                    score=score,
                    details=details,
                    scan_date=datetime.datetime.now(),
                    version=version,        # ← เพิ่ม
                    hostname=executor.host if executor else "localhost",  # ← เพิ่ม
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
            "scan_id":      scan_id,
            "target_name":  target_label,
            "version":      version,
            "baseline_file": os.path.basename(baseline_path),
            "score":        score,
            "items_scanned": len(details),
            "details":      details,
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
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="Username or password incorrect")
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {
        "access_token": access_token,
        "token_type":   "bearer",
        "username":     user.username,
        "role":         user.role,
    }


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
        "total_scans":   count,
        "latest_score":  latest.score,
        "target":        latest.target_name,
        "details":       latest.details,
    }


# ---------------------------------------------------------------------------
# Local Scan  (Background Task + polling)
# ---------------------------------------------------------------------------

@app.post("/api/scan/run")
async def run_security_scan(
    req:                LocalScanRequest,
    background_tasks:   BackgroundTasks,
):
    """เริ่มสแกน Local Machine — คืน job_id ทันที ให้ frontend poll /api/scan/status/{job_id}"""
    try:
        baseline_path = resolve_baseline_path(req.version)
    except (ValueError, FileNotFoundError) as e:
        raise HTTPException(status_code=400, detail=str(e))

    job_id, job = _new_job()
    target_label = f"localhost ({req.version})"

    background_tasks.add_task(
        _run_scan_job,
        job=job,
        baseline_path=baseline_path,
        version=req.version,
        target_label=target_label,
    )

    return {"job_id": job_id, "status": "pending"}


# ---------------------------------------------------------------------------
# Remote Scan  (Background Task + polling)
# ---------------------------------------------------------------------------

@app.post("/api/scan/test-connection")
async def test_remote_connection(req: ConnectionTestRequest):
    try:
        executor = RemoteExecutor(
            host=req.host, username=req.username, password=req.password,
            use_ssl=req.use_ssl, skip_ca_check=req.skip_ca_check,
        )
        # test_connection อาจ block → ใส่ใน threadpool + timeout
        result = await asyncio.wait_for(
            run_in_threadpool(executor.test_connection),
            timeout=15,
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
    current_user:     User = Depends(get_current_user),  # ← เพิ่มตรงนี้
):
    try:
        baseline_path = resolve_baseline_path(req.version)
    except (ValueError, FileNotFoundError) as e:
        raise HTTPException(status_code=400, detail=str(e))

    executor = RemoteExecutor(
        host=req.host, username=req.username, password=req.password,
        use_ssl=req.use_ssl, skip_ca_check=req.skip_ca_check,
    )
    try:
        conn_test = await asyncio.wait_for(
            run_in_threadpool(executor.test_connection),
            timeout=15,
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

    job_id, job = _new_job()

    background_tasks.add_task(
        _run_scan_job,
        job=job,
        baseline_path=baseline_path,
        version=req.version,
        target_label=target_label,
        executor=executor,
        user_id=current_user.id,  # ← ตอนนี้มี current_user แล้ว
    )

    return {
        "job_id":      job_id,
        "status":      "pending",
        "host":        req.host,
        "hostname":    hostname,
        "target_name": target_label,
    }


# ---------------------------------------------------------------------------
# Job Status Polling  ← frontend เรียกทุก 2s
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
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(ScanResult)

    # admin เห็นทั้งหมด, user เห็นแค่ของตัวเอง
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
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(ScanResult).filter(ScanResult.id == scan_id)

    # user ธรรมดาเข้าถึงได้แค่ของตัวเอง
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

@app.get("/api/scan/versions")
async def get_supported_versions():
    return [
        {
            "version":   version,
            "filename":  filename,
            "available": os.path.exists(os.path.join(DATA_PATH, filename)),
        }
        for version, filename in BASELINE_FILE_MAP.items()
    ]