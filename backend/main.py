import os
import datetime

from fastapi import FastAPI, Depends, HTTPException
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
from app.core.scan.scanner.security_scanner import SecurityBaselineScanner
from app.core.scan.scanner.executors.remote_executor import RemoteExecutor

Base.metadata.create_all(bind=engine)

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Version → Baseline file mapping
# ---------------------------------------------------------------------------

DATA_PATH = r"C:\MicrosoftScanEngine\backend\data"

BASELINE_FILE_MAP = {
    "Windows 11 v24H2": "MS Security Baseline Windows 11 v24H2.xlsx",
    "Windows 11 v25H2": "MS Security Baseline Windows 11 v25H2.xlsx",
}


def resolve_baseline_path(version: str) -> str:
    """แปลง version string → full path ของไฟล์ baseline พร้อมตรวจว่ามีไฟล์จริง"""
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
# Schemas
# ---------------------------------------------------------------------------

class RemoteScanRequest(BaseModel):
    host: str = Field(..., example="192.168.1.50")
    username: str = Field(..., example=".\\Administrator")
    password: str = Field(..., example="P@ssw0rd")
    version: str = Field("Windows 11 v25H2", description="version ของ baseline เช่น 'Windows 11 v24H2'")
    use_ssl: bool = Field(False, description="ใช้ WinRM over HTTPS (port 5986)")
    skip_ca_check: bool = Field(True, description="ข้ามการตรวจ CA cert (self-signed)")
    target_name: str = Field("", description="ชื่อ label สำหรับบันทึกผล (ถ้าว่างจะใช้ hostname)")


class LocalScanRequest(BaseModel):
    version: str = Field("Windows 11 v25H2", description="version ของ baseline ที่ต้องการสแกน")


class ConnectionTestRequest(BaseModel):
    host: str
    username: str
    password: str
    use_ssl: bool = False
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
# Auth Routes
# ---------------------------------------------------------------------------

@app.post("/register", response_model=UserResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user_data.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    hashed_pwd = get_password_hash(user_data.password)
    new_user = User(username=user_data.username, hashed_password=hashed_pwd, role="admin")
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
        "token_type": "bearer",
        "username": user.username,
        "role": user.role,
    }


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    latest = db.query(ScanResult).order_by(ScanResult.scan_date.desc()).first()
    count = db.query(func.count(ScanResult.id)).scalar()
    if not latest:
        return {"total_scans": 0, "latest_score": 0, "target": "No Data", "details": {}}
    return {
        "total_scans": count,
        "latest_score": latest.score,
        "target": latest.target_name,
        "details": latest.details,
    }


# ---------------------------------------------------------------------------
# Local Scan
# ---------------------------------------------------------------------------

@app.post("/api/scan/run")
async def run_security_scan(req: LocalScanRequest, db: Session = Depends(get_db)):
    """รันการสแกน Local Machine ตาม version ที่เลือก"""
    try:
        baseline_path = resolve_baseline_path(req.version)

        scanner = SecurityBaselineScanner(DATA_PATH)
        scanner.target_file = baseline_path  # override ตาม version ที่เลือก

        score, details = scanner.run_baseline_scan()
        if "Error" in details:
            raise HTTPException(status_code=500, detail=details["Error"])

        new_scan = ScanResult(
            target_name=f"localhost ({req.version})",
            score=score,
            details=details,
            scan_date=datetime.datetime.now(),
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)

        return {
            "status": "success",
            "version": req.version,
            "baseline_file": os.path.basename(baseline_path),
            "score": score,
            "items_scanned": len(details),
            "details": details,          # ← เพิ่ม details เพื่อให้ frontend แสดงผล
        }

    except (ValueError, FileNotFoundError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Remote Scan
# ---------------------------------------------------------------------------

@app.post("/api/scan/test-connection")
async def test_remote_connection(req: ConnectionTestRequest):
    """ทดสอบการเชื่อมต่อ WinRM ก่อนสแกนจริง"""
    try:
        executor = RemoteExecutor(
            host=req.host,
            username=req.username,
            password=req.password,
            use_ssl=req.use_ssl,
            skip_ca_check=req.skip_ca_check,
        )
        return executor.test_connection()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/remote")
async def run_remote_security_scan(req: RemoteScanRequest, db: Session = Depends(get_db)):
    """รันการสแกน MS Security Baseline บน remote Windows machine"""
    try:
        # 1. ตรวจ version และ path ก่อนเลย
        baseline_path = resolve_baseline_path(req.version)

        # 2. เชื่อมต่อ remote
        executor = RemoteExecutor(
            host=req.host,
            username=req.username,
            password=req.password,
            use_ssl=req.use_ssl,
            skip_ca_check=req.skip_ca_check,
        )

        conn_test = executor.test_connection()
        if not conn_test["success"]:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot connect to {req.host}: {conn_test['message']}"
            )

        hostname = conn_test.get("hostname") or req.host
        target_label = req.target_name.strip() or f"{hostname} ({req.version})"

        # 3. สแกนด้วย baseline ตาม version ที่เลือก
        scanner = SecurityBaselineScanner(data_path=DATA_PATH, executor=executor)
        scanner.target_file = baseline_path  # override ตาม version ที่เลือก

        score, details = scanner.run_baseline_scan()
        if "Error" in details:
            raise HTTPException(status_code=500, detail=details["Error"])

        # 4. บันทึกผล
        new_scan = ScanResult(
            target_name=target_label,
            score=score,
            details=details,
            scan_date=datetime.datetime.now(),
        )
        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)

        return {
            "status": "success",
            "host": req.host,
            "hostname": hostname,
            "target_name": target_label,
            "version": req.version,
            "baseline_file": os.path.basename(baseline_path),
            "score": score,
            "items_scanned": len(details),
            "details": details,          # ← เพิ่ม details เพื่อให้ frontend แสดงผล
        }

    except (ValueError, FileNotFoundError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# History & Versions
# ---------------------------------------------------------------------------

@app.get("/api/scan/history")
async def get_scan_history(limit: int = 20, db: Session = Depends(get_db)):
    scans = (
        db.query(ScanResult)
        .order_by(ScanResult.scan_date.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": s.id,
            "target_name": s.target_name,
            "score": s.score,
            "scan_date": s.scan_date.isoformat(),
            "items_scanned": len(s.details) if s.details else 0,
        }
        for s in scans
    ]


@app.get("/api/scan/versions")
async def get_supported_versions():
    """ดึงรายการ version ที่รองรับ พร้อมสถานะว่ามีไฟล์อยู่จริงไหม"""
    return [
        {
            "version": version,
            "filename": filename,
            "available": os.path.exists(os.path.join(DATA_PATH, filename)),
        }
        for version, filename in BASELINE_FILE_MAP.items()
    ]