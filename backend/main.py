from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import func
import datetime

# Import Database Core
from app.core.database import SessionLocal, Base, engine

# Import Models
from app.models.user import User
from app.models.scan import ScanResult

# Import Schemas & Security
from app.schemas.user import UserCreate, UserResponse
from app.schemas.scan import ScanResultResponse
from app.core.security import get_password_hash, verify_password, create_access_token

# Import Scanner (ใช้ชื่อ alias SecurityBaselineScanner จาก scanner.py)

from app.core.scan.scanner.security_scanner import SecurityBaselineScanner

# สร้างตารางใน Database
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Middleware CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Database Session Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# -----------------------------------------------------------------------
# Auth Routes
# -----------------------------------------------------------------------

@app.post("/register", response_model=UserResponse)
def register(user_data: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.username == user_data.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_pwd = get_password_hash(user_data.password)
    new_user   = User(username=user_data.username, hashed_password=hashed_pwd, role="admin")

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


# -----------------------------------------------------------------------
# Dashboard & Scan Routes
# -----------------------------------------------------------------------

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """ดึงสถิติและผลการสแกนล่าสุด"""
    latest = db.query(ScanResult).order_by(ScanResult.scan_date.desc()).first()
    count  = db.query(func.count(ScanResult.id)).scalar()
    

    if not latest:
        return {
            "total_scans":  0,
            "latest_score": 0,
            "target":       "No Data",
            "details":      {},
        }

    return {
        "total_scans":  count,
        "latest_score": latest.score,
        "target":       latest.target_name,
        "details":      latest.details,   # ต้องเป็น Type JSON ในฐานข้อมูล
    }


@app.post("/api/scan/run")
async def run_security_scan(db: Session = Depends(get_db)):
    """รันการสแกน MS Security Baseline Windows 11 v25H2"""
    try:
        # ✅ แก้ไข: path ชี้ไปยัง folder ที่มีไฟล์ v25H2
        DATA_PATH = r"D:\MiniProject\backend\data"
        scanner   = SecurityBaselineScanner(DATA_PATH)

        score, details = scanner.run_baseline_scan()

        # ตรวจสอบว่าสแกนสำเร็จจริง (ไม่ใช่ error จากไฟล์ไม่เจอ)
        if "Error" in details:
            raise HTTPException(status_code=500, detail=details["Error"])

        new_scan = ScanResult(
            target_name="Windows-11-v25H2-Scan",
            score=score,
            details=details,
            scan_date=datetime.datetime.now(),
        )

        db.add(new_scan)
        db.commit()
        db.refresh(new_scan)

        return {
            "status":        "success",
            "score":         score,
            "items_scanned": len(details),
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))