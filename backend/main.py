from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func  # <--- ต้องมีตัวนี้เพื่อใช้ count()
from fastapi.middleware.cors import CORSMiddleware
import random

# Import Database Core
from app.core.database import SessionLocal, Base, engine

# Import Models (ต้อง Import ก่อนเรียก create_all)
from app.models.user import User
from app.models.scan import ScanResult 

# Import Schemas & Security
from app.schemas.user import UserCreate, UserResponse
from app.schemas.scan import ScanResultResponse
from app.core.security import get_password_hash, verify_password, create_access_token
from fastapi.security import OAuth2PasswordRequestForm

from app.core.scanner import SecurityScanner

# --- คำสั่งสร้างตารางใน Database (สำคัญมาก!) ---
Base.metadata.create_all(bind=engine)

app = FastAPI()

# Middleware สำหรับให้ React คุยกับ FastAPI ได้
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

# --- Auth Routes ---

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
        "role": user.role
    }

# --- Dashboard & Scan Routes ---

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    # ดึงข้อมูลล่าสุด
    latest_scan = db.query(ScanResult).order_by(ScanResult.scan_date.desc()).first()
    # นับจำนวนครั้งที่สแกนทั้งหมด
    total_scans = db.query(func.count(ScanResult.id)).scalar()
    
    if not latest_scan:
        return {"total_scans": 0, "latest_score": 0, "target": "N/A", "details": {}}

    return {
        "total_scans": total_scans,
        "latest_score": latest_scan.score,
        "target": latest_scan.target_name,
        "details": latest_scan.details
    }

@app.post("/api/scan/run")
async def run_security_scan(db: Session = Depends(get_db)):
    # เรียกใช้ตัวสแกนของจริง
    scanner = SecurityScanner()
    score, details = scanner.run_baseline_2602()
    
    new_scan = ScanResult(
        target_name="Windows-Server-2025-Node",
        score=score,
        details=details
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    return {"status": "success", "score": score}