from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.sql import func
from app.core.database import Base

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(Integer, primary_key=True, index=True)
    scan_date = Column(DateTime(timezone=True), server_default=func.now())
    target_name = Column(String)  # ชื่อเครื่องที่สแกน
    score = Column(Integer)       # คะแนนความปลอดภัย (0-100)
    
    # เก็บรายละเอียดผลการสแกนแต่ละข้อเป็น JSON 
    # เช่น {"firewall": "pass", "password_policy": "fail"}
    details = Column(JSON) 
    
    # เชื่อมโยงว่าใครเป็นคนสั่งสแกน
    user_id = Column(Integer, ForeignKey("users.id"))