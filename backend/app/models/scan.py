from sqlalchemy import Column, Integer, String, DateTime, JSON, ForeignKey
from sqlalchemy.sql import func
from app.core.database import Base
from typing import Dict, Any, Optional 

class ScanResult(Base):
    __tablename__ = "scan_results"

    id          = Column(Integer, primary_key=True, index=True)
    scan_date   = Column(DateTime(timezone=True), server_default=func.now())
    target_name = Column(String)
    score       = Column(Integer)
    details     = Column(JSON)
    user_id     = Column(Integer, ForeignKey("users.id"))
    version     = Column(String, nullable=True)   # ← ต้องมี
    hostname    = Column(String, nullable=True)   # ← ต้องมี
    scan_type      = Column(String, default="single")   # "single" | "subnet"
    parent_scan_id = Column(Integer, nullable=True)     # สำหรับ child scan ของ subnet