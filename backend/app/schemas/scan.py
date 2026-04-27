from pydantic import BaseModel
from datetime import datetime
from typing import Dict, Any, Optional

class ScanResultBase(BaseModel):
    target_name: str
    score:       int
    details:     Dict[str, Any]

class ScanResultResponse(ScanResultBase):
    id:       int
    scan_date: datetime
    version:  Optional[str] = None   # ← เพิ่ม
    hostname: Optional[str] = None   # ← เพิ่ม

    class Config:
        from_attributes = True

class ScanHistoryItem(BaseModel):
    id:            int
    target_name:   str
    score:         int
    scan_date:     datetime
    version:       Optional[str] = None
    hostname:      Optional[str] = None
    items_scanned: int
    pass_count:    int
    fail_count:    int

    class Config:
        from_attributes = True