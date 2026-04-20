from pydantic import BaseModel
from datetime import datetime
from typing import Dict, Any

class ScanResultBase(BaseModel):
    target_name: str
    score: int
    details: Dict[str, Any]

class ScanResultResponse(ScanResultBase):
    id: int
    scan_date: datetime

    class Config:
        from_attributes = True