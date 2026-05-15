import datetime
import secrets

from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.job_store import _jobs
from app.core.database import SessionLocal
from app.models.scan import ScanResult
from app.models.agent import AgentToken

router = APIRouter(prefix="/agent", tags=["agent"])

# in-memory job queue เท่านั้น (token ย้ายไป DB แล้ว)
_pending: dict[str, list[dict]] = {}


# ── Dependency ──────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_agent_id(
    x_agent_token: str = Header(...),
    db: Session = Depends(get_db)
) -> str:
    row = db.query(AgentToken).filter(AgentToken.token == x_agent_token).first()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    # อัปเดต last_seen
    row.last_seen = datetime.datetime.now()
    db.commit()
    return row.agent_id


# ── Agent: ดึง job ที่รอ ────────────────────────────────────────────
@router.get("/jobs/pending")
def pending_jobs(agent_id: str = Depends(get_agent_id)):
    jobs = _pending.pop(agent_id, [])
    return {"jobs": jobs}


# ── Agent: ส่งผลสแกนกลับ ────────────────────────────────────────────
class JobResult(BaseModel):
    job_id:  str
    score:   int = 0
    details: dict = {}
    error:   str = ""


@router.post("/jobs/{job_id}/result")
def job_result(
    job_id:   str,
    body:     JobResult,
    agent_id: str = Depends(get_agent_id),
):

    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job not found")

    if body.error:
        job.status = "error"
        job.error  = body.error
    else:
        job.status   = "done"
        job.progress = 100
        job.message  = "เสร็จสิ้น"
        job.result   = {
            "score":         body.score,
            "details":       body.details,
            "items_scanned": len(body.details),
        }

        db: Session = SessionLocal()
        try:
            scan_record = ScanResult(
                target_name = agent_id,
                score       = body.score,
                details     = body.details,
                scan_date   = datetime.datetime.now(),
                hostname    = agent_id,
            )
            db.add(scan_record)
            db.commit()
            db.refresh(scan_record)
            job.result["scan_id"] = scan_record.id
        finally:
            db.close()

    return {"ok": True}


# ── Admin: ลงทะเบียน agent ─────────────────────────────────────────
@router.post("/register")
def register_agent(hostname: str, db: Session = Depends(get_db)):
    agent_id = f"agent-{hostname}"
    
    # ถ้ามีอยู่แล้ว ให้ออก token ใหม่
    row = db.query(AgentToken).filter(AgentToken.agent_id == agent_id).first()
    token = secrets.token_urlsafe(32)
    
    if row:
        row.token      = token
        row.registered = datetime.datetime.now()
    else:
        row = AgentToken(
            agent_id   = agent_id,
            token      = token,
            hostname   = hostname,
            registered = datetime.datetime.now(),
        )
        db.add(row)
    
    db.commit()
    return {"agent_id": agent_id, "token": token}


# ── Admin: ดู agent ทั้งหมด ────────────────────────────────────────
@router.get("/list")
def list_agents(db: Session = Depends(get_db)):
    rows = db.query(AgentToken).all()
    return [
        {
            "agent_id":   r.agent_id,
            "hostname":   r.hostname,
            "registered": r.registered.isoformat() if r.registered else None,
            "last_seen":  r.last_seen.isoformat() if r.last_seen else None,
            "online":     (
                datetime.datetime.now() - r.last_seen
            ).seconds < 60 if r.last_seen else False,
        }
        for r in rows
    ]


# ── Helper: main.py เรียกตอน enqueue job ──────────────────────────
def enqueue(agent_id: str, job_id: str, version: str, baseline_path: str):
    _pending.setdefault(agent_id, []).append({
        "job_id":        job_id,
        "version":       version,
        "baseline_path": baseline_path,
    })