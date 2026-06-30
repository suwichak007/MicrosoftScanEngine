import datetime
import hashlib
import io
import os
import secrets
import zipfile
from pathlib import Path

from fastapi import APIRouter, HTTPException, Header, Depends
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.core.job_store import _jobs
from app.core.database import SessionLocal
from app.core.activity_routes import log_activity
from app.models.scan import ScanResult
from app.models.agent import AgentToken
from app.models.agent_job import AgentJob
from app.core.scan.scanner.framework_mapping import (
    calculate_cis_style_score,
    normalize_score_breakdown,
)

router = APIRouter(prefix="/agent", tags=["agent"])


AGENT_JOB_RUNNING_TIMEOUT_SECONDS = int(os.environ.get("AGENT_JOB_RUNNING_TIMEOUT_SECONDS", "900"))
AGENT_JOB_MAX_ATTEMPTS = int(os.environ.get("AGENT_JOB_MAX_ATTEMPTS", "2"))
ROOT_DIR = Path(__file__).resolve().parents[3]
SCANNER_SOURCE_DIR = Path(__file__).resolve().parent / "scan" / "scanner"


def _score_breakdown_from_details(details: dict | None) -> dict | None:
    if not isinstance(details, dict):
        return None
    return normalize_score_breakdown(details.get("_score_breakdown"))


def _calculate_compliance_score(details: dict | None) -> tuple[int, dict | None]:
    if not isinstance(details, dict):
        return 0, None
    existing = _score_breakdown_from_details(details)
    if existing:
        assessed = int(existing.get("total_assessed_count", 0) or 0)
        passed = int(existing.get("passed_assessed_count", 0) or 0)
        return (int((passed / assessed) * 100) if assessed else 0), existing
    return calculate_cis_style_score(details)


def _items_scanned(details: dict | None) -> int:
    if not isinstance(details, dict):
        return 0
    return sum(1 for key in details if not str(key).startswith("_"))


def _baseline_source_dirs() -> list[Path]:
    configured = os.environ.get("BASELINES_DIR", "").strip()
    candidates = []
    if configured:
        candidates.append(Path(configured))
    candidates.extend([
        ROOT_DIR / "baselines" / "generated",
        ROOT_DIR / "backend" / "baselines" / "generated",
        ROOT_DIR / "agent" / "baselines" / "generated",
    ])

    seen = set()
    existing = []
    for path in candidates:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        if resolved.is_dir():
            existing.append(resolved)
    return existing


def _iter_package_files():
    emitted = set()
    for path in SCANNER_SOURCE_DIR.rglob("*"):
        if path.is_file() and "__pycache__" not in path.parts and path.suffix in {".py", ".json", ".yaml", ".yml"}:
            arcname = Path("scanner") / path.relative_to(SCANNER_SOURCE_DIR)
            emitted.add(arcname.as_posix())
            yield path, arcname

    for baseline_dir in _baseline_source_dirs():
        for path in baseline_dir.rglob("*"):
            if path.is_file() and path.suffix.lower() in {".json", ".yaml", ".yml"}:
                arcname = Path("baselines") / "generated" / path.relative_to(baseline_dir)
                key = arcname.as_posix()
                if key in emitted:
                    continue
                emitted.add(key)
                yield path, arcname


def _build_scanner_package() -> tuple[bytes, str, str]:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        file_count = 0
        baseline_count = 0
        for src, arcname in _iter_package_files():
            zf.write(src, arcname.as_posix())
            file_count += 1
            if arcname.parts[:2] == ("baselines", "generated") and arcname.suffix.lower() == ".json":
                baseline_count += 1
        if file_count == 0:
            raise HTTPException(status_code=500, detail="Scanner package has no files")
        if baseline_count == 0:
            raise HTTPException(status_code=500, detail="Scanner package has no baseline JSON files")

    data = buffer.getvalue()
    sha256 = hashlib.sha256(data).hexdigest()
    version = os.environ.get("SCANNER_PACKAGE_VERSION") or sha256[:12]
    return data, version, sha256


def _sync_memory_job(row: AgentJob, message: str | None = None):
    job = _jobs.get(row.job_id)
    if not job:
        return
    job.status = row.status
    if row.status == "pending":
        job.progress = min(getattr(job, "progress", 0) or 0, 10)
    elif row.status == "running":
        job.progress = max(getattr(job, "progress", 0) or 0, 10)
    elif row.status == "error":
        job.progress = 100
        job.error = row.error or "Agent job failed"
    if message:
        job.message = message

# in-memory job queue เท่านั้น (token ย้ายไป DB แล้ว)
# ── Dependency ──────────────────────────────────────────────────────
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_agent_id(
    x_agent_token: str = Header(...),
    x_agent_hostname: str | None = Header(None),
    x_agent_version: str | None = Header(None),
    x_agent_detected_role: str | None = Header(None),
    x_agent_ip_addresses: str | None = Header(None),
    x_agent_os_name: str | None = Header(None),
    x_agent_os_version: str | None = Header(None),
    x_agent_os_build: str | None = Header(None),
    x_agent_os_release: str | None = Header(None),
    x_agent_os_family: str | None = Header(None),
    db: Session = Depends(get_db)
) -> str:
    row = db.query(AgentToken).filter(AgentToken.token == x_agent_token).first()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid agent token")
    # อัปเดต last_seen
    row.last_seen = datetime.datetime.now()
    if x_agent_hostname:
        row.hostname = x_agent_hostname
    if x_agent_version:
        row.agent_version = x_agent_version
    if x_agent_detected_role in ("Member Server", "Domain Controller"):
        row.detected_role = x_agent_detected_role
    if x_agent_ip_addresses:
        row.ip_addresses = [
            item.strip()
            for item in x_agent_ip_addresses.split(",")
            if item.strip()
        ]
    if x_agent_os_name:
        row.os_name = x_agent_os_name
    if x_agent_os_version:
        row.os_version = x_agent_os_version
    if x_agent_os_build:
        row.os_build = x_agent_os_build
    if x_agent_os_release:
        row.os_release = x_agent_os_release
    if x_agent_os_family:
        row.os_family = x_agent_os_family
    db.commit()
    return row.agent_id


@router.get("/scanner-package/latest")
def scanner_package_latest(agent_id: str = Depends(get_agent_id)):
    data, version, sha256 = _build_scanner_package()
    return {
        "version": version,
        "sha256": sha256,
        "size": len(data),
        "download_url": f"/agent/scanner-package/download?version={version}",
    }


@router.get("/scanner-package/download")
def scanner_package_download(
    version: str = "",
    agent_id: str = Depends(get_agent_id),
):
    data, current_version, sha256 = _build_scanner_package()
    if version and version != current_version:
        raise HTTPException(status_code=404, detail="Scanner package version not found")
    return StreamingResponse(
        io.BytesIO(data),
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=scanner-{current_version}.zip",
            "Content-Length": str(len(data)),
            "X-Scanner-Package-Version": current_version,
            "X-Scanner-Package-SHA256": sha256,
        },
    )


# ── Agent: ดึง job ที่รอ ────────────────────────────────────────────
@router.get("/jobs/pending")
def pending_jobs(
    agent_id: str = Depends(get_agent_id),
    db: Session = Depends(get_db),
):
    now = datetime.datetime.now()
    stale_cutoff = now - datetime.timedelta(seconds=AGENT_JOB_RUNNING_TIMEOUT_SECONDS)
    stale_rows = (
        db.query(AgentJob)
        .filter(
            AgentJob.agent_id == agent_id,
            AgentJob.status == "running",
            AgentJob.picked_at != None,
            AgentJob.picked_at < stale_cutoff,
        )
        .all()
    )
    for row in stale_rows:
        attempts = row.attempts or 0
        if attempts < AGENT_JOB_MAX_ATTEMPTS:
            row.status = "pending"
            row.picked_at = None
            row.error = f"Retrying after agent timeout (attempt {attempts}/{AGENT_JOB_MAX_ATTEMPTS})"
            row.updated_at = now
            _sync_memory_job(row, "Retrying agent job after timeout...")
        else:
            row.status = "error"
            row.error = f"Agent job timeout after {attempts} attempt(s)"
            row.completed_at = now
            row.updated_at = now
            agent = db.query(AgentToken).filter(AgentToken.agent_id == row.agent_id).first()
            if agent:
                agent.last_error = row.error
                agent.last_error_at = now
            _sync_memory_job(row)

    rows = (
        db.query(AgentJob)
        .filter(AgentJob.agent_id == agent_id, AgentJob.status == "pending")
        .order_by(AgentJob.created_at.asc())
        .all()
    )
    jobs = []
    for row in rows:
        row.status = "running"
        row.picked_at = now
        row.attempts = (row.attempts or 0) + 1
        row.error = ""
        row.updated_at = now
        _sync_memory_job(row, f"Agent picked up job (attempt {row.attempts})")
        payload = row.payload or {}
        jobs.append({
            "job_id": row.job_id,
            "version": row.version,
            "baseline_path": row.baseline_path,
            **payload,
        })
    db.commit()
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
    db: Session = SessionLocal()
    db_job = db.query(AgentJob).filter(
        AgentJob.job_id == job_id,
        AgentJob.agent_id == agent_id,
    ).first()
    job = _jobs.get(job_id)
    if not db_job and not job:
        db.close()
        raise HTTPException(status_code=404, detail="job not found")

    if db_job and db_job.status in ("done", "error") and db_job.completed_at:
        db.close()
        return {"ok": True}

    version = (db_job.version if db_job else None) or getattr(job, "version", "")
    configured_role = (db_job.role if db_job else None) or getattr(job, "role", "")
    user_id = (db_job.user_id if db_job else None) or getattr(job, "user_id", None)
    parent_scan_id = (db_job.parent_scan_id if db_job else None) or getattr(job, "parent_scan_id", None)
    payload = (db_job.payload if db_job else {}) or {}
    job_type = payload.get("job_type", "scan")
    baseline_match_type = payload.get("baseline_match_type", getattr(job, "baseline_match_type", ""))
    baseline_warning = payload.get("baseline_warning", getattr(job, "baseline_warning", ""))

    if body.error:
        if job:
            job.status = "error"
            job.error  = body.error
        if db_job:
            db_job.status = "error"
            db_job.error = body.error
            db_job.completed_at = datetime.datetime.now()
            db_job.updated_at = db_job.completed_at
            db_job.result = {
                "job_id": body.job_id,
                "score": body.score,
                "details": body.details,
                "error": body.error,
            }
        try:
            agent = db.query(AgentToken).filter(AgentToken.agent_id == agent_id).first()
            if agent:
                agent.last_error = body.error
                agent.last_error_at = datetime.datetime.now()
            db.commit()
        finally:
            db.close()
    elif job_type in ("autofix", "rollback"):
        now = datetime.datetime.now()
        details = body.details or {}
        result_payload = {
            "job_id": body.job_id,
            "job_type": job_type,
            "scan_id": payload.get("scan_id"),
            "agent_id": agent_id,
            "requested_by": payload.get("requested_by") or user_id,
            "created_at": db_job.created_at.isoformat() if db_job and db_job.created_at else "",
            "completed_at": now.isoformat(),
            "details": details,
            "autofix_results": details.get("autofix_results", []),
        }
        if job:
            job.status = "done"
            job.progress = 100
            job.message = f"{job_type} done"
            job.result = result_payload
        try:
            agent = db.query(AgentToken).filter(AgentToken.agent_id == agent_id).first()
            if agent:
                agent.last_error = ""
                agent.last_error_at = None
            if db_job:
                db_job.status = "done"
                db_job.result = result_payload
                db_job.error = ""
                db_job.completed_at = now
                db_job.updated_at = db_job.completed_at
            log_activity(
                db,
                action=f"{job_type}_completed",
                target_type="scan",
                target_id=payload.get("scan_id") or "",
                detail={
                    "job_id": body.job_id,
                    "agent_id": agent_id,
                    "result_count": len(details.get("autofix_results", [])),
                },
            )
            db.commit()
        finally:
            db.close()
    else:
        from app.core.baseline_metadata import enrich_scan_details, resolve_scan_role, summarize_findings

        role = resolve_scan_role(body.details, configured_role=configured_role)
        findings        = enrich_scan_details(body.details, version=version, role=role)
        finding_summary = summarize_findings(findings)
        compliance_score, score_breakdown = _calculate_compliance_score(body.details)
        final_score = compliance_score if score_breakdown else body.score
        stored_details = dict(body.details or {})
        if score_breakdown and "_score_breakdown" not in stored_details:
            stored_details["_score_breakdown"] = score_breakdown

        result_payload = {
            "score":         final_score,
            "details":       stored_details,
            "findings":      findings,
            "summary":       finding_summary,
            "items_scanned": _items_scanned(stored_details),
            "score_breakdown": score_breakdown,
            "version":       version,
            "baseline_match_type": baseline_match_type,
            "baseline_warning": baseline_warning,
            "target_name":   agent_id,
            "agent_id":      agent_id,
            "detected_role":  role,
        }
        if job:
            job.status   = "done"
            job.progress = 100
            job.message  = "done"
            job.result   = result_payload

        try:
            agent = db.query(AgentToken).filter(AgentToken.agent_id == agent_id).first()
            hostname = agent.hostname if agent and agent.hostname else agent_id
            if agent:
                agent.last_error = ""
                agent.last_error_at = None
                agent.detected_role = role
            scan_record = ScanResult(
                target_name = f"{hostname} ({version})" if version else hostname,
                score       = final_score,
                details     = stored_details,
                scan_date   = datetime.datetime.now(),
                hostname    = hostname,
                version     = version,
                user_id     = user_id,
                scan_type   = "single",
                parent_scan_id = parent_scan_id,
            )
            db.add(scan_record)
            db.commit()
            db.refresh(scan_record)
            result_payload["scan_id"] = scan_record.id
            result_payload["hostname"] = hostname
            if db_job:
                db_job.status = "done"
                db_job.result = result_payload
                db_job.error = ""
                db_job.completed_at = datetime.datetime.now()
                db_job.updated_at = db_job.completed_at
                db.commit()
            if job:
                job.result = result_payload
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
            ip_addresses = [],
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
            "ip_addresses": r.ip_addresses or [],
            "agent_version": r.agent_version or "",
            "os_name": r.os_name or "",
            "os_version": r.os_version or "",
            "os_build": r.os_build or "",
            "os_release": r.os_release or "",
            "os_family": r.os_family or "",
            "detected_role": r.detected_role or "",
            "last_error": r.last_error or "",
            "last_error_at": r.last_error_at.isoformat() if r.last_error_at else None,
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
    # เก็บ version ไว้ใน job ด้วย
    job = _jobs.get(job_id)
    if job:
        job.version = version


def enqueue(agent_id: str, job_id: str, version: str, baseline_path: str):
    job = _jobs.get(job_id)
    role = getattr(job, "role", "Member Server") if job else "Member Server"
    user_id = getattr(job, "user_id", None) if job else None
    parent_scan_id = getattr(job, "parent_scan_id", None) if job else None
    payload = {
        "job_id": job_id,
        "version": version,
        "baseline_path": baseline_path,
        "role": role,
        "baseline_match_type": getattr(job, "baseline_match_type", "") if job else "",
        "baseline_warning": getattr(job, "baseline_warning", "") if job else "",
    }

    db = SessionLocal()
    try:
        now = datetime.datetime.now()
        row = db.query(AgentJob).filter(AgentJob.job_id == job_id).first()
        if row:
            row.agent_id = agent_id
            row.status = "pending"
            row.version = version
            row.role = role
            row.baseline_path = baseline_path
            row.payload = payload
            row.error = ""
            row.result = None
            row.attempts = 0
            row.picked_at = None
            row.completed_at = None
            row.updated_at = now
        else:
            db.add(AgentJob(
                job_id=job_id,
                agent_id=agent_id,
                status="pending",
                version=version,
                role=role,
                baseline_path=baseline_path,
                payload=payload,
                attempts=0,
                user_id=user_id,
                parent_scan_id=parent_scan_id,
                created_at=now,
                updated_at=now,
            ))
        db.commit()
    finally:
        db.close()

    if job:
        job.version = version
        job.role = role
