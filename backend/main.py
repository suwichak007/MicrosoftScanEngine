"""
main.py  (updated — config-driven multi-OS support via JSON baselines)

เปลี่ยนหลักๆ:
  - ถอดการโหลดและแกะไฟล์ Excel/XLSX ตัวเก่าออกทั้งหมด
  - ใช้ load_checks() และ list_available_versions() เพื่อดึงข้อมูลตรงจาก JSON แทน
  - ปรับปรุง _run_scan_job ให้ส่งฟังก์ชัน checks เข้า run_baseline_scan()
  - ปรับปรุงทุก Endpoint (/run, /remote, /versions, /agent) ให้รองรับโครงสร้างใหม่
"""

import os
import uuid
import datetime
import asyncio
import time
import ipaddress
import re

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
ENV_PATH = os.path.join(ROOT_DIR, ".env")
if load_dotenv:
    load_dotenv(ENV_PATH)

if os.path.exists(ENV_PATH):
    with open(ENV_PATH, "r", encoding="utf-8-sig") as env_file:
        for raw_line in env_file:
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, value = line.split("=", 1)
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))

from fastapi import FastAPI, Depends, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import func, text

from app.core.database import SessionLocal, Base, engine
from app.models.user import User
from app.models.scan import ScanResult
from app.models.agent_job import AgentJob
from app.models.scan_schedule import ScanSchedule
from app.schemas.user import UserCreate, UserResponse
from app.schemas.scan import ScanResultResponse
from app.core.security import get_password_hash, verify_password, create_access_token
from app.core.config import AUTH_PROVIDER
from app.core.ldap_auth import authenticate_ldap
from app.core.scan.scanner.security_scanner import SecurityScanner as SecurityBaselineScanner
from app.core.scan.scanner.baseline_config import (
    load_checks,               # ← ใหม่: load checks จาก JSON
    list_available_versions,   # ← ใหม่: list จาก JSON files
)
from app.core.scan.scanner.executors.remote_executor import RemoteExecutor
from fastapi.concurrency import run_in_threadpool

from app.core.security import get_current_user
from app.core.summary_route import router as summary_router
from app.core.installer_routes import router as installer_router
from app.core.agent_routes import router as agent_router, enqueue
from app.models.agent import AgentToken
from app.core.job_store import _jobs
from app.core.export_routes import router as export_router
from app.core.admin_routes import compute_next_run, router as admin_router
from app.core.baseline_metadata import enrich_scan_details, summarize_findings

Base.metadata.create_all(bind=engine)

def _ensure_agent_inventory_columns():
    if engine.dialect.name != "sqlite":
        return
    with engine.begin() as conn:
        existing = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(agent_tokens)")).fetchall()
        }
        if "ip_addresses" not in existing:
            conn.execute(text("ALTER TABLE agent_tokens ADD COLUMN ip_addresses JSON"))
        if "agent_version" not in existing:
            conn.execute(text("ALTER TABLE agent_tokens ADD COLUMN agent_version VARCHAR"))
        for col in ["os_name", "os_version", "os_build", "os_release", "os_family"]:
            if col not in existing:
                conn.execute(text(f"ALTER TABLE agent_tokens ADD COLUMN {col} VARCHAR"))
        if "last_error" not in existing:
            conn.execute(text("ALTER TABLE agent_tokens ADD COLUMN last_error VARCHAR"))
        if "last_error_at" not in existing:
            conn.execute(text("ALTER TABLE agent_tokens ADD COLUMN last_error_at DATETIME"))

        agent_job_columns = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(agent_jobs)")).fetchall()
        }
        if "attempts" not in agent_job_columns:
            conn.execute(text("ALTER TABLE agent_jobs ADD COLUMN attempts INTEGER DEFAULT 0"))

        schedule_columns = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(scan_schedules)")).fetchall()
        }
        if schedule_columns:
            expected_schedule_columns = {
                "name": "VARCHAR",
                "scan_type": "VARCHAR",
                "agent_id": "VARCHAR",
                "subnet": "VARCHAR",
                "version": "VARCHAR",
                "role": "VARCHAR",
                "frequency": "VARCHAR",
                "time": "VARCHAR",
                "day_of_week": "INTEGER",
                "enabled": "BOOLEAN DEFAULT 1",
                "user_id": "INTEGER",
                "last_run": "DATETIME",
                "next_run": "DATETIME",
                "last_job_id": "VARCHAR",
                "last_error": "VARCHAR",
                "created_at": "DATETIME",
                "updated_at": "DATETIME",
            }
            for col, ddl in expected_schedule_columns.items():
                if col not in schedule_columns:
                    conn.execute(text(f"ALTER TABLE scan_schedules ADD COLUMN {col} {ddl}"))

        scan_result_columns = {
            row[1]
            for row in conn.execute(text("PRAGMA table_info(scan_results)")).fetchall()
        }
        if "version" not in scan_result_columns:
            conn.execute(text("ALTER TABLE scan_results ADD COLUMN version VARCHAR"))
        if "hostname" not in scan_result_columns:
            conn.execute(text("ALTER TABLE scan_results ADD COLUMN hostname VARCHAR"))
        if "scan_type" not in scan_result_columns:
            conn.execute(text("ALTER TABLE scan_results ADD COLUMN scan_type VARCHAR DEFAULT 'single'"))
        if "parent_scan_id" not in scan_result_columns:
            conn.execute(text("ALTER TABLE scan_results ADD COLUMN parent_scan_id INTEGER"))

_ensure_agent_inventory_columns()


def _ensure_owner_user():
    db = SessionLocal()
    try:
        owner = db.query(User).filter(User.username == "Boat").first()
        if owner and owner.role != "owner":
            owner.role = "owner"
            owner.is_active = True
            db.commit()
            print("[startup] Promoted Boat to owner")
    finally:
        db.close()


_ensure_owner_user()

app = FastAPI()


def _has_admin_access(user: User) -> bool:
    return user.role in ("admin", "owner")

app.include_router(installer_router)
app.include_router(agent_router)
app.include_router(export_router)
app.include_router(admin_router)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(summary_router)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DATA_PATH = os.environ.get(
    "DATA_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
)
SCAN_TIMEOUT_SECONDS = int(os.environ.get("SCAN_TIMEOUT_SECONDS", "600"))
SUBNET_DISCOVERY_TIMEOUT_SECONDS = float(os.environ.get("SUBNET_DISCOVERY_TIMEOUT_MS", "800")) / 1000
SUBNET_DISCOVERY_PARALLEL = int(os.environ.get("SUBNET_DISCOVERY_PARALLEL", "100"))
AGENT_JOB_RUNNING_TIMEOUT_SECONDS = int(os.environ.get("AGENT_JOB_RUNNING_TIMEOUT_SECONDS", "900"))
AGENT_JOB_MAX_ATTEMPTS = int(os.environ.get("AGENT_JOB_MAX_ATTEMPTS", "2"))

@app.on_event("startup")
async def startup_event():
    """ตรวจสอบหรือแสดงผลระบบจัดเก็บ Baseline แบบใหม่ตอนเริ่มต้นระบบ"""
    try:
        versions = list_available_versions()
        print(f"[startup] Available JSON baselines detected: {versions}")
    except Exception as e:
        print(f"[startup] Warning during baseline detection: {str(e)}")
    asyncio.create_task(_schedule_loop())


# ---------------------------------------------------------------------------
# In-memory Job Store
# ---------------------------------------------------------------------------

class ScanJob:
    def __init__(self):
        self.status   = "pending"
        self.progress = 0
        self.message  = ""
        self.result   = None
        self.error    = ""

def _new_job() -> tuple[str, ScanJob]:
    job_id        = str(uuid.uuid4())
    job           = ScanJob()
    _jobs[job_id] = job
    return job_id, job


def _sync_memory_agent_job(db_job: AgentJob):
    job = _jobs.get(db_job.job_id)
    if not job:
        return
    job.status = db_job.status
    if db_job.status == "pending":
        job.progress = min(job.progress or 0, 10)
        job.message = "Waiting for agent retry..."
    elif db_job.status == "running":
        job.progress = max(job.progress or 0, 10)
    elif db_job.status == "error":
        job.progress = 100
        job.error = db_job.error or "Agent job failed"
    elif db_job.status == "done":
        job.progress = 100
        job.message = "done"
        job.result = db_job.result


def _recover_stale_agent_jobs(db: Session):
    now = datetime.datetime.now()
    cutoff = now - datetime.timedelta(seconds=AGENT_JOB_RUNNING_TIMEOUT_SECONDS)
    stale_jobs = (
        db.query(AgentJob)
        .filter(
            AgentJob.status == "running",
            AgentJob.picked_at != None,
            AgentJob.picked_at < cutoff,
        )
        .all()
    )
    changed = False
    for db_job in stale_jobs:
        attempts = db_job.attempts or 0
        if attempts < AGENT_JOB_MAX_ATTEMPTS:
            db_job.status = "pending"
            db_job.picked_at = None
            db_job.error = f"Retrying after agent timeout (attempt {attempts}/{AGENT_JOB_MAX_ATTEMPTS})"
        else:
            db_job.status = "error"
            db_job.error = f"Agent job timeout after {attempts} attempt(s)"
            db_job.completed_at = now
            agent = db.query(AgentToken).filter(AgentToken.agent_id == db_job.agent_id).first()
            if agent:
                agent.last_error = db_job.error
                agent.last_error_at = now
        db_job.updated_at = now
        _sync_memory_agent_job(db_job)
        changed = True
    if changed:
        db.commit()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RemoteScanRequest(BaseModel):
    host:          str  = Field(...,   example="192.168.1.50")
    username:      str  = Field(...,   example=".\\Administrator")
    password:      str  = Field(...,   example="P@ssw0rd")
    version:       str  = Field("Windows 11 v24H2")
    role:          str  = Field("Member Server")   
    use_ssl:       bool = Field(False)
    skip_ca_check: bool = Field(True)
    target_name:   str  = Field("")

class LocalScanRequest(BaseModel):
    version: str = Field("Windows 11 v24H2")

class AgentScanRequest(BaseModel):
    agent_id: str = Field(..., example="agent-WORKSTATION01")
    version:   str = Field("auto")
    role:      str = Field("Member Server")

class AgentSubnetScanRequest(BaseModel):
    subnet:  str = Field(..., example="192.168.1.0/24")
    version: str = Field("auto")
    role:    str = Field("Member Server")

class ConnectionTestRequest(BaseModel):
    host:          str
    username:      str
    password:      str
    use_ssl:       bool = False
    skip_ca_check: bool = True

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password:     str


class SubnetScanRequest(BaseModel):
    subnet:        str  = Field(..., example="192.168.1.0/24")
    username:      str  = Field(..., example=".\\Administrator")
    password:      str  = Field(..., example="P@ssw0rd")
    version:       str  = Field("Windows Server 2025 v2602 (MS Security Baseline)")
    role:          str  = Field("Member Server")
    use_ssl:       bool = Field(False)
    skip_ca_check: bool = Field(True)
    max_parallel:  int  = Field(10)  # สแกนพร้อมกันสูงสุด 10 เครื่อง


# ---------------------------------------------------------------------------
# DB Dependency
# ---------------------------------------------------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _build_registry_prefetch_keys(checks: list[dict]) -> list[tuple[str, str, str]]:
    registry_keys = []
    seen = set()

    for check in checks:
        registry_path = check.get("registry_path", "")
        if not registry_path:
            continue

        if "!" in registry_path:
            path_part, key_name = registry_path.split("!", 1)
        else:
            last_slash = registry_path.rfind("\\")
            if last_slash == -1:
                continue
            path_part = registry_path[:last_slash]
            key_name = registry_path[last_slash + 1:]

        path_upper = path_part.upper()
        if path_upper.startswith("HKLM\\") or path_upper.startswith("HKEY_LOCAL_MACHINE\\"):
            import re as _re
            sub_path = _re.sub(r"^(HKEY_LOCAL_MACHINE|HKLM)\\", "", path_part, flags=_re.IGNORECASE)
            key = ("HKLM", sub_path, key_name)
        elif path_upper.startswith("HKCU\\") or path_upper.startswith("HKEY_CURRENT_USER\\"):
            import re as _re
            sub_path = _re.sub(r"^(HKEY_CURRENT_USER|HKCU)\\", "", path_part, flags=_re.IGNORECASE)
            key = ("HKCU", sub_path, key_name)
        elif path_upper.startswith("MACHINE\\"):
            import re as _re
            sub_path = _re.sub(r"^MACHINE\\", "", path_part, flags=_re.IGNORECASE)
            key = ("HKLM", sub_path, key_name)
        elif path_upper.startswith("SOFTWARE\\"):
            key = ("HKLM", path_part, key_name)
        else:
            continue

        if key not in seen:
            seen.add(key)
            registry_keys.append(key)

    return registry_keys


def _scan_counts_from_details(details: dict | None) -> dict:
    counts = {
        "items_scanned": 0,
        "pass_count": 0,
        "fail_count": 0,
        "manual_count": 0,
        "critical_count": 0,
        "high_count": 0,
    }
    if not isinstance(details, dict):
        return counts
    for key, value in details.items():
        if str(key).startswith("_"):
            continue
        if not isinstance(value, dict):
            status = str(value)
            severity = ""
        else:
            status = str(value.get("status", ""))
            severity = str(value.get("severity", "")).lower()
        if not status:
            continue
        counts["items_scanned"] += 1
        status_lower = status.lower()
        if status_lower.startswith("pass"):
            counts["pass_count"] += 1
        elif status_lower.startswith("fail"):
            counts["fail_count"] += 1
            if severity == "critical":
                counts["critical_count"] += 1
            if severity == "high":
                counts["high_count"] += 1
        elif "manual" in status_lower:
            counts["manual_count"] += 1
    return counts


def _score_breakdown_from_details(details: dict | None) -> dict | None:
    if not isinstance(details, dict):
        return None


def _aggregate_score_breakdowns(results: list[dict]) -> tuple[int, dict | None]:
    weights = {"critical": 10, "high": 7, "medium": 4, "low": 1}
    passed_weight = assessed_weight = excluded_manual = 0
    severity_totals = {key: 0 for key in weights}
    severity_failed = {key: 0 for key in weights}
    for row in results:
        breakdown = row.get("score_breakdown") if isinstance(row, dict) else None
        if not isinstance(breakdown, dict) or breakdown.get("model") != "nist_cis_informed_v1":
            continue
        passed_weight += int(breakdown.get("passed_weight", 0) or 0)
        assessed_weight += int(breakdown.get("assessed_weight", 0) or 0)
        excluded_manual += int(breakdown.get("excluded_manual_count", 0) or 0)
        for sev in weights:
            severity_totals[sev] += int((breakdown.get("severity_totals") or {}).get(sev, 0))
            severity_failed[sev] += int((breakdown.get("severity_failed") or {}).get(sev, 0))

    if assessed_weight <= 0:
        return 0, None
    score = int((passed_weight / assessed_weight) * 100)
    return score, {
        "model": "nist_cis_informed_v1",
        "passed_weight": passed_weight,
        "assessed_weight": assessed_weight,
        "excluded_manual_count": excluded_manual,
        "severity_weights": weights,
        "severity_totals": severity_totals,
        "severity_failed": severity_failed,
    }
    breakdown = details.get("_score_breakdown")
    if not isinstance(breakdown, dict):
        return None
    if breakdown.get("model") != "nist_cis_informed_v1":
        return None
    try:
        return {
            **breakdown,
            "passed_weight": int(breakdown.get("passed_weight", 0)),
            "assessed_weight": int(breakdown.get("assessed_weight", 0)),
            "excluded_manual_count": int(breakdown.get("excluded_manual_count", 0)),
        }
    except Exception:
        return None


def _subnet_summary_from_details(details):
    if not isinstance(details, dict):
        return None
    results = details.get("results")
    if not isinstance(results, list):
        return None
    success_count = sum(1 for r in results if isinstance(r, dict) and r.get("status") == "done")
    failed_count = sum(1 for r in results if isinstance(r, dict) and r.get("status") == "error")
    return {
        "items_scanned": success_count,
        "pass_count": success_count,
        "fail_count": failed_count,
        "host_count": len(results),
        "failed_host_count": failed_count,
        "critical_count": 0,
        "high_count": 0,
        "score_breakdown": details.get("score_breakdown") if isinstance(details.get("score_breakdown"), dict) else None,
    }


def _subnet_summary_from_children(parent: ScanResult, db: Session, current_user: User) -> dict:
    query = db.query(ScanResult).filter(ScanResult.parent_scan_id == parent.id)
    if not _has_admin_access(current_user):
        query = query.filter(ScanResult.user_id == current_user.id)
    children = query.all()
    if not children:
        return _subnet_summary_from_details(parent.details) or {
            "items_scanned": 0,
            "pass_count": 0,
            "fail_count": 0,
            "host_count": 0,
            "failed_host_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "score": parent.score or 0,
        }

    host_count = len(children)
    failed_host_count = 0
    pass_count = fail_count = critical_count = high_count = 0
    score_total = 0
    scored = 0
    aggregate_passed_weight = 0
    aggregate_assessed_weight = 0
    aggregate_manual_excluded = 0
    aggregate_severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    aggregate_severity_failed = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for child in children:
        counts = _scan_counts_from_details(child.details)
        pass_count += counts["pass_count"]
        fail_count += counts["fail_count"]
        critical_count += counts["critical_count"]
        high_count += counts["high_count"]
        breakdown = _score_breakdown_from_details(child.details)
        if breakdown:
            aggregate_passed_weight += breakdown["passed_weight"]
            aggregate_assessed_weight += breakdown["assessed_weight"]
            aggregate_manual_excluded += breakdown["excluded_manual_count"]
            for sev in aggregate_severity_totals:
                aggregate_severity_totals[sev] += int((breakdown.get("severity_totals") or {}).get(sev, 0))
                aggregate_severity_failed[sev] += int((breakdown.get("severity_failed") or {}).get(sev, 0))
        if counts["fail_count"] > 0 or (child.score or 0) < 100:
            failed_host_count += 1
        if child.score is not None:
            score_total += int(child.score or 0)
            scored += 1

    score = (
        int((aggregate_passed_weight / aggregate_assessed_weight) * 100)
        if aggregate_assessed_weight > 0
        else int(score_total / scored) if scored else (parent.score or 0)
    )

    return {
        "items_scanned": host_count,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "host_count": host_count,
        "failed_host_count": failed_host_count,
        "critical_count": critical_count,
        "high_count": high_count,
        "score": score,
        "score_breakdown": {
            "model": "nist_cis_informed_v1",
            "passed_weight": aggregate_passed_weight,
            "assessed_weight": aggregate_assessed_weight,
            "excluded_manual_count": aggregate_manual_excluded,
            "severity_weights": {"critical": 10, "high": 7, "medium": 4, "low": 1},
            "severity_totals": aggregate_severity_totals,
            "severity_failed": aggregate_severity_failed,
        } if aggregate_assessed_weight > 0 else None,
    }


def _agent_matches_subnet(agent: AgentToken, network) -> bool:
    for ip in agent.ip_addresses or []:
        try:
            if ipaddress.ip_address(ip) in network:
                return True
        except Exception:
            continue
    return False


def _version_release(value: str) -> tuple[int, int] | None:
    match = re.search(r"(\d{2})H([12])", value or "", re.IGNORECASE)
    if not match:
        return None
    return int(match.group(1)), int(match.group(2))


def _latest_baseline(candidates: list[dict]) -> dict | None:
    def key(item: dict):
        text = f"{item.get('version_id', '')} {item.get('display_name', '')}"
        release = _version_release(text)
        if release:
            return (release[0], release[1], 0)
        year = re.search(r"\b(20\d{2})\b", text)
        if year:
            return (int(year.group(1)), 0, 0)
        return (0, 0, 0)

    return max(candidates, key=key) if candidates else None


def _agent_os_payload(agent: AgentToken) -> dict:
    os_name = agent.os_name or ""
    os_release = agent.os_release or ""
    os_build = agent.os_build or ""
    os_family = agent.os_family or ""
    if not os_family:
        text = f"{os_name} {os_release}".lower()
        if "server" in text:
            os_family = "windows_server"
        elif "windows" in text:
            os_family = "windows_client"
    return {
        "os_name": os_name,
        "os_version": agent.os_version or "",
        "os_build": os_build,
        "os_release": os_release,
        "os_family": os_family,
    }


def _resolve_agent_baseline(agent: AgentToken) -> dict:
    os_meta = _agent_os_payload(agent)
    os_name = os_meta["os_name"]
    os_release = os_meta["os_release"]
    os_build = os_meta["os_build"]
    os_family = os_meta["os_family"]
    agent_label = agent.hostname or agent.agent_id

    if not os_name and not os_build and not os_release and not os_family:
        return {
            **os_meta,
            "version": "",
            "match_type": "unresolved",
            "warning": "",
            "error": (
                f"Agent {agent_label} has not reported OS metadata yet. "
                "Rebuild/reinstall or restart the updated agent, then wait for heartbeat."
            ),
        }

    if os_family not in ("windows_client", "windows_server"):
        return {
            **os_meta,
            "version": "",
            "match_type": "unresolved",
            "warning": "",
            "error": f"No suitable baseline for {os_name or 'Unknown OS'} build {os_build or '-'}",
        }

    versions = list_available_versions()
    candidates = [v for v in versions if v.get("os_family") == os_family]
    if not candidates:
        return {
            **os_meta,
            "version": "",
            "match_type": "unresolved",
            "warning": "",
            "error": f"No baseline family {os_family} for {os_name or 'Unknown OS'} build {os_build or '-'}",
        }

    text = f"{os_name} {os_release} {os_build}".lower()
    release = _version_release(os_release) or _version_release(os_name)
    if not release:
        try:
            build_number = int(os_build or "0")
        except ValueError:
            build_number = 0
        if build_number >= 26200:
            release = (25, 2)
        elif build_number >= 26100:
            release = (24, 2)
        elif build_number >= 22631:
            release = (23, 2)

    if os_family == "windows_client":
        is_windows_11 = "windows 11" in text
        try:
            is_windows_11 = is_windows_11 or int(os_build or "0") >= 22000
        except ValueError:
            pass
        if not is_windows_11:
            return {
                **os_meta,
                "version": "",
                "match_type": "unresolved",
                "warning": "",
                "error": f"No suitable baseline for {os_name or 'Unknown OS'} build {os_build or '-'}",
            }

        win11 = [
            v for v in candidates
            if "windows 11" in f"{v.get('version_id', '')} {v.get('display_name', '')}".lower()
        ]
        if release:
            release_text = f"{release[0]}H{release[1]}".lower()
            exact = [
                v for v in win11
                if release_text in f"{v.get('version_id', '')} {v.get('display_name', '')}".lower()
            ]
            if exact:
                chosen = exact[0]
                return {**os_meta, "version": chosen["version_id"], "match_type": "exact", "warning": "", "error": ""}

        chosen = _latest_baseline(win11)
        if chosen:
            return {
                **os_meta,
                "version": chosen["version_id"],
                "match_type": "same_major_fallback",
                "warning": f"Exact baseline not found; using {chosen['display_name']} instead",
                "error": "",
            }

    if os_family == "windows_server":
        server_candidates = [
            v for v in candidates
            if "server" in f"{v.get('version_id', '')} {v.get('display_name', '')}".lower()
        ]
        year = re.search(r"\b(20\d{2})\b", text)
        if year:
            exact = [
                v for v in server_candidates
                if year.group(1) in f"{v.get('version_id', '')} {v.get('display_name', '')}"
            ]
            if exact:
                chosen = exact[0]
                return {**os_meta, "version": chosen["version_id"], "match_type": "exact", "warning": "", "error": ""}

        chosen = _latest_baseline(server_candidates)
        if chosen:
            return {
                **os_meta,
                "version": chosen["version_id"],
                "match_type": "same_major_fallback",
                "warning": f"Exact baseline not found; using {chosen['display_name']} instead",
                "error": "",
            }

    return {
        **os_meta,
        "version": "",
        "match_type": "unresolved",
        "warning": "",
        "error": f"No suitable baseline for {os_name or 'Unknown OS'} build {os_build or '-'}",
    }


def _agent_health(agent: AgentToken, baseline_info: dict, now: datetime.datetime) -> dict:
    online = ((now - agent.last_seen).total_seconds() < 300) if agent.last_seen else False
    has_os_metadata = bool(agent.os_name and agent.os_build and agent.os_family)
    baseline_ready = bool(baseline_info.get("version")) and not baseline_info.get("error")

    if not online:
        status = "offline"
        message = "Agent offline or heartbeat older than 5 minutes"
    elif agent.last_error:
        status = "scan_error"
        message = agent.last_error
    elif not has_os_metadata:
        status = "missing_os_metadata"
        message = "Agent heartbeat is missing OS metadata"
    elif not baseline_ready:
        status = "baseline_unresolved"
        message = baseline_info.get("error") or "No suitable baseline"
    else:
        status = "ready"
        message = baseline_info.get("warning") or "Ready"

    return {
        "online": online,
        "has_os_metadata": has_os_metadata,
        "baseline_ready": baseline_ready,
        "health_status": status,
        "health_message": message,
    }


def _resolve_schedule_role(agent: AgentToken | None, version: str, configured_role: str | None) -> str:
    role = (configured_role or "auto").strip()
    if role and role.lower() != "auto":
        return role

    label = " ".join([
        getattr(agent, "hostname", "") or "",
        getattr(agent, "os_name", "") or "",
        getattr(agent, "os_family", "") or "",
    ]).lower()
    if "domain controller" in label or re.match(r"(^|[-_.])dc\d*($|[-_.])", label):
        return "Domain Controller"

    try:
        dc_checks = load_checks(version, role="Domain Controller")
        member_checks = load_checks(version, role="Member Server")
        if dc_checks and not member_checks:
            return "Domain Controller"
    except Exception:
        pass
    return "Member Server"


def _dispatch_scheduled_agent_scan(db: Session, schedule: ScanSchedule) -> str:
    db_agent = db.query(AgentToken).filter(AgentToken.agent_id == schedule.agent_id).first()
    if not db_agent:
        raise ValueError(f"agent not found: {schedule.agent_id}")

    if (schedule.version or "auto").lower() == "auto":
        baseline_info = _resolve_agent_baseline(db_agent)
        if baseline_info.get("error"):
            raise ValueError(baseline_info["error"])
        resolved_version = baseline_info["version"]
    else:
        resolved_version = schedule.version or "auto"
        baseline_info = {
            **_agent_os_payload(db_agent),
            "version": resolved_version,
            "match_type": "manual",
            "warning": "",
            "error": "",
        }

    baseline_path = os.path.join(ROOT_DIR, "baselines", "generated", f"{resolved_version}.json")
    job_id, job = _new_job()
    job.status = "running"
    job.message = f"Scheduled scan: {schedule.name}"
    job.user_id = schedule.user_id
    job.role = _resolve_schedule_role(db_agent, resolved_version, "auto")
    job.target_agent_id = schedule.agent_id
    job.baseline_match_type = baseline_info.get("match_type", "")
    job.baseline_warning = baseline_info.get("warning", "")
    enqueue(schedule.agent_id, job_id, resolved_version, baseline_path)
    return job_id


def _prepare_scheduled_agent_subnet_scan(db: Session, schedule: ScanSchedule) -> tuple[str, int, AgentSubnetScanRequest, list[dict], list[dict]]:
    try:
        network = ipaddress.ip_network(schedule.subnet or "", strict=False)
    except ValueError:
        raise ValueError(f"invalid subnet: {schedule.subnet}")

    now = datetime.datetime.now()
    matched = []
    for a in db.query(AgentToken).all():
        if not _agent_matches_subnet(a, network):
            continue
        if (schedule.version or "auto").lower() == "auto":
            baseline_info = _resolve_agent_baseline(a)
        else:
            baseline_info = {
                **_agent_os_payload(a),
                "version": schedule.version,
                "match_type": "manual",
                "warning": "",
                "error": "",
            }
        matched.append({
            "agent_id": a.agent_id,
            "hostname": a.hostname or a.agent_id,
            "ip_addresses": a.ip_addresses or [],
            "last_seen": a.last_seen,
            "online": ((now - a.last_seen).total_seconds() < 300) if a.last_seen else False,
            "baseline_info": baseline_info,
        })

    req = AgentSubnetScanRequest(
        subnet=schedule.subnet or "",
        version=schedule.version or "auto",
        role="auto",
    )
    parent = ScanResult(
        target_name=f"{req.subnet} ({req.version})",
        score=0,
        details={},
        scan_date=now,
        version=req.version,
        hostname=req.subnet,
        user_id=schedule.user_id,
        scan_type="subnet",
    )
    db.add(parent)
    db.commit()
    db.refresh(parent)

    unresolved_results = [
        {
            "host": agent["hostname"],
            "hostname": agent["hostname"],
            "agent_id": agent["agent_id"],
            "ip_addresses": agent["ip_addresses"],
            "score": 0,
            "status": "error",
            "phase": "baseline_resolve",
            "method": "agent",
            "version": "",
            "baseline_match_type": "unresolved",
            "error": agent["baseline_info"].get("error") or "No suitable baseline",
        }
        for agent in matched
        if agent["baseline_info"].get("error")
    ]
    offline_results = [
        {
            "host": agent["hostname"],
            "hostname": agent["hostname"],
            "agent_id": agent["agent_id"],
            "ip_addresses": agent["ip_addresses"],
            "score": 0,
            "status": "error",
            "phase": "agent_offline",
            "method": "agent",
            "version": agent["baseline_info"].get("version", ""),
            "baseline_match_type": agent["baseline_info"].get("match_type", ""),
            "error": "Agent offline or heartbeat older than 5 minutes",
        }
        for agent in matched
        if not agent["online"] and not agent["baseline_info"].get("error")
    ]
    online_agents = [
        a for a in matched
        if a["online"] and not a["baseline_info"].get("error")
    ]

    job_id, job = _new_job()
    job.message = f"Scheduled agent subnet scan: {schedule.name}"
    asyncio.create_task(
        _run_agent_subnet_scan_job(
            parent_job=job,
            parent_scan_id=parent.id,
            req=req,
            user_id=schedule.user_id,
            online_agents=online_agents,
            offline_results=unresolved_results + offline_results,
        )
    )
    return job_id, parent.id, req, online_agents, unresolved_results + offline_results


def _run_due_schedules_once():
    db = SessionLocal()
    try:
        now = datetime.datetime.now()
        due = (
            db.query(ScanSchedule)
            .filter(
                ScanSchedule.enabled == True,
                ScanSchedule.next_run != None,
                ScanSchedule.next_run <= now,
            )
            .all()
        )
        for schedule in due:
            schedule.last_run = now
            try:
                if schedule.scan_type == "agent":
                    job_id = _dispatch_scheduled_agent_scan(db, schedule)
                elif schedule.scan_type == "agent-subnet":
                    job_id, _parent_id, _req, _online, _offline = _prepare_scheduled_agent_subnet_scan(db, schedule)
                else:
                    raise ValueError(f"unsupported scan_type: {schedule.scan_type}")
                schedule.last_job_id = job_id
                schedule.last_error = ""
            except Exception as e:
                schedule.last_error = str(e)
                print(f"[scheduler] schedule {schedule.id} failed: {e}")
            schedule.next_run = compute_next_run(
                schedule.frequency or "daily",
                schedule.time,
                schedule.day_of_week,
                now + datetime.timedelta(seconds=1),
            )
            schedule.updated_at = now
        if due:
            db.commit()
    finally:
        db.close()


async def _schedule_loop():
    await asyncio.sleep(3)
    while True:
        try:
            _run_due_schedules_once()
        except Exception as e:
            print(f"[scheduler] loop error: {e}")
        await asyncio.sleep(int(os.environ.get("SCAN_SCHEDULER_INTERVAL_SECONDS", "30")))


async def _run_subnet_scan_job(job, hosts, req, user_id):
    import asyncio
    from fastapi.concurrency import run_in_threadpool

    job.status   = "running"
    job.progress = 0
    job.message  = f"กำลัง discover hosts ใน {req.subnet}..."

    # สร้าง parent record ก่อน
    def _save_parent():
        db = SessionLocal()
        try:
            parent = ScanResult(
                target_name = f"{req.subnet} ({req.version})",
                score       = 0,
                details     = {},
                scan_date   = datetime.datetime.now(),
                version     = req.version,
                hostname    = req.subnet,
                user_id     = user_id,
                scan_type   = "subnet",
            )
            db.add(parent)
            db.commit()
            db.refresh(parent)
            return parent.id
        finally:
            db.close()

    parent_id = await run_in_threadpool(_save_parent)

    discovery_port = 5986 if req.use_ssl else 5985
    discovery_parallel = max(1, min(SUBNET_DISCOVERY_PARALLEL, len(hosts)))
    discovery_semaphore = asyncio.Semaphore(discovery_parallel)
    discovered = 0
    live_count = 0
    live_hosts: list[str] = []

    async def probe_host(host: str):
        nonlocal discovered, live_count
        async with discovery_semaphore:
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, discovery_port),
                    timeout=SUBNET_DISCOVERY_TIMEOUT_SECONDS,
                )
                live_count += 1
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return host
            except Exception:
                return None
            finally:
                discovered += 1
                job.progress = min(10, int(discovered / len(hosts) * 10))
                job.message = (
                    f"Discover WinRM {discovered}/{len(hosts)} hosts "
                    f"(เจอ {live_count} เครื่อง)"
                )

    for result in await asyncio.gather(*(probe_host(host) for host in hosts)):
        if result:
            live_hosts.append(result)

    live_host_set = set(live_hosts)
    discovery_failures = [
        {
            "host": host,
            "hostname": "",
            "score": 0,
            "status": "error",
            "phase": "discovery",
            "error": f"WinRM port {discovery_port} ไม่ตอบภายใน {int(SUBNET_DISCOVERY_TIMEOUT_SECONDS * 1000)}ms",
        }
        for host in hosts
        if host not in live_host_set
    ]

    if not live_hosts:
        def _update_parent_empty():
            db = SessionLocal()
            try:
                parent = db.query(ScanResult).filter(ScanResult.id == parent_id).first()
                if parent:
                    parent.score = 0
                    parent.details = {
                        "results": discovery_failures,
                        "subnet": req.subnet,
                        "discovered_hosts": 0,
                    }
                    db.commit()
            finally:
                db.close()

        await run_in_threadpool(_update_parent_empty)
        job.status = "done"
        job.progress = 100
        job.message = f"ไม่พบ host ที่เปิด WinRM port {discovery_port} ใน {req.subnet}"
        job.result = {
            "subnet": req.subnet,
            "total": len(hosts),
            "discovered_hosts": 0,
            "success_count": 0,
            "failed_count": len(discovery_failures),
            "results": discovery_failures,
            "scan_id": parent_id,
        }
        return

    try:
        checks = load_checks(req.version, role=req.role)
    except FileNotFoundError as e:
        job.status = "error"
        job.error = str(e)
        return
    registry_prefetch_keys = _build_registry_prefetch_keys(checks)

    semaphore = asyncio.Semaphore(req.max_parallel)
    done      = 0
    total     = len(live_hosts)
    job.progress = 10
    job.message = f"พบ WinRM {total}/{len(hosts)} hosts กำลังเริ่ม scan..."

    async def scan_one(host: str):
        nonlocal done
        async with semaphore:
            try:
                executor = RemoteExecutor(
                    host=host,
                    username=req.username,
                    password=req.password,
                    use_ssl=req.use_ssl,
                    skip_ca_check=req.skip_ca_check,
                    timeout=15,
                )
                conn = await asyncio.wait_for(
                    run_in_threadpool(executor.test_connection),
                    timeout=15,
                )
                if not conn["success"]:
                    done += 1
                    job.progress = 10 + int(done / total * 90)
                    return {
                        "host": host,
                        "hostname": conn.get("hostname") or "",
                        "score": 0,
                        "status": "error",
                        "phase": "connection",
                        "error": conn.get("message") or "WinRM connection test failed",
                    }

                hostname = conn.get("hostname") or host
                if registry_prefetch_keys and hasattr(executor, "prefetch_registry_bulk"):
                    batch_size = 100
                    for index in range(0, len(registry_prefetch_keys), batch_size):
                        batch = registry_prefetch_keys[index:index + batch_size]
                        try:
                            await asyncio.wait_for(
                                run_in_threadpool(executor.prefetch_registry_bulk, batch),
                                timeout=getattr(executor, "_REGISTRY_PREFETCH_TIMEOUT", 25),
                            )
                        except Exception as e:
                            print(f"[subnet-prefetch] {host} registry prefetch skipped: {type(e).__name__}: {e}")
                            break

                scanner  = SecurityBaselineScanner(executor=executor, role=req.role)
                score, details = await asyncio.wait_for(
                    run_in_threadpool(scanner.run_baseline_scan, checks),
                    timeout=SCAN_TIMEOUT_SECONDS,
                )

                findings        = enrich_scan_details(details, version=req.version, role=req.role)
                finding_summary = summarize_findings(findings)

                def _save():
                    db = SessionLocal()
                    try:
                        new_scan = ScanResult(
                            target_name    = f"{hostname} ({req.version})",
                            score          = score,
                            details        = details,
                            scan_date      = datetime.datetime.now(),
                            version        = req.version,
                            hostname       = hostname,
                            user_id        = user_id,
                            scan_type      = "single",
                            parent_scan_id = parent_id,
                        )
                        db.add(new_scan)
                        db.commit()
                        db.refresh(new_scan)
                        return new_scan.id
                    finally:
                        db.close()

                scan_id = await run_in_threadpool(_save)
                done += 1
                job.progress = 10 + int(done / total * 90)
                job.message  = f"สแกนแล้ว {done}/{total} hosts"

                return {
                    "host": host, "hostname": hostname,
                    "score": score, "scan_id": scan_id, "status": "done",
                    "score_breakdown": _score_breakdown_from_details(details),
                }

            except Exception as e:
                done += 1
                job.progress = 10 + int(done / total * 90)
                return {"host": host, "score": 0, "status": "error", "error": str(e)}

    tasks   = [scan_one(h) for h in live_hosts]
    scanned = await asyncio.gather(*tasks)
    results = discovery_failures + [r for r in scanned if r is not None]

    success = [r for r in results if r["status"] == "done"]
    failed  = [r for r in results if r["status"] == "error"]

    aggregate_score, aggregate_breakdown = _aggregate_score_breakdowns(success)
    avg_score = aggregate_score if aggregate_breakdown else int(sum(r["score"] for r in success) / len(success)) if success else 0

    def _update_parent():
        db = SessionLocal()
        try:
            parent = db.query(ScanResult).filter(ScanResult.id == parent_id).first()
            if parent:
                parent.score   = avg_score
                parent.details = {
                    "results": results,
                    "subnet": req.subnet,
                    "discovered_hosts": total,
                    "score_breakdown": aggregate_breakdown,
                }
                db.commit()
        finally:
            db.close()

    await run_in_threadpool(_update_parent)

    job.status   = "done"
    job.progress = 100
    job.message  = f"เสร็จสิ้น: สำเร็จ {len(success)}, ล้มเหลว {len(failed)}"
    job.result   = {
        "subnet":        req.subnet,
        "total":         len(hosts),
        "discovered_hosts": total,
        "success_count": len(success),
        "failed_count":  len(failed),
        "results":       results,
        "scan_id":       parent_id,
    }

@app.get("/api/scan/history/{scan_id}/children")
async def get_subnet_children(
    scan_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    parent_query = db.query(ScanResult).filter(ScanResult.id == scan_id)
    if not _has_admin_access(current_user):
        parent_query = parent_query.filter(ScanResult.user_id == current_user.id)
    parent = parent_query.first()
    if not parent:
        raise HTTPException(status_code=404, detail="ไม่พบ subnet scan นี้หรือไม่มีสิทธิ์เข้าถึง")

    query = db.query(ScanResult).filter(ScanResult.parent_scan_id == scan_id)
    if not _has_admin_access(current_user):
        query = query.filter(ScanResult.user_id == current_user.id)
    children = query.order_by(ScanResult.scan_date).all()
    rows = []
    for c in children:
        role = "Domain Controller" if "Domain Controller" in (c.target_name or "") else "Member Server"
        details = c.details or {}
        findings = enrich_scan_details(details, version=c.version or "", role=role)
        counts = _scan_counts_from_details(details)
        rows.append({
            "id":          c.id,
            "scan_id":     c.id,
            "target_name": c.target_name,
            "hostname":    c.hostname or "",
            "host":        c.hostname or "",
            "score":       c.score,
            "scan_date":   c.scan_date.isoformat(),
            "version":     c.version or "",
            "status":      "done",
            "phase":       "",
            "error":       "",
            "items_scanned": counts["items_scanned"],
            "pass_count":  counts["pass_count"],
            "fail_count":  counts["fail_count"],
            "critical_count": counts["critical_count"],
            "high_count": counts["high_count"],
            "score_breakdown": _score_breakdown_from_details(details),
            "details":     details,
            "findings":    findings,
        })
    return rows

@app.post("/api/scan/subnet")
async def run_subnet_scan(
    req:              SubnetScanRequest,
    background_tasks: BackgroundTasks,
    current_user:     User = Depends(get_current_user),
):
    import ipaddress
    try:
        network = ipaddress.ip_network(req.subnet, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"subnet ไม่ถูกต้อง: {req.subnet}")

    hosts = [str(h) for h in network.hosts()]
    if len(hosts) > 254:
        raise HTTPException(status_code=400, detail="subnet ใหญ่เกินไป (max /24)")

    job_id, job = _new_job()
    job.message = f"เตรียมสแกน {len(hosts)} hosts..."

    background_tasks.add_task(
        _run_subnet_scan_job,
        job=job,
        hosts=hosts,
        req=req,
        user_id=current_user.id,
    )
    return {
        "job_id":  job_id,
        "status":  "pending",
        "subnet":  req.subnet,
        "total_hosts": len(hosts),
    }

# ---------------------------------------------------------------------------
# Background scan worker (จุดที่ 2 ตามหลักการแก้โค้ดใหม่)
# ---------------------------------------------------------------------------

async def _run_scan_job(
    job, version, target_label,
    role: str = "Member Server",
    executor=None, user_id=None,
):
    started_at = time.perf_counter()

    def _log_stage(stage: str, detail: str = ""):
        suffix = f" ({detail})" if detail else ""
        print(f"[scan-timing] {stage}: {time.perf_counter() - started_at:.2f}s{suffix}")

    job.status   = "running"
    job.progress = 5
    job.message  = "กำลังโหลด check definitions..."
    _log_stage("job_started", f"version={version} role={role} target={target_label}")

    # ── โหลด checks จาก JSON แทนการแกะไฟล์ตัวเก่า ──────────────────
    try:
        checks = load_checks(version, role=role)
    except FileNotFoundError as e:
        job.status = "error"
        job.error  = str(e)
        _log_stage("load_checks_failed", str(e))
        return

    if not checks:
        job.status = "error"
        job.error  = f"ไม่พบ check definitions สำหรับ version '{version}'"
        _log_stage("load_checks_empty")
        return

    job.progress = 10
    job.message  = "กำลังเตรียมข้อมูล Registry..."
    _log_stage("checks_loaded", f"count={len(checks)}")

    if executor and hasattr(executor, "prefetch_registry_bulk"):
        registry_keys = []
        for c in checks:
            rp = c.get("registry_path", "")
            if rp and "!" in rp:
                path_part, key_name = rp.split("!", 1)
                # normalize hive
                import re as _re
                path_upper = path_part.upper()
                if path_upper.startswith("HKLM\\") or path_upper.startswith("HKEY_LOCAL_MACHINE\\"):
                    sub = _re.sub(r"^(HKEY_LOCAL_MACHINE|HKLM)\\", "", path_part, flags=_re.IGNORECASE)
                    registry_keys.append(("HKLM", sub, key_name))
                elif path_upper.startswith("HKCU\\") or path_upper.startswith("HKEY_CURRENT_USER\\"):
                    sub = _re.sub(r"^(HKEY_CURRENT_USER|HKCU)\\", "", path_part, flags=_re.IGNORECASE)
                    registry_keys.append(("HKCU", sub, key_name))
                elif path_upper.startswith("MACHINE\\"):  # ← เพิ่มนี้
                    sub = _re.sub(r"^MACHINE\\", "", path_part, flags=_re.IGNORECASE)
                    registry_keys.append(("HKLM", sub, key_name))
                elif path_upper.startswith("SOFTWARE\\"):  # ← เพิ่มนี้
                    registry_keys.append(("HKLM", path_part, key_name))
        if registry_keys:
            batch_size = 100
            total_batches = (len(registry_keys) + batch_size - 1) // batch_size
            _log_stage("prefetch_registry_start", f"keys={len(registry_keys)} batches={total_batches}")
            for index in range(0, len(registry_keys), batch_size):
                batch_number = index // batch_size + 1
                batch = registry_keys[index:index + batch_size]
                job.progress = 10 + int(4 * (batch_number - 1) / max(total_batches, 1))
                job.message = f"กำลังเตรียมข้อมูล Registry... ({batch_number}/{total_batches})"
                _log_stage("prefetch_registry_batch_start", f"batch={batch_number}/{total_batches} keys={len(batch)}")
                # ใช้ timeout รอบการ prefetch แต่ละ batch เพื่อป้องกันการค้างทั้งหมด
                try:
                    batch_timeout = getattr(executor, "_REGISTRY_PREFETCH_TIMEOUT", 25)
                    # cap timeout to a reasonable upper bound
                    batch_timeout = int(batch_timeout or 25)
                    await asyncio.wait_for(
                        run_in_threadpool(executor.prefetch_registry_bulk, batch),
                        timeout=batch_timeout,
                    )
                    _log_stage("prefetch_registry_batch_done", f"batch={batch_number}/{total_batches} keys={len(batch)}")
                except asyncio.TimeoutError:
                    # ถ้าบาง batch timeout ให้บันทึกแล้วยุติการ prefetch ทั้งหมด
                    # (การรอให้ timeout ซ้ำหลาย batch ทำให้เสียเวลาเป็นจำนวนมาก)
                    _log_stage("prefetch_registry_batch_timeout", f"batch={batch_number}/{total_batches}")
                    job.message = f"กำลังเตรียมข้อมูล Registry... (ยกเลิกการ prefetch เนื่องจาก timeout ที่ batch {batch_number})"
                    prefetch_failed = True
                    break
                except Exception as e:
                    _log_stage("prefetch_registry_batch_error", f"batch={batch_number}/{total_batches} err={type(e).__name__}: {e}")
                    job.message = f"เกิดข้อผิดพลาดขณะเตรียม Registry (batch {batch_number})"
                    prefetch_failed = True
                    break
            # end for batches
            if 'prefetch_failed' in locals() and prefetch_failed:
                _log_stage("prefetch_registry_aborted", f"after batch={batch_number}")
            else:
                _log_stage("prefetch_registry_done", f"keys={len(registry_keys)} batches={total_batches}")
            

    job.progress = 15
    job.message  = "กำลังสแกน Security Policy..."
    _log_stage("scan_phase_start", f"checks={len(checks)}")

    try:
        # ── สร้าง scanner ไม่ต้องส่ง baseline_config / data_path อีกแล้ว ──
        from app.core.scan.scanner.security_scanner import SecurityScanner as SecurityBaselineScanner
        scanner = SecurityBaselineScanner(
            executor=executor,
            role=role,
        )
        
        try:
            _log_stage("scanner_run_start")
            score, details = await asyncio.wait_for(
                run_in_threadpool(scanner.run_baseline_scan, checks),  # ← ส่งตัวแปร checks เข้าไปตรงๆ
                timeout=SCAN_TIMEOUT_SECONDS,
            )
            _log_stage("scanner_run_done", f"score={score} details={len(details)}")
        except asyncio.TimeoutError:
            job.status = "error"
            job.error  = f"Scan timeout หลังจาก {SCAN_TIMEOUT_SECONDS}s"
            _log_stage("scanner_run_timeout", f"timeout={SCAN_TIMEOUT_SECONDS}s")
            return

        job.progress = 90
        job.message  = "กำลังบันทึกผล..."
        _log_stage("save_phase_start")

        findings        = enrich_scan_details(details, version=version, role=role)
        finding_summary = summarize_findings(findings)

        import datetime
        from app.core.database import SessionLocal
        from app.models.scan import ScanResult

        def _save():
            db = SessionLocal()
            try:
                new_scan = ScanResult(
                    target_name=target_label,
                    score=score,
                    details=details,          # เก็บ dict ครบ metadata
                    scan_date=datetime.datetime.now(),
                    version=version,
                    hostname=executor.host if executor else "localhost",
                    user_id=user_id,
                )
                db.add(new_scan)
                db.commit()
                db.refresh(new_scan)
                return new_scan.id
            finally:
                db.close()

        scan_id = await run_in_threadpool(_save)
        _log_stage("save_phase_done", f"scan_id={scan_id}")

        job.status   = "done"
        job.progress = 100
        job.message  = "เสร็จสิ้น"
        job.result   = {
            "scan_id":       scan_id,
            "target_name":   target_label,
            "version":       version,
            "score":         score,
            "items_scanned": _scan_counts_from_details(details)["items_scanned"],
            "details":       details,
            "findings":      findings,
            "summary":       finding_summary,
            "score_breakdown": _score_breakdown_from_details(details),
        }
        _log_stage("job_done", f"score={score} items={len(details)}")

    except Exception as e:
        job.status = "error"
        job.error  = str(e)
        _log_stage("job_error", f"{type(e).__name__}: {e}")


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
    user = None

    if AUTH_PROVIDER in ("ldap", "hybrid"):
        try:
            ldap_user = authenticate_ldap(form_data.username, form_data.password)
            user = db.query(User).filter(User.username == ldap_user.username).first()
            if not user:
                user = User(
                    username=ldap_user.username,
                    hashed_password="",
                    role=ldap_user.role,
                    is_active=True,
                )
                db.add(user)
            else:
                user.role = ldap_user.role
                user.is_active = True
            db.commit()
            db.refresh(user)
        except HTTPException:
            if AUTH_PROVIDER == "ldap":
                raise

    if user is None:
        user = db.query(User).filter(User.username == form_data.username).first()
        if not user or not user.hashed_password or not verify_password(form_data.password, user.hashed_password):
            raise HTTPException(status_code=400, detail="Username or password incorrect")
        if not user.is_active:
            raise HTTPException(status_code=403, detail="User account is inactive")
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {
        "access_token": access_token,
        "token_type":   "bearer",
        "username":     user.username,
        "role":         user.role,
    }


@app.get("/api/me")
def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "is_active": current_user.is_active,
    }


@app.post("/api/user/change-password")
def change_password(
    body:         ChangePasswordRequest,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    if not current_user.hashed_password:
        raise HTTPException(status_code=400, detail="LDAP users cannot change password here")
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="รหัสผ่านเดิมไม่ถูกต้อง")
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="รหัสผ่านใหม่ต้องมีอย่างน้อย 6 ตัวอักษร")
    current_user.hashed_password = get_password_hash(body.new_password)
    db.add(current_user)
    db.commit()
    return {"ok": True, "message": "เปลี่ยนรหัสผ่านสำเร็จ"}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    query = db.query(ScanResult)
    if not _has_admin_access(current_user):
        query = query.filter(ScanResult.user_id == current_user.id)

    latest = query.order_by(ScanResult.scan_date.desc()).first()
    count  = query.with_entities(func.count(ScanResult.id)).scalar()
    if not latest:
        return {"total_scans": 0, "latest_score": 0, "target": "No Data", "details": {}}
    return {
        "total_scans":  count,
        "latest_score": latest.score,
        "target":       latest.target_name,
        "details":      latest.details,
    }


# ---------------------------------------------------------------------------
# Local Scan (จุดที่ 4 - แก้ไข Local Scan เอา resolve_baseline_path ออก)
# ---------------------------------------------------------------------------

@app.post("/api/scan/run")
async def run_security_scan(
    req:              LocalScanRequest,
    background_tasks: BackgroundTasks,
    current_user:     User = Depends(get_current_user),
):
    job_id, job  = _new_job()
    target_label = f"localhost ({req.version})"

    background_tasks.add_task(
        _run_scan_job,
        job=job,
        version=req.version,
        target_label=target_label,
        user_id=current_user.id,
    )
    return {"job_id": job_id, "status": "pending"}


# ---------------------------------------------------------------------------
# Remote Scan (จุดที่ 4 - แก้ไข Remote Scan เอา resolve_baseline_path ออก)
# ---------------------------------------------------------------------------

@app.post("/api/scan/test-connection")
async def test_remote_connection(
    req:          ConnectionTestRequest,
    current_user: User = Depends(get_current_user),
):
    try:
        executor = RemoteExecutor(
            host=req.host, username=req.username, password=req.password,
            use_ssl=req.use_ssl, skip_ca_check=req.skip_ca_check,
            timeout=SCAN_TIMEOUT_SECONDS,
        )
        result = await asyncio.wait_for(
            run_in_threadpool(executor.test_connection), timeout=15,
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
    current_user:     User = Depends(get_current_user),
):
    from app.core.scan.scanner.executors.remote_executor import RemoteExecutor
    import asyncio
    from fastapi.concurrency import run_in_threadpool

    executor = RemoteExecutor(
        host=req.host, username=req.username, password=req.password,
        use_ssl=req.use_ssl, skip_ca_check=req.skip_ca_check,
        timeout=SCAN_TIMEOUT_SECONDS,
    )
    try:
        conn_test = await asyncio.wait_for(
            run_in_threadpool(executor.test_connection), timeout=15,
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
    job_id, job  = _new_job()

    background_tasks.add_task(
        _run_scan_job,
        job=job,
        version=req.version,
        role=req.role,            
        target_label=target_label,
        executor=executor,
        user_id=current_user.id,
    )
    return {
        "job_id":      job_id,
        "status":      "pending",
        "host":        req.host,
        "hostname":    hostname,
        "target_name": target_label,
    }


# ---------------------------------------------------------------------------
# Job Status Polling
# ---------------------------------------------------------------------------

@app.get("/api/scan/status/{job_id}")
async def get_scan_status(
    job_id:       str,
    current_user: User = Depends(get_current_user),
):
    job = _jobs.get(job_id)
    db = SessionLocal()
    try:
        _recover_stale_agent_jobs(db)
        db_job = db.query(AgentJob).filter(AgentJob.job_id == job_id).first()
        if db_job:
            if not _has_admin_access(current_user) and db_job.user_id != current_user.id:
                raise HTTPException(status_code=404, detail="job not found")
            _sync_memory_agent_job(db_job)
            job = _jobs.get(job_id)
            if not job:
                progress = 100 if db_job.status in ("done", "error") else (50 if db_job.status == "running" else 5)
                resp = {
                    "job_id": job_id,
                    "status": db_job.status,
                    "progress": progress,
                    "message": db_job.status,
                }
                if db_job.status == "done":
                    resp["result"] = db_job.result or {}
                elif db_job.status == "error":
                    resp["error"] = db_job.error or "Agent job failed"
                return resp
    finally:
        db.close()

    if not job:
        raise HTTPException(status_code=404, detail="job not found")

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
    limit:        int     = 20,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    query = db.query(ScanResult).filter(
        ScanResult.parent_scan_id == None  # ← เฉพาะ top-level
    )
    if not _has_admin_access(current_user):
        query = query.filter(ScanResult.user_id == current_user.id)
    scans = query.order_by(ScanResult.scan_date.desc()).limit(limit).all()
    rows = []
    for s in scans:
        subnet_summary = _subnet_summary_from_children(s, db, current_user) if getattr(s, "scan_type", "single") == "subnet" else None
        single_counts = _scan_counts_from_details(s.details)
        rows.append({
            "id":            s.id,
            "target_name":   s.target_name,
            "score":         subnet_summary.get("score", s.score) if subnet_summary else s.score,
            "scan_date":     s.scan_date.isoformat(),
            "version":       s.version or "",
            "hostname":      s.hostname or "",
            "scan_type":     getattr(s, "scan_type", "single"),
            "items_scanned": subnet_summary["items_scanned"] if subnet_summary else single_counts["items_scanned"],
            "pass_count":    subnet_summary["pass_count"] if subnet_summary else single_counts["pass_count"],
            "fail_count":    subnet_summary["fail_count"] if subnet_summary else single_counts["fail_count"],
            "host_count":    subnet_summary.get("host_count", 1) if subnet_summary else 1,
            "failed_host_count": subnet_summary.get("failed_host_count", 0) if subnet_summary else (1 if single_counts["fail_count"] else 0),
            "critical_count": subnet_summary.get("critical_count", single_counts["critical_count"]) if subnet_summary else single_counts["critical_count"],
            "high_count": subnet_summary.get("high_count", single_counts["high_count"]) if subnet_summary else single_counts["high_count"],
            "score_breakdown": subnet_summary.get("score_breakdown") if subnet_summary else _score_breakdown_from_details(s.details),
        })
    return rows


@app.get("/api/scan/history/{scan_id}")
async def get_scan_detail(
    scan_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    query = db.query(ScanResult).filter(ScanResult.id == scan_id)
    if not _has_admin_access(current_user):
        query = query.filter(ScanResult.user_id == current_user.id)
    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="ไม่พบผลการสแกนนี้หรือไม่มีสิทธิ์เข้าถึง")
    role = "Domain Controller" if "Domain Controller" in (scan.target_name or "") else "Member Server"
    if getattr(scan, "scan_type", "single") == "subnet":
        findings = []
        summary = _subnet_summary_from_children(scan, db, current_user)
    else:
        findings = enrich_scan_details(scan.details, version=scan.version or "", role=role)
        summary = summarize_findings(findings)
    count_summary = summary if getattr(scan, "scan_type", "single") == "subnet" else _scan_counts_from_details(scan.details)
    score_breakdown = (
        count_summary.get("score_breakdown")
        if isinstance(count_summary, dict) and getattr(scan, "scan_type", "single") == "subnet"
        else _score_breakdown_from_details(scan.details)
    )
    return {
        "id":            scan.id,
        "target_name":   scan.target_name,
        "score":         count_summary.get("score", scan.score) if isinstance(count_summary, dict) else scan.score,
        "scan_date":     scan.scan_date.isoformat(),
        "version":       scan.version or "",
        "hostname":      scan.hostname or "",
        "scan_type":     getattr(scan, "scan_type", "single"),
        "parent_scan_id": scan.parent_scan_id,
        "items_scanned": count_summary.get("items_scanned", 0) if isinstance(count_summary, dict) else 0,
        "pass_count":    count_summary.get("pass_count", 0) if isinstance(count_summary, dict) else 0,
        "fail_count":    count_summary.get("fail_count", 0) if isinstance(count_summary, dict) else 0,
        "host_count":    count_summary.get("host_count", 1) if isinstance(count_summary, dict) else 1,
        "failed_host_count": count_summary.get("failed_host_count", 0) if isinstance(count_summary, dict) else 0,
        "critical_count": count_summary.get("critical_count", 0) if isinstance(count_summary, dict) else 0,
        "high_count":    count_summary.get("high_count", 0) if isinstance(count_summary, dict) else 0,
        "details":       scan.details,
        "findings":      findings,
        "summary":       summary,
        "score_breakdown": score_breakdown,
    }


def _failed_finding_map(scan: ScanResult) -> dict[str, dict]:
    role = "Domain Controller" if "Domain Controller" in (scan.target_name or "") else "Member Server"
    details = scan.details or {}
    findings = enrich_scan_details(details, version=scan.version or "", role=role)
    rows = {}
    for item in findings:
        status = str(item.get("status", "")).lower()
        if not status.startswith("fail"):
            continue
        key = item.get("check_id") or item.get("source_key") or item.get("check_name")
        if not key:
            continue
        rows[str(key)] = item
    return rows


def _severity_category_delta(current_items: dict[str, dict], base_items: dict[str, dict]) -> dict:
    def counts(items):
        severity = {}
        category = {}
        for item in items.values():
            sev = str(item.get("severity") or "Low").title()
            cat = str(item.get("category") or "General")
            severity[sev] = severity.get(sev, 0) + 1
            category[cat] = category.get(cat, 0) + 1
        return severity, category

    current_sev, current_cat = counts(current_items)
    base_sev, base_cat = counts(base_items)
    severities = sorted(set(current_sev) | set(base_sev))
    categories = sorted(set(current_cat) | set(base_cat))
    return {
        "severity": {k: current_sev.get(k, 0) - base_sev.get(k, 0) for k in severities},
        "category": {k: current_cat.get(k, 0) - base_cat.get(k, 0) for k in categories},
    }


@app.get("/api/scan/history/{scan_id}/compare/{base_scan_id}")
async def compare_scan_results(
    scan_id: int,
    base_scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(ScanResult).filter(ScanResult.id.in_([scan_id, base_scan_id]))
    if not _has_admin_access(current_user):
        query = query.filter(ScanResult.user_id == current_user.id)
    scans = {scan.id: scan for scan in query.all()}
    current = scans.get(scan_id)
    base = scans.get(base_scan_id)
    if not current or not base:
        raise HTTPException(status_code=404, detail="scan not found")
    if getattr(current, "scan_type", "single") != "single" or getattr(base, "scan_type", "single") != "single":
        raise HTTPException(status_code=400, detail="comparison supports single-machine scans only")

    current_host = (current.hostname or current.target_name or "").lower()
    base_host = (base.hostname or base.target_name or "").lower()
    if current_host and base_host and current_host != base_host:
        raise HTTPException(status_code=400, detail="scans must belong to the same host")

    current_failed = _failed_finding_map(current)
    base_failed = _failed_finding_map(base)
    current_keys = set(current_failed)
    base_keys = set(base_failed)
    fixed_keys = sorted(base_keys - current_keys)
    new_keys = sorted(current_keys - base_keys)
    still_keys = sorted(current_keys & base_keys)

    return {
        "current_scan_id": current.id,
        "base_scan_id": base.id,
        "hostname": current.hostname or base.hostname or "",
        "version": current.version or "",
        "base_version": base.version or "",
        "score": current.score,
        "base_score": base.score,
        "score_delta": (current.score or 0) - (base.score or 0),
        "fixed": [base_failed[k] for k in fixed_keys],
        "newly_failed": [current_failed[k] for k in new_keys],
        "still_failing": [current_failed[k] for k in still_keys],
        "counts": {
            "fixed": len(fixed_keys),
            "newly_failed": len(new_keys),
            "still_failing": len(still_keys),
        },
        "delta": _severity_category_delta(current_failed, base_failed),
    }


@app.delete("/api/scan/history/{scan_id}")
async def delete_scan(
    scan_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    query = db.query(ScanResult).filter(ScanResult.id == scan_id)
    if not _has_admin_access(current_user):
        query = query.filter(ScanResult.user_id == current_user.id)
    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="ไม่พบผลการสแกนหรือไม่มีสิทธิ์ลบ")
    db.delete(scan)
    db.commit()
    return {"ok": True}


# ── จุดที่ 3 - แก้ไขเวอร์ชันให้อ่านจาก /baselines/generated/*.json แทน ──
@app.get("/api/scan/versions")
async def get_supported_versions(current_user: User = Depends(get_current_user)):
    return list_available_versions()


# ---------------------------------------------------------------------------
# Agent Scan (ปรับตัวแปรตามสถาปัตยกรรม JSON ใหม่)
# ---------------------------------------------------------------------------

@app.post("/api/scan/agent")
async def run_agent_scan(
    req:              AgentScanRequest,
    background_tasks: BackgroundTasks,
    current_user:     User = Depends(get_current_user),
):
    baseline_info = None

    agent = db_agent = None
    db = SessionLocal()
    try:
        db_agent = db.query(AgentToken).filter(AgentToken.agent_id == req.agent_id).first()
        if not db_agent:
            raise HTTPException(status_code=404, detail=f"ไม่พบ agent: {req.agent_id}")
        if req.version.lower() == "auto":
            baseline_info = _resolve_agent_baseline(db_agent)
            if baseline_info.get("error"):
                raise HTTPException(status_code=400, detail=baseline_info["error"])
            resolved_version = baseline_info["version"]
        else:
            resolved_version = req.version
            baseline_info = {
                **_agent_os_payload(db_agent),
                "version": resolved_version,
                "match_type": "manual",
                "warning": "",
                "error": "",
            }
        agent = {
            "agent_id": db_agent.agent_id,
            "hostname": db_agent.hostname or db_agent.agent_id,
        }
    finally:
        db.close()

    baseline_path = os.path.join(ROOT_DIR, "baselines", "generated", f"{resolved_version}.json")
    agent_id    = req.agent_id
    job_id, job = _new_job()
    job.status  = "running"
    job.message = "Waiting for agent to pick up job..."
    job.user_id = current_user.id
    job.role = req.role
    job.target_agent_id = agent_id
    job.baseline_match_type = baseline_info.get("match_type", "")
    job.baseline_warning = baseline_info.get("warning", "")
    
    enqueue(agent_id, job_id, resolved_version, baseline_path)
    return {
        "job_id":   job_id,
        "status":   "pending",
        "host":     agent["hostname"],
        "agent_id": agent_id,
        "version": resolved_version,
        "baseline_match_type": baseline_info.get("match_type", ""),
        "baseline_warning": baseline_info.get("warning", ""),
    }


async def _run_agent_subnet_scan_job(parent_job, parent_scan_id, req, user_id, online_agents, offline_results):
    parent_job.status = "running"
    parent_job.progress = 5
    parent_job.message = f"Dispatching agent jobs for {req.subnet}..."

    child_jobs = []
    for agent in online_agents:
        resolved_version = agent["baseline_info"]["version"]
        baseline_path = os.path.join(ROOT_DIR, "baselines", "generated", f"{resolved_version}.json")
        child_job_id, child_job = _new_job()
        child_job.status = "running"
        child_job.message = "Waiting for agent to pick up job..."
        child_job.user_id = user_id
        child_job.role = _resolve_schedule_role(
            type("AgentLike", (), {
                "hostname": agent.get("hostname", ""),
                "os_name": agent.get("baseline_info", {}).get("os_name", ""),
                "os_family": agent.get("baseline_info", {}).get("os_family", ""),
            })(),
            resolved_version,
            req.role,
        )
        child_job.parent_scan_id = parent_scan_id
        child_job.target_agent_id = agent["agent_id"]
        child_job.baseline_match_type = agent["baseline_info"].get("match_type", "")
        child_job.baseline_warning = agent["baseline_info"].get("warning", "")
        enqueue(agent["agent_id"], child_job_id, resolved_version, baseline_path)
        child_jobs.append((agent, child_job_id, child_job))

    if not child_jobs:
        results = offline_results
    else:
        timeout_seconds = int(os.environ.get("AGENT_SUBNET_TIMEOUT_SECONDS", "900"))
        deadline = time.time() + timeout_seconds
        total = len(child_jobs)

        def _sync_child_jobs_from_db():
            db = SessionLocal()
            try:
                _recover_stale_agent_jobs(db)
                rows = {
                    row.job_id: row
                    for row in db.query(AgentJob)
                    .filter(AgentJob.job_id.in_([job_id for _agent, job_id, _child_job in child_jobs]))
                    .all()
                }
                for _agent, child_job_id, child_job in child_jobs:
                    row = rows.get(child_job_id)
                    if not row or row.status not in ("done", "error"):
                        continue
                    child_job.status = row.status
                    child_job.error = row.error or ""
                    child_job.result = row.result
            finally:
                db.close()

        while time.time() < deadline:
            await run_in_threadpool(_sync_child_jobs_from_db)
            done = sum(1 for _agent, _job_id, child_job in child_jobs if child_job.status in ("done", "error"))
            parent_job.progress = 5 + int(done / max(total, 1) * 90)
            parent_job.message = f"Agent scan progress {done}/{total} hosts"
            if done >= total:
                break
            await asyncio.sleep(2)

        for _agent, _job_id, child_job in child_jobs:
            if child_job.status not in ("done", "error"):
                child_job.status = "error"
                child_job.error = "Agent scan timeout"

        def _mark_unfinished_children_timeout():
            db = SessionLocal()
            try:
                now = datetime.datetime.now()
                for _agent, child_job_id, child_job in child_jobs:
                    if child_job.status != "error" or child_job.error != "Agent scan timeout":
                        continue
                    row = db.query(AgentJob).filter(AgentJob.job_id == child_job_id).first()
                    if row and row.status not in ("done", "error"):
                        row.status = "error"
                        row.error = child_job.error
                        row.completed_at = now
                        row.updated_at = now
                db.commit()
            finally:
                db.close()

        await run_in_threadpool(_mark_unfinished_children_timeout)

        results = list(offline_results)
        for agent, child_job_id, child_job in child_jobs:
            if child_job.status == "done" and child_job.result:
                results.append({
                    "host": agent["hostname"],
                    "hostname": child_job.result.get("hostname") or agent["hostname"],
                    "agent_id": agent["agent_id"],
                    "ip_addresses": agent["ip_addresses"],
                    "score": child_job.result.get("score", 0),
                    "scan_id": child_job.result.get("scan_id"),
                    "status": "done",
                    "method": "agent",
                    "version": child_job.result.get("version") or agent["baseline_info"].get("version", ""),
                    "baseline_match_type": agent["baseline_info"].get("match_type", ""),
                    "baseline_warning": agent["baseline_info"].get("warning", ""),
                    "score_breakdown": child_job.result.get("score_breakdown"),
                })
            else:
                results.append({
                    "host": agent["hostname"],
                    "hostname": agent["hostname"],
                    "agent_id": agent["agent_id"],
                    "ip_addresses": agent["ip_addresses"],
                    "score": 0,
                    "status": "error",
                    "phase": "agent_scan",
                    "method": "agent",
                    "version": agent["baseline_info"].get("version", ""),
                    "baseline_match_type": agent["baseline_info"].get("match_type", ""),
                    "baseline_warning": agent["baseline_info"].get("warning", ""),
                    "error": getattr(child_job, "error", "") or "Agent scan failed",
                })

    success = [r for r in results if r.get("status") == "done"]
    failed = [r for r in results if r.get("status") == "error"]
    aggregate_score, aggregate_breakdown = _aggregate_score_breakdowns(success)
    avg_score = aggregate_score if aggregate_breakdown else int(sum(r.get("score", 0) for r in success) / len(success)) if success else 0

    def _update_parent():
        db = SessionLocal()
        try:
            parent = db.query(ScanResult).filter(ScanResult.id == parent_scan_id).first()
            if parent:
                parent.score = avg_score
                parent.details = {
                    "results": results,
                    "subnet": req.subnet,
                    "method": "agent",
                    "discovered_hosts": len(results),
                    "score_breakdown": aggregate_breakdown,
                }
                db.commit()
        finally:
            db.close()

    await run_in_threadpool(_update_parent)

    parent_job.status = "done"
    parent_job.progress = 100
    parent_job.message = f"Finished: success {len(success)}, failed {len(failed)}"
    parent_job.result = {
        "subnet": req.subnet,
        "total": len(results),
        "discovered_hosts": len(results),
        "success_count": len(success),
        "failed_count": len(failed),
        "results": results,
        "scan_id": parent_scan_id,
    }


@app.post("/api/scan/agent-subnet")
async def run_agent_subnet_scan(
    req:              AgentSubnetScanRequest,
    background_tasks: BackgroundTasks,
    current_user:     User = Depends(get_current_user),
):
    try:
        network = ipaddress.ip_network(req.subnet, strict=False)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"subnet ไม่ถูกต้อง: {req.subnet}")

    db = SessionLocal()
    try:
        agents = db.query(AgentToken).all()
        now = datetime.datetime.now()
        matched = []
        for a in agents:
            if not _agent_matches_subnet(a, network):
                continue
            if req.version.lower() == "auto":
                baseline_info = _resolve_agent_baseline(a)
            else:
                baseline_info = {
                    **_agent_os_payload(a),
                    "version": req.version,
                    "match_type": "manual",
                    "warning": "",
                    "error": "",
                }
            matched.append({
                "agent_id": a.agent_id,
                "hostname": a.hostname or a.agent_id,
                "ip_addresses": a.ip_addresses or [],
                "last_seen": a.last_seen,
                "online": ((now - a.last_seen).total_seconds() < 300) if a.last_seen else False,
                "baseline_info": baseline_info,
            })

        parent = ScanResult(
            target_name = f"{req.subnet} ({req.version})",
            score       = 0,
            details     = {},
            scan_date   = datetime.datetime.now(),
            version     = req.version,
            hostname    = req.subnet,
            user_id     = current_user.id,
            scan_type   = "subnet",
        )
        db.add(parent)
        db.commit()
        db.refresh(parent)
        parent_scan_id = parent.id
    finally:
        db.close()

    unresolved_results = [
        {
            "host": agent["hostname"],
            "hostname": agent["hostname"],
            "agent_id": agent["agent_id"],
            "ip_addresses": agent["ip_addresses"],
            "score": 0,
            "status": "error",
            "phase": "baseline_resolve",
            "method": "agent",
            "version": "",
            "baseline_match_type": "unresolved",
            "error": agent["baseline_info"].get("error") or "No suitable baseline",
        }
        for agent in matched
        if agent["baseline_info"].get("error")
    ]
    online_agents = [
        a for a in matched
        if a["online"] and not a["baseline_info"].get("error")
    ]
    offline_results = [
        {
            "host": agent["hostname"],
            "hostname": agent["hostname"],
            "agent_id": agent["agent_id"],
            "ip_addresses": agent["ip_addresses"],
            "score": 0,
            "status": "error",
            "phase": "agent_offline",
            "method": "agent",
            "version": agent["baseline_info"].get("version", ""),
            "baseline_match_type": agent["baseline_info"].get("match_type", ""),
            "error": "Agent offline or heartbeat older than 5 minutes",
        }
        for agent in matched
        if not agent["online"] and not agent["baseline_info"].get("error")
    ]

    job_id, job = _new_job()
    job.message = f"Preparing agent scan for {req.subnet}..."
    background_tasks.add_task(
        _run_agent_subnet_scan_job,
        parent_job=job,
        parent_scan_id=parent_scan_id,
        req=req,
        user_id=current_user.id,
        online_agents=online_agents,
        offline_results=unresolved_results + offline_results,
    )

    return {
        "job_id": job_id,
        "status": "pending",
        "subnet": req.subnet,
        "total_agents": len(matched),
        "online_agents": len(online_agents),
        "offline_agents": len(unresolved_results) + len(offline_results),
    }


@app.get("/api/agents")
async def list_agents(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    _recover_stale_agent_jobs(db)
    agents = db.query(AgentToken).order_by(AgentToken.last_seen.desc()).all()
    now = datetime.datetime.now()
    rows = []
    for a in agents:
        baseline_info = _resolve_agent_baseline(a)
        health = _agent_health(a, baseline_info, now)
        pending_jobs = db.query(AgentJob).filter(
            AgentJob.agent_id == a.agent_id,
            AgentJob.status == "pending",
        ).count()
        running_jobs = db.query(AgentJob).filter(
            AgentJob.agent_id == a.agent_id,
            AgentJob.status == "running",
        ).count()
        last_job = (
            db.query(AgentJob)
            .filter(AgentJob.agent_id == a.agent_id)
            .order_by(AgentJob.created_at.desc())
            .first()
        )
        rows.append({
            "agent_id":   a.agent_id,
            "hostname":   a.hostname,
            "ip_addresses": a.ip_addresses or [],
            "agent_version": a.agent_version or "",
            "os_name": a.os_name or "",
            "os_version": a.os_version or "",
            "os_build": a.os_build or "",
            "os_release": a.os_release or "",
            "os_family": a.os_family or "",
            "detected_baseline": baseline_info.get("version", ""),
            "baseline_match_type": baseline_info.get("match_type", ""),
            "baseline_warning": baseline_info.get("warning", ""),
            "baseline_error": baseline_info.get("error", ""),
            "last_error": a.last_error or "",
            "last_error_at": a.last_error_at.isoformat() if a.last_error_at else None,
            "has_os_metadata": health["has_os_metadata"],
            "baseline_ready": health["baseline_ready"],
            "health_status": health["health_status"],
            "health_message": health["health_message"],
            "pending_jobs": pending_jobs,
            "running_jobs": running_jobs,
            "last_job_status": last_job.status if last_job else "",
            "last_job_attempts": last_job.attempts if last_job else 0,
            "last_job_at": last_job.updated_at.isoformat() if last_job and last_job.updated_at else None,
            "registered": a.registered.isoformat() if a.registered else None,
            "last_seen":  a.last_seen.isoformat() if a.last_seen else None,
            "online":     health["online"],
        })
    return rows
