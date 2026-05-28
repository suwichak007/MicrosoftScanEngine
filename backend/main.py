"""
main.py  (updated â€” config-driven multi-OS support via JSON baselines)

à¹€à¸›à¸¥à¸µà¹ˆà¸¢à¸™à¸«à¸¥à¸±à¸à¹†:
  - à¸–à¸­à¸”à¸à¸²à¸£à¹‚à¸«à¸¥à¸”à¹à¸¥à¸°à¹à¸à¸°à¹„à¸Ÿà¸¥à¹Œ Excel/XLSX à¸•à¸±à¸§à¹€à¸à¹ˆà¸²à¸­à¸­à¸à¸—à¸±à¹‰à¸‡à¸«à¸¡à¸”
  - à¹ƒà¸Šà¹‰ load_checks() à¹à¸¥à¸° list_available_versions() à¹€à¸žà¸·à¹ˆà¸­à¸”à¸¶à¸‡à¸‚à¹‰à¸­à¸¡à¸¹à¸¥à¸•à¸£à¸‡à¸ˆà¸²à¸ JSON à¹à¸—à¸™
  - à¸›à¸£à¸±à¸šà¸›à¸£à¸¸à¸‡ _run_scan_job à¹ƒà¸«à¹‰à¸ªà¹ˆà¸‡à¸Ÿà¸±à¸‡à¸à¹Œà¸Šà¸±à¸™ checks à¹€à¸‚à¹‰à¸² run_baseline_scan()
  - à¸›à¸£à¸±à¸šà¸›à¸£à¸¸à¸‡à¸—à¸¸à¸ Endpoint (/run, /remote, /versions, /agent) à¹ƒà¸«à¹‰à¸£à¸­à¸‡à¸£à¸±à¸šà¹‚à¸„à¸£à¸‡à¸ªà¸£à¹‰à¸²à¸‡à¹ƒà¸«à¸¡à¹ˆ
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
from app.schemas.user import UserCreate, UserResponse
from app.schemas.scan import ScanResultResponse
from app.core.security import get_password_hash, verify_password, create_access_token
from app.core.config import AUTH_PROVIDER
from app.core.ldap_auth import authenticate_ldap
from app.core.scan.scanner.security_scanner import SecurityScanner as SecurityBaselineScanner
from app.core.scan.scanner.baseline_config import (
    load_checks,               # â† à¹ƒà¸«à¸¡à¹ˆ: load checks à¸ˆà¸²à¸ JSON
    list_available_versions,   # â† à¹ƒà¸«à¸¡à¹ˆ: list à¸ˆà¸²à¸ JSON files
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
from app.core.admin_routes import router as admin_router
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

_ensure_agent_inventory_columns()

app = FastAPI()

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
    """à¸•à¸£à¸§à¸ˆà¸ªà¸­à¸šà¸«à¸£à¸·à¸­à¹à¸ªà¸”à¸‡à¸œà¸¥à¸£à¸°à¸šà¸šà¸ˆà¸±à¸”à¹€à¸à¹‡à¸š Baseline à¹à¸šà¸šà¹ƒà¸«à¸¡à¹ˆà¸•à¸­à¸™à¹€à¸£à¸´à¹ˆà¸¡à¸•à¹‰à¸™à¸£à¸°à¸šà¸š"""
    try:
        versions = list_available_versions()
        print(f"[startup] Available JSON baselines detected: {versions}")
    except Exception as e:
        print(f"[startup] Warning during baseline detection: {str(e)}")


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
    max_parallel:  int  = Field(10)  # à¸ªà¹à¸à¸™à¸žà¸£à¹‰à¸­à¸¡à¸à¸±à¸™à¸ªà¸¹à¸‡à¸ªà¸¸à¸” 10 à¹€à¸„à¸£à¸·à¹ˆà¸­à¸‡


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


def _subnet_summary_from_details(details):
    if not isinstance(details, dict):
        return None
    results = details.get("results")
    if not isinstance(results, list):
        return None
    success_count = sum(1 for r in results if isinstance(r, dict) and r.get("status") == "done")
    return {
        "items_scanned": success_count,
        "pass_count": success_count,
        "fail_count": 0,
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


async def _run_subnet_scan_job(job, hosts, req, user_id):
    import asyncio
    from fastapi.concurrency import run_in_threadpool

    job.status   = "running"
    job.progress = 0
    job.message  = f"à¸à¸³à¸¥à¸±à¸‡ discover hosts à¹ƒà¸™ {req.subnet}..."

    # à¸ªà¸£à¹‰à¸²à¸‡ parent record à¸à¹ˆà¸­à¸™
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
                    f"(à¹€à¸ˆà¸­ {live_count} à¹€à¸„à¸£à¸·à¹ˆà¸­à¸‡)"
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
            "error": f"WinRM port {discovery_port} à¹„à¸¡à¹ˆà¸•à¸­à¸šà¸ à¸²à¸¢à¹ƒà¸™ {int(SUBNET_DISCOVERY_TIMEOUT_SECONDS * 1000)}ms",
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
        job.message = f"à¹„à¸¡à¹ˆà¸žà¸š host à¸—à¸µà¹ˆà¹€à¸›à¸´à¸” WinRM port {discovery_port} à¹ƒà¸™ {req.subnet}"
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
    job.message = f"à¸žà¸š WinRM {total}/{len(hosts)} hosts à¸à¸³à¸¥à¸±à¸‡à¹€à¸£à¸´à¹ˆà¸¡ scan..."

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
                job.message  = f"à¸ªà¹à¸à¸™à¹à¸¥à¹‰à¸§ {done}/{total} hosts"

                return {
                    "host": host, "hostname": hostname,
                    "score": score, "scan_id": scan_id, "status": "done",
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

    # update parent score
    avg_score = int(sum(r["score"] for r in success) / len(success)) if success else 0

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
                }
                db.commit()
        finally:
            db.close()

    await run_in_threadpool(_update_parent)

    job.status   = "done"
    job.progress = 100
    job.message  = f"à¹€à¸ªà¸£à¹‡à¸ˆà¸ªà¸´à¹‰à¸™: à¸ªà¸³à¹€à¸£à¹‡à¸ˆ {len(success)}, à¸¥à¹‰à¸¡à¹€à¸«à¸¥à¸§ {len(failed)}"
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
    if current_user.role != "admin":
        parent_query = parent_query.filter(ScanResult.user_id == current_user.id)
    parent = parent_query.first()
    if not parent:
        raise HTTPException(status_code=404, detail="à¹„à¸¡à¹ˆà¸žà¸š subnet scan à¸™à¸µà¹‰à¸«à¸£à¸·à¸­à¹„à¸¡à¹ˆà¸¡à¸µà¸ªà¸´à¸—à¸˜à¸´à¹Œà¹€à¸‚à¹‰à¸²à¸–à¸¶à¸‡")

    query = db.query(ScanResult).filter(ScanResult.parent_scan_id == scan_id)
    if current_user.role != "admin":
        query = query.filter(ScanResult.user_id == current_user.id)
    children = query.order_by(ScanResult.scan_date).all()
    return [
        {
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
            "pass_count":  sum(1 for v in (c.details or {}).values()
                              if isinstance(v, dict) and v.get("status") == "Pass"),
            "fail_count":  sum(1 for v in (c.details or {}).values()
                              if isinstance(v, dict) and str(v.get("status","")).startswith("Fail")),
        }
        for c in children
    ]

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
        raise HTTPException(status_code=400, detail=f"subnet à¹„à¸¡à¹ˆà¸–à¸¹à¸à¸•à¹‰à¸­à¸‡: {req.subnet}")

    hosts = [str(h) for h in network.hosts()]
    if len(hosts) > 254:
        raise HTTPException(status_code=400, detail="subnet à¹ƒà¸«à¸à¹ˆà¹€à¸à¸´à¸™à¹„à¸› (max /24)")

    job_id, job = _new_job()
    job.message = f"à¹€à¸•à¸£à¸µà¸¢à¸¡à¸ªà¹à¸à¸™ {len(hosts)} hosts..."

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
# Background scan worker (à¸ˆà¸¸à¸”à¸—à¸µà¹ˆ 2 à¸•à¸²à¸¡à¸«à¸¥à¸±à¸à¸à¸²à¸£à¹à¸à¹‰à¹‚à¸„à¹‰à¸”à¹ƒà¸«à¸¡à¹ˆ)
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
    job.message  = "à¸à¸³à¸¥à¸±à¸‡à¹‚à¸«à¸¥à¸” check definitions..."
    _log_stage("job_started", f"version={version} role={role} target={target_label}")

    # â”€â”€ à¹‚à¸«à¸¥à¸” checks à¸ˆà¸²à¸ JSON à¹à¸—à¸™à¸à¸²à¸£à¹à¸à¸°à¹„à¸Ÿà¸¥à¹Œà¸•à¸±à¸§à¹€à¸à¹ˆà¸² â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
    try:
        checks = load_checks(version, role=role)
    except FileNotFoundError as e:
        job.status = "error"
        job.error  = str(e)
        _log_stage("load_checks_failed", str(e))
        return

    if not checks:
        job.status = "error"
        job.error  = f"à¹„à¸¡à¹ˆà¸žà¸š check definitions à¸ªà¸³à¸«à¸£à¸±à¸š version '{version}'"
        _log_stage("load_checks_empty")
        return

    job.progress = 10
    job.message  = "à¸à¸³à¸¥à¸±à¸‡à¹€à¸•à¸£à¸µà¸¢à¸¡à¸‚à¹‰à¸­à¸¡à¸¹à¸¥ Registry..."
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
                elif path_upper.startswith("MACHINE\\"):  # â† à¹€à¸žà¸´à¹ˆà¸¡à¸™à¸µà¹‰
                    sub = _re.sub(r"^MACHINE\\", "", path_part, flags=_re.IGNORECASE)
                    registry_keys.append(("HKLM", sub, key_name))
                elif path_upper.startswith("SOFTWARE\\"):  # â† à¹€à¸žà¸´à¹ˆà¸¡à¸™à¸µà¹‰
                    registry_keys.append(("HKLM", path_part, key_name))
        if registry_keys:
            batch_size = 100
            total_batches = (len(registry_keys) + batch_size - 1) // batch_size
            _log_stage("prefetch_registry_start", f"keys={len(registry_keys)} batches={total_batches}")
            for index in range(0, len(registry_keys), batch_size):
                batch_number = index // batch_size + 1
                batch = registry_keys[index:index + batch_size]
                job.progress = 10 + int(4 * (batch_number - 1) / max(total_batches, 1))
                job.message = f"à¸à¸³à¸¥à¸±à¸‡à¹€à¸•à¸£à¸µà¸¢à¸¡à¸‚à¹‰à¸­à¸¡à¸¹à¸¥ Registry... ({batch_number}/{total_batches})"
                _log_stage("prefetch_registry_batch_start", f"batch={batch_number}/{total_batches} keys={len(batch)}")
                # à¹ƒà¸Šà¹‰ timeout à¸£à¸­à¸šà¸à¸²à¸£ prefetch à¹à¸•à¹ˆà¸¥à¸° batch à¹€à¸žà¸·à¹ˆà¸­à¸›à¹‰à¸­à¸‡à¸à¸±à¸™à¸à¸²à¸£à¸„à¹‰à¸²à¸‡à¸—à¸±à¹‰à¸‡à¸«à¸¡à¸”
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
                    # à¸–à¹‰à¸²à¸šà¸²à¸‡ batch timeout à¹ƒà¸«à¹‰à¸šà¸±à¸™à¸—à¸¶à¸à¹à¸¥à¹‰à¸§à¸¢à¸¸à¸•à¸´à¸à¸²à¸£ prefetch à¸—à¸±à¹‰à¸‡à¸«à¸¡à¸”
                    # (à¸à¸²à¸£à¸£à¸­à¹ƒà¸«à¹‰ timeout à¸‹à¹‰à¸³à¸«à¸¥à¸²à¸¢ batch à¸—à¸³à¹ƒà¸«à¹‰à¹€à¸ªà¸µà¸¢à¹€à¸§à¸¥à¸²à¹€à¸›à¹‡à¸™à¸ˆà¸³à¸™à¸§à¸™à¸¡à¸²à¸)
                    _log_stage("prefetch_registry_batch_timeout", f"batch={batch_number}/{total_batches}")
                    job.message = f"à¸à¸³à¸¥à¸±à¸‡à¹€à¸•à¸£à¸µà¸¢à¸¡à¸‚à¹‰à¸­à¸¡à¸¹à¸¥ Registry... (à¸¢à¸à¹€à¸¥à¸´à¸à¸à¸²à¸£ prefetch à¹€à¸™à¸·à¹ˆà¸­à¸‡à¸ˆà¸²à¸ timeout à¸—à¸µà¹ˆ batch {batch_number})"
                    prefetch_failed = True
                    break
                except Exception as e:
                    _log_stage("prefetch_registry_batch_error", f"batch={batch_number}/{total_batches} err={type(e).__name__}: {e}")
                    job.message = f"à¹€à¸à¸´à¸”à¸‚à¹‰à¸­à¸œà¸´à¸”à¸žà¸¥à¸²à¸”à¸‚à¸“à¸°à¹€à¸•à¸£à¸µà¸¢à¸¡ Registry (batch {batch_number})"
                    prefetch_failed = True
                    break
            # end for batches
            if 'prefetch_failed' in locals() and prefetch_failed:
                _log_stage("prefetch_registry_aborted", f"after batch={batch_number}")
            else:
                _log_stage("prefetch_registry_done", f"keys={len(registry_keys)} batches={total_batches}")
            

    job.progress = 15
    job.message  = "à¸à¸³à¸¥à¸±à¸‡à¸ªà¹à¸à¸™ Security Policy..."
    _log_stage("scan_phase_start", f"checks={len(checks)}")

    try:
        # â”€â”€ à¸ªà¸£à¹‰à¸²à¸‡ scanner à¹„à¸¡à¹ˆà¸•à¹‰à¸­à¸‡à¸ªà¹ˆà¸‡ baseline_config / data_path à¸­à¸µà¸à¹à¸¥à¹‰à¸§ â”€â”€
        from app.core.scan.scanner.security_scanner import SecurityScanner as SecurityBaselineScanner
        scanner = SecurityBaselineScanner(
            executor=executor,
            role=role,
        )
        
        try:
            _log_stage("scanner_run_start")
            score, details = await asyncio.wait_for(
                run_in_threadpool(scanner.run_baseline_scan, checks),  # â† à¸ªà¹ˆà¸‡à¸•à¸±à¸§à¹à¸›à¸£ checks à¹€à¸‚à¹‰à¸²à¹„à¸›à¸•à¸£à¸‡à¹†
                timeout=SCAN_TIMEOUT_SECONDS,
            )
            _log_stage("scanner_run_done", f"score={score} details={len(details)}")
        except asyncio.TimeoutError:
            job.status = "error"
            job.error  = f"Scan timeout à¸«à¸¥à¸±à¸‡à¸ˆà¸²à¸ {SCAN_TIMEOUT_SECONDS}s"
            _log_stage("scanner_run_timeout", f"timeout={SCAN_TIMEOUT_SECONDS}s")
            return

        job.progress = 90
        job.message  = "à¸à¸³à¸¥à¸±à¸‡à¸šà¸±à¸™à¸—à¸¶à¸à¸œà¸¥..."
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
                    details=details,          # à¹€à¸à¹‡à¸š dict à¸„à¸£à¸š metadata
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
        job.message  = "à¹€à¸ªà¸£à¹‡à¸ˆà¸ªà¸´à¹‰à¸™"
        job.result   = {
            "scan_id":       scan_id,
            "target_name":   target_label,
            "version":       version,
            "score":         score,
            "items_scanned": len(details),
            "details":       details,
            "findings":      findings,
            "summary":       finding_summary,
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
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    return {
        "access_token": access_token,
        "token_type":   "bearer",
        "username":     user.username,
        "role":         user.role,
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
        raise HTTPException(status_code=400, detail="à¸£à¸«à¸±à¸ªà¸œà¹ˆà¸²à¸™à¹€à¸”à¸´à¸¡à¹„à¸¡à¹ˆà¸–à¸¹à¸à¸•à¹‰à¸­à¸‡")
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="à¸£à¸«à¸±à¸ªà¸œà¹ˆà¸²à¸™à¹ƒà¸«à¸¡à¹ˆà¸•à¹‰à¸­à¸‡à¸¡à¸µà¸­à¸¢à¹ˆà¸²à¸‡à¸™à¹‰à¸­à¸¢ 6 à¸•à¸±à¸§à¸­à¸±à¸à¸©à¸£")
    current_user.hashed_password = get_password_hash(body.new_password)
    db.add(current_user)
    db.commit()
    return {"ok": True, "message": "à¹€à¸›à¸¥à¸µà¹ˆà¸¢à¸™à¸£à¸«à¸±à¸ªà¸œà¹ˆà¸²à¸™à¸ªà¸³à¹€à¸£à¹‡à¸ˆ"}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    query = db.query(ScanResult)
    if current_user.role != "admin":
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
# Local Scan (à¸ˆà¸¸à¸”à¸—à¸µà¹ˆ 4 - à¹à¸à¹‰à¹„à¸‚ Local Scan à¹€à¸­à¸² resolve_baseline_path à¸­à¸­à¸)
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
# Remote Scan (à¸ˆà¸¸à¸”à¸—à¸µà¹ˆ 4 - à¹à¸à¹‰à¹„à¸‚ Remote Scan à¹€à¸­à¸² resolve_baseline_path à¸­à¸­à¸)
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
        raise HTTPException(status_code=408, detail=f"à¹„à¸¡à¹ˆà¸ªà¸²à¸¡à¸²à¸£à¸–à¹€à¸Šà¸·à¹ˆà¸­à¸¡à¸•à¹ˆà¸­ {req.host}: timeout 15s")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

    if not conn_test["success"]:
        raise HTTPException(
            status_code=400,
            detail=f"à¹„à¸¡à¹ˆà¸ªà¸²à¸¡à¸²à¸£à¸–à¹€à¸Šà¸·à¹ˆà¸­à¸¡à¸•à¹ˆà¸­ {req.host}: {conn_test['message']}"
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
            if current_user.role != "admin" and db_job.user_id != current_user.id:
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
        ScanResult.parent_scan_id == None  # â† à¹€à¸‰à¸žà¸²à¸° top-level
    )
    if current_user.role != "admin":
        query = query.filter(ScanResult.user_id == current_user.id)
    scans = query.order_by(ScanResult.scan_date.desc()).limit(limit).all()
    rows = []
    for s in scans:
        subnet_summary = _subnet_summary_from_details(s.details) if getattr(s, "scan_type", "single") == "subnet" else None
        rows.append({
            "id":            s.id,
            "target_name":   s.target_name,
            "score":         s.score,
            "scan_date":     s.scan_date.isoformat(),
            "version":       s.version or "",
            "hostname":      s.hostname or "",
            "scan_type":     getattr(s, "scan_type", "single"),
            "items_scanned": subnet_summary["items_scanned"] if subnet_summary else len(s.details) if s.details else 0,
            "pass_count":    subnet_summary["pass_count"] if subnet_summary else sum(1 for v in (s.details or {}).values()
                                if isinstance(v, dict) and v.get("status") == "Pass"),
            "fail_count":    subnet_summary["fail_count"] if subnet_summary else sum(1 for v in (s.details or {}).values()
                                if isinstance(v, dict) and str(v.get("status","")).startswith("Fail")),
        })
    return rows


@app.get("/api/scan/history/{scan_id}")
async def get_scan_detail(
    scan_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    query = db.query(ScanResult).filter(ScanResult.id == scan_id)
    if current_user.role != "admin":
        query = query.filter(ScanResult.user_id == current_user.id)
    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="à¹„à¸¡à¹ˆà¸žà¸šà¸œà¸¥à¸à¸²à¸£à¸ªà¹à¸à¸™à¸™à¸µà¹‰à¸«à¸£à¸·à¸­à¹„à¸¡à¹ˆà¸¡à¸µà¸ªà¸´à¸—à¸˜à¸´à¹Œà¹€à¸‚à¹‰à¸²à¸–à¸¶à¸‡")
    role = "Domain Controller" if "Domain Controller" in (scan.target_name or "") else "Member Server"
    if getattr(scan, "scan_type", "single") == "subnet":
        findings = []
        summary = None
    else:
        findings = enrich_scan_details(scan.details, version=scan.version or "", role=role)
        summary = summarize_findings(findings)
    return {
        "id":            scan.id,
        "target_name":   scan.target_name,
        "score":         scan.score,
        "scan_date":     scan.scan_date.isoformat(),
        "version":       scan.version or "",
        "hostname":      scan.hostname or "",
        "scan_type":     getattr(scan, "scan_type", "single"),
        "parent_scan_id": scan.parent_scan_id,
        "items_scanned": len(scan.details) if scan.details else 0,
        "details":       scan.details,
        "findings":      findings,
        "summary":       summary,
    }


@app.delete("/api/scan/history/{scan_id}")
async def delete_scan(
    scan_id:      int,
    db:           Session = Depends(get_db),
    current_user: User    = Depends(get_current_user),
):
    query = db.query(ScanResult).filter(ScanResult.id == scan_id)
    if current_user.role != "admin":
        query = query.filter(ScanResult.user_id == current_user.id)
    scan = query.first()
    if not scan:
        raise HTTPException(status_code=404, detail="à¹„à¸¡à¹ˆà¸žà¸šà¸œà¸¥à¸à¸²à¸£à¸ªà¹à¸à¸™à¸«à¸£à¸·à¸­à¹„à¸¡à¹ˆà¸¡à¸µà¸ªà¸´à¸—à¸˜à¸´à¹Œà¸¥à¸š")
    db.delete(scan)
    db.commit()
    return {"ok": True}


# â”€â”€ à¸ˆà¸¸à¸”à¸—à¸µà¹ˆ 3 - à¹à¸à¹‰à¹„à¸‚à¹€à¸§à¸­à¸£à¹Œà¸Šà¸±à¸™à¹ƒà¸«à¹‰à¸­à¹ˆà¸²à¸™à¸ˆà¸²à¸ /baselines/generated/*.json à¹à¸—à¸™ â”€â”€
@app.get("/api/scan/versions")
async def get_supported_versions(current_user: User = Depends(get_current_user)):
    return list_available_versions()


# ---------------------------------------------------------------------------
# Agent Scan (à¸›à¸£à¸±à¸šà¸•à¸±à¸§à¹à¸›à¸£à¸•à¸²à¸¡à¸ªà¸–à¸²à¸›à¸±à¸•à¸¢à¸à¸£à¸£à¸¡ JSON à¹ƒà¸«à¸¡à¹ˆ)
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
            raise HTTPException(status_code=404, detail=f"à¹„à¸¡à¹ˆà¸žà¸š agent: {req.agent_id}")
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
        child_job.role = req.role
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
    avg_score = int(sum(r.get("score", 0) for r in success) / len(success)) if success else 0

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
        raise HTTPException(status_code=400, detail=f"subnet à¹„à¸¡à¹ˆà¸–à¸¹à¸à¸•à¹‰à¸­à¸‡: {req.subnet}")

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
