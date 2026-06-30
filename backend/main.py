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
from typing import Any

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
from sqlalchemy import func, inspect, text

from app.core.database import SessionLocal, Base, engine, get_database_dialect, mask_database_url
from app.models.user import User
from app.models.scan import ScanResult
from app.models.agent_job import AgentJob
from app.models.scan_schedule import ScanSchedule
from app.models.activity_log import ActivityLog
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
from app.core.scan.scanner.framework_mapping import (
    SCORE_MODEL,
    empty_framework_breakdown,
    normalize_score_breakdown,
)
from app.core.scan.scanner.mappings import (
    AUDIT_SUBCATEGORY_MAP,
    FIREWALL_PROFILE_MAP,
    SECEDIT_KEY_MAP,
    SID_MAP,
    SPECIAL_VALUE_MAP,
    USER_RIGHTS_MAP,
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
from app.core.activity_routes import log_activity, router as activity_router
from app.core.baseline_metadata import enrich_scan_details, resolve_scan_role, summarize_findings

print(f"Database backend: {get_database_dialect()} ({mask_database_url()})")
Base.metadata.create_all(bind=engine)

def _ensure_agent_inventory_columns():
    if engine.dialect.name != "sqlite":
        existing = {column["name"] for column in inspect(engine).get_columns("agent_tokens")}
        if "detected_role" not in existing:
            with engine.begin() as conn:
                conn.execute(text("ALTER TABLE agent_tokens ADD COLUMN detected_role VARCHAR"))
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
        for col in ["os_name", "os_version", "os_build", "os_release", "os_family", "detected_role"]:
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


def _configured_owner_usernames() -> set[str]:
    raw = os.environ.get("OWNER_USERNAMES", "Boat")
    return {item.strip() for item in raw.split(",") if item.strip()}


def _ensure_owner_users():
    owner_usernames = _configured_owner_usernames()
    if not owner_usernames:
        print("[startup] OWNER_USERNAMES is empty; no owner bootstrap applied")
        return

    db = SessionLocal()
    try:
        changed = False
        existing = db.query(User).filter(User.username.in_(owner_usernames)).all()
        found = {user.username for user in existing}
        missing = sorted(owner_usernames - found)
        for owner in existing:
            if owner.role != "owner" or not owner.is_active:
                owner.role = "owner"
                owner.is_active = True
                changed = True
                print(f"[startup] Promoted configured owner: {owner.username}")
        if changed:
            db.commit()
        for username in missing:
            print(f"[startup] Configured owner user not found: {username}")
    finally:
        db.close()


_ensure_owner_users()

app = FastAPI()


def _has_admin_access(user: User) -> bool:
    return user.role in ("admin", "owner")

app.include_router(installer_router)
app.include_router(agent_router)
app.include_router(export_router)
app.include_router(admin_router)
app.include_router(activity_router)

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
    role:      str = Field("auto")

class AgentSubnetScanRequest(BaseModel):
    subnet:  str = Field(..., example="192.168.1.0/24")
    version: str = Field("auto")
    role:    str = Field("auto")

class AutofixRequest(BaseModel):
    check_ids: list[str] = Field(default_factory=list)
    autofix_values: dict[str, str] = Field(default_factory=dict)

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


UNSUPPORTED_AUTOFIX_KEYWORDS = (
    "windows defender",
    "defender",
)

AUDIT_AUTOFIX_VALUES = (
    "Success",
    "Failure",
    "Success and Failure",
    "No Auditing",
)

SERVICE_STARTUP_AUTOFIX_VALUES = (
    "Automatic",
    "Manual",
    "Disabled",
)

FIREWALL_STATE_AUTOFIX_VALUES = (
    "On",
    "Off",
)

SECURITY_POLICY_BOOLEAN_KEYS = {
    "PasswordComplexity",
    "ClearTextPassword",
    "AllowAdministratorLockout",
}

SECURITY_POLICY_NUMERIC_KEYS = {
    "MinimumPasswordLength",
    "MaximumPasswordAge",
    "MinimumPasswordAge",
    "PasswordHistorySize",
    "LockoutDuration",
    "LockoutBadCount",
    "ResetLockoutCount",
}

SAFE_USER_RIGHT_ALIASES = {
    "everyone": "*S-1-1-0",
    "authenticated users": "*S-1-5-11",
    "nt authority\\authenticated users": "*S-1-5-11",
    "enterprise domain controllers": "*S-1-5-9",
    "administrators": "*S-1-5-32-544",
    "builtin\\administrators": "*S-1-5-32-544",
    "users": "*S-1-5-32-545",
    "builtin\\users": "*S-1-5-32-545",
    "guests": "*S-1-5-32-546",
    "builtin\\guests": "*S-1-5-32-546",
    "backup operators": "*S-1-5-32-551",
    "builtin\\backup operators": "*S-1-5-32-551",
    "remote desktop users": "*S-1-5-32-555",
    "builtin\\remote desktop users": "*S-1-5-32-555",
    "local service": "*S-1-5-19",
    "nt authority\\local service": "*S-1-5-19",
    "network service": "*S-1-5-20",
    "nt authority\\network service": "*S-1-5-20",
    "service": "*S-1-5-6",
    "nt authority\\service": "*S-1-5-6",
}
SAFE_USER_RIGHT_ALIASES.update({name.lower(): sid for sid, name in SID_MAP.items()})

BLANK_USER_RIGHT_VALUES = {
    "",
    "no one",
    "no one (blank)",
    "(blank)",
    "blank",
    "none",
    "not defined",
}


def _split_registry_entries(registry_path: str) -> list[dict]:
    entries = []
    normalized_path = re.sub(
        r"\s+(?=(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU|MACHINE|SOFTWARE)\\)",
        ";",
        str(registry_path or "").replace("\r", "\n"),
        flags=re.IGNORECASE,
    )
    for raw_entry in re.split(r"[;\n]+", normalized_path):
        entry = raw_entry.strip()
        if not entry:
            continue
        if "!" in entry:
            path_part, value_name = entry.split("!", 1)
        else:
            last_slash = entry.rfind("\\")
            if last_slash == -1:
                return []
            path_part = entry[:last_slash]
            value_name = entry[last_slash + 1:]
        path_part = path_part.strip()
        value_name = value_name.strip()
        upper = path_part.upper()
        if not value_name:
            return []
        if not (
            upper.startswith("HKLM\\")
            or upper.startswith("HKEY_LOCAL_MACHINE\\")
            or upper.startswith("HKCU\\")
            or upper.startswith("HKEY_CURRENT_USER\\")
            or upper.startswith("MACHINE\\")
            or upper.startswith("SOFTWARE\\")
        ):
            return []
        entries.append({"path": path_part, "value_name": value_name, "raw": entry})
    return entries


def _looks_like_sddl(value: str) -> bool:
    text = str(value or "").strip()
    return bool(re.match(r"^(O:|G:|D:|S:)[A-Za-z0-9:;()]+$", text))


def _parse_named_target_values(expected_value: str) -> dict[str, str]:
    values = {}
    for raw_line in str(expected_value or "").replace("_x000D_", "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("[[[") or "=" not in line:
            continue
        name, value = line.split("=", 1)
        name = name.strip()
        value = value.strip()
        if name and value:
            values[name.lower()] = value
    return values


DEFENDER_VALUE_ALLOWLIST = {
    "puaprotection": {
        "block": "1",
        "enabled": "1",
        "enable": "1",
        "disabled": "0",
    },
    "disableblockatfirstseen": {
        "enabled": "0",
        "enable": "0",
        "disabled": "1",
        "disable": "1",
    },
    "spynetreporting": {
        "advanced maps": "2",
        "basic maps": "1",
        "disabled": "0",
    },
    "submitsamplesconsent": {
        "send safe samples": "1",
        "always prompt": "0",
        "never send": "2",
        "send all samples": "3",
    },
    "enablenetworkprotection": {
        "block": "1",
        "enabled": "1",
        "enable": "1",
        "audit": "2",
        "disabled": "0",
    },
    "mpcloudblocklevel": {
        "high blocking level": "2",
        "high plus": "4",
        "default": "0",
    },
    "disableioavprotection": {
        "enabled": "0",
        "enable": "0",
        "disabled": "1",
    },
    "disablebehaviormonitoring": {
        "enabled": "0",
        "enable": "0",
        "disabled": "1",
    },
    "disablescriptscanning": {
        "enabled": "0",
        "enable": "0",
        "disabled": "1",
    },
    "disableremovabledrivescanning": {
        "enabled": "0",
        "enable": "0",
        "disabled": "1",
    },
    "enablesmartscreen": {
        "enabled": "1",
        "enable": "1",
        "warn and prevent bypass": "1",
        "disabled": "0",
    },
    "shellsmartscreenlevel": {
        "warn and prevent bypass": "Block",
        "warn": "Warn",
        "block": "Block",
    },
    "preventoverride": {
        "enabled": "1",
        "enable": "1",
        "disabled": "0",
    },
    "preventoverrideapprepunknown": {
        "enabled": "1",
        "enable": "1",
        "disabled": "0",
    },
    "enabledv9": {
        "on": "1",
        "enabled": "1",
        "enable": "1",
        "off": "0",
    },
    "2301": {
        "enable": "0",
        "enabled": "0",
        "disable": "3",
        "disabled": "3",
    },
}


def _normalize_registry_value_for_entry(entry: dict, expected_value: str, item: dict) -> tuple[bool, str, str]:
    value_name = str(entry.get("value_name") or "").strip()
    value_key = value_name.lower()
    text = str(expected_value or "").strip()
    named_targets = _parse_named_target_values(text)
    candidate = named_targets.get(value_key, text)
    if value_key in named_targets and "\n" in candidate:
        return False, "", "complex named registry value"

    lower_text = re.sub(r"\s+", " ", text.replace("[[[main setting]]]", "")).strip().lower()
    lower_candidate = re.sub(r"\s+", " ", str(candidate or "").strip()).lower()
    allowlist = DEFENDER_VALUE_ALLOWLIST.get(value_key)
    if allowlist:
        for key in (lower_candidate, lower_text):
            if key in allowlist:
                return True, allowlist[key], ""
            for label, mapped in allowlist.items():
                if label and label in key:
                    return True, mapped, ""
        return False, "", "Defender registry value not allowlisted"

    if value_key in named_targets:
        candidate = named_targets[value_key]
    mapped = SPECIAL_VALUE_MAP.get(str(candidate).strip().lower())
    if mapped is not None:
        return True, str(mapped), ""

    supported_value, reason = _autofix_value_supported(str(candidate))
    if supported_value:
        return True, str(candidate).strip(), ""
    if _looks_like_sddl(str(candidate)) and len(_split_registry_entries(str(item.get("registry_path") or ""))) == 1:
        return True, str(candidate).strip(), ""
    return False, "", reason


def _registry_autofix_entries_for_finding(item: dict) -> tuple[list[dict], str]:
    registry_path = str(item.get("registry_path") or "").strip()
    if not registry_path:
        return [], "no registry path"
    entries = _split_registry_entries(registry_path)
    if not entries:
        return [], "unsupported registry path"

    planned = []
    for entry in entries:
        ok, value, reason = _normalize_registry_value_for_entry(entry, str(item.get("expected_value") or ""), item)
        if not ok:
            return [], reason
        planned.append({
            "path": entry["path"],
            "value_name": entry["value_name"],
            "value": value,
        })
    return planned, ""


def _autofix_value_supported(expected_value: str) -> tuple[bool, str]:
    value = str(expected_value or "").strip()
    if not value:
        return False, "missing expected value"
    lower = value.lower()
    if _looks_like_sddl(value):
        return True, ""
    if "\n" in value or "\r" in value:
        return False, "multi-line expected value"
    if lower.startswith(("enabled:", "disabled:")):
        return False, "structured enabled/disabled value"
    if any(token in value for token in ("{", "}", "[", "]")):
        return False, "structured expected value"
    if ";" in value:
        return False, "multi-value expected value"
    if lower in ("enabled", "enable", "true", "yes", "on", "disabled", "disable", "false", "no", "off"):
        return True, ""
    if value.isdigit():
        return True, ""
    return False, "registry label is not allowlisted"


def _autofix_support_for_finding(item: dict) -> tuple[bool, str]:
    status = str(item.get("status") or "").strip().lower()
    if not status.startswith("fail"):
        return False, "not a failed check"
    haystack = " ".join(str(item.get(k) or "") for k in ("category", "policy_path", "check_name", "source_key")).lower()
    if any(keyword in haystack for keyword in UNSUPPORTED_AUTOFIX_KEYWORDS):
        planned, reason = _registry_autofix_entries_for_finding(item)
        if not planned:
            return False, "Defender command not allowlisted" if reason == "unsupported policy type" else reason
        return True, ""
    planned, reason = _registry_autofix_entries_for_finding(item)
    if not planned:
        return False, reason
    return True, ""


def _is_audit_policy_finding(item: dict) -> bool:
    text = " ".join(str(item.get(k) or "") for k in ("category", "policy_path", "check_name", "source_key")).lower()
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    name = str(item.get("check_name") or item.get("source_key") or "").strip()
    return (
        "advanced audit" in text
        or "audit policy" in text
        or "audit policies" in text
        or str(item.get("category") or "").strip().lower() == "audit policies"
        or name in AUDIT_SUBCATEGORY_MAP
        or str(metadata.get("sheet_type") or "").lower() == "advanced_audit"
    )


def _audit_subcategory_for_finding(item: dict) -> str:
    name = str(item.get("check_name") or item.get("source_key") or "").strip()
    if not name:
        return ""
    return AUDIT_SUBCATEGORY_MAP.get(name, name.replace("Audit ", "", 1).strip())


def _normalize_audit_autofix_value(value: str) -> str:
    normalized = re.sub(r"\s+", " ", str(value or "").strip()).lower()
    aliases = {
        "success": "Success",
        "failure": "Failure",
        "success and failure": "Success and Failure",
        "success/failure": "Success and Failure",
        "success, failure": "Success and Failure",
        "no auditing": "No Auditing",
        "no audit": "No Auditing",
        "none": "No Auditing",
    }
    return aliases.get(normalized, "")


def _normalize_service_startup_value(value: str) -> str:
    normalized = re.sub(r"\s+", " ", str(value or "").strip()).lower()
    aliases = {
        "automatic": "Automatic",
        "auto": "Automatic",
        "manual": "Manual",
        "demand": "Manual",
        "disabled": "Disabled",
        "disable": "Disabled",
    }
    return aliases.get(normalized, "")


def _normalize_firewall_state_value(value: str) -> str:
    normalized = re.sub(r"\s+", " ", str(value or "").strip()).lower()
    aliases = {
        "on": "On",
        "enabled": "On",
        "enable": "On",
        "true": "On",
        "1": "On",
        "off": "Off",
        "disabled": "Off",
        "disable": "Off",
        "false": "Off",
        "0": "Off",
    }
    return aliases.get(normalized, "")


def _security_policy_key_for_finding(item: dict) -> str:
    name = str(item.get("check_name") or item.get("source_key") or "").strip()
    if not name:
        return ""
    if name in SECEDIT_KEY_MAP:
        return SECEDIT_KEY_MAP[name]
    normalized_name = re.sub(r"\s+", " ", name).strip().lower()
    for label, key in SECEDIT_KEY_MAP.items():
        if re.sub(r"\s+", " ", label).strip().lower() == normalized_name:
            return key
    return ""


def _normalize_security_policy_value(policy_key: str, value: str) -> str:
    text = str(value or "").strip()
    if not policy_key or not text:
        return ""
    mapped = SPECIAL_VALUE_MAP.get(text.lower())
    if mapped is not None:
        text = str(mapped)
    normalized = re.sub(r"\s+", " ", text).strip().lower()
    boolean_aliases = {
        "enabled": "1",
        "enable": "1",
        "true": "1",
        "yes": "1",
        "on": "1",
        "disabled": "0",
        "disable": "0",
        "false": "0",
        "no": "0",
        "off": "0",
    }
    if policy_key in SECURITY_POLICY_BOOLEAN_KEYS:
        if normalized in boolean_aliases:
            return boolean_aliases[normalized]
        if normalized in ("0", "1"):
            return normalized
        return ""
    if policy_key in SECURITY_POLICY_NUMERIC_KEYS:
        return text if re.fullmatch(r"-?\d+", text) else ""
    return ""


def _is_zero_lockout_threshold(value: str) -> bool:
    text = str(value or "").strip().lower()
    return text in ("", "0", "never", "not configured", "none")


def _autofix_payload_order(item: dict) -> tuple[int, str]:
    if item.get("fix_type") == "security_policy":
        key = item.get("security_policy_key") or ""
        if key == "LockoutBadCount":
            return (0, str(item.get("check_id") or ""))
        if key == "ResetLockoutCount":
            return (1, str(item.get("check_id") or ""))
        if key == "LockoutDuration":
            return (2, str(item.get("check_id") or ""))
    return (5, str(item.get("check_id") or ""))


def _is_security_policy_finding(item: dict) -> bool:
    if not str(item.get("status") or "").strip().lower().startswith("fail"):
        return False
    haystack = " ".join(str(item.get(k) or "") for k in ("category", "policy_path", "check_name", "source_key")).lower()
    if "password policy" not in haystack and "account lockout" not in haystack:
        return False
    policy_key = _security_policy_key_for_finding(item)
    if not policy_key:
        return False
    return bool(_normalize_security_policy_value(policy_key, str(item.get("expected_value") or "")))


def _user_right_privilege_for_finding(item: dict) -> str:
    name = str(item.get("check_name") or item.get("source_key") or "").strip()
    if not name:
        return ""
    if name in USER_RIGHTS_MAP:
        return USER_RIGHTS_MAP[name]
    normalized_name = re.sub(r"\s+", " ", name).strip().lower()
    for label, privilege in USER_RIGHTS_MAP.items():
        if re.sub(r"\s+", " ", label).strip().lower() == normalized_name:
            return privilege
    return ""


def _parse_user_right_accounts(value: str) -> tuple[list[str], str]:
    text = str(value or "").strip()
    normalized = re.sub(r"\s+", " ", text).strip().lower()
    if normalized in BLANK_USER_RIGHT_VALUES:
        return [], ""
    if not text:
        return [], ""
    if "\n" in text or "\r" in text:
        return [], "multi-line user-right value"
    if any(token in text for token in ("{", "}", "[", "]")):
        return [], "structured user-right value"
    if re.search(r"\bor\b", normalized):
        return [], "ambiguous user-right value"

    tokens = [
        token.strip().strip('"').strip("'")
        for token in re.split(r"\s*(?:,|;|\|)\s*", text)
        if token.strip().strip('"').strip("'")
    ]
    accounts = []
    for token in tokens:
        token_key = token.lower()
        if token.startswith("*S-"):
            accounts.append(token)
            continue
        sid = SAFE_USER_RIGHT_ALIASES.get(token_key)
        if not sid:
            return [], f"account cannot be resolved: {token}"
        accounts.append(sid)
    return accounts, ""


def _is_user_rights_finding(item: dict) -> bool:
    if not str(item.get("status") or "").strip().lower().startswith("fail"):
        return False
    haystack = " ".join(str(item.get(k) or "") for k in ("category", "policy_path", "check_name", "source_key")).lower()
    if "user rights" not in haystack and "user rights assignment" not in haystack:
        return False
    privilege = _user_right_privilege_for_finding(item)
    if not privilege:
        return False
    _accounts, reason = _parse_user_right_accounts(str(item.get("expected_value") or ""))
    return not reason


def _normalize_fix_job_type(value: str) -> str:
    text = str(value or "").strip().lower()
    return text if text in ("autofix", "rollback") else ""


def _is_service_startup_finding(item: dict) -> bool:
    if not str(item.get("status") or "").strip().lower().startswith("fail"):
        return False
    source = item.get("source") if isinstance(item.get("source"), dict) else {}
    sheet_type = str(source.get("sheet_type") or "").lower()
    row_type = str(source.get("row_type") or "Services").strip().lower()
    expected = _normalize_service_startup_value(str(item.get("expected_value") or ""))
    if sheet_type == "services" and row_type != "scheduled task" and expected:
        return True
    if (
        not item.get("registry_path")
        and expected
        and str(item.get("category") or "").lower() == "services & features"
        and str(item.get("policy_path") or "").lower() in ("", "system services")
    ):
        return True
    return False


def _firewall_profile_for_finding(item: dict) -> str:
    source = item.get("source") if isinstance(item.get("source"), dict) else {}
    sheet_type = str(source.get("sheet_type") or "").lower()
    category = str(item.get("category") or "").lower()
    check_name = str(item.get("check_name") or item.get("source_key") or "").strip()
    if sheet_type != "firewall" and "firewall" not in category:
        return ""
    if check_name.lower() != "firewall state":
        return ""
    policy_path = str(item.get("policy_path") or "").strip()
    profile_name = policy_path.split("\\", 1)[0].strip()
    return FIREWALL_PROFILE_MAP.get(profile_name, "")


def _is_firewall_state_finding(item: dict) -> bool:
    if not str(item.get("status") or "").strip().lower().startswith("fail"):
        return False
    return bool(_firewall_profile_for_finding(item) and _normalize_firewall_state_value(str(item.get("expected_value") or "")))


def _rollback_support_for_result(row: dict) -> tuple[bool, str]:
    if not isinstance(row, dict) or row.get("status") != "done":
        return False, "only successful fixes can be rolled back"
    fix_type = str(row.get("fix_type") or "registry")
    old_value = str(row.get("old_value") or "").strip()
    if fix_type == "registry":
        if not row.get("registry_path") or not old_value:
            return False, "missing registry rollback data"
        return True, ""
    if fix_type in ("registry_multi", "defender_registry"):
        if (row.get("registry_path") or row.get("registry_entries")) and old_value:
            return True, ""
        return False, "missing registry rollback data"
    if fix_type == "service_startup":
        if _normalize_service_startup_value(old_value):
            return True, ""
        return False, "service old value is not a supported startup type"
    if fix_type == "audit_policy":
        if _normalize_audit_autofix_value(old_value):
            return True, ""
        return False, "audit old value is not parseable"
    if fix_type == "firewall_profile":
        if _normalize_firewall_state_value(old_value):
            return True, ""
        return False, "firewall old value is not parseable"
    if fix_type == "security_policy":
        if row.get("security_policy_key") and old_value:
            return True, ""
        return False, "missing security policy rollback data"
    if fix_type == "user_rights":
        if row.get("privilege_name") and old_value is not None:
            return True, ""
        return False, "missing user-right rollback data"
    return False, "unsupported rollback type"


def _summarize_fix_job(row: AgentJob, requested_by: str = "") -> dict:
    payload = row.payload or {}
    result = row.result or {}
    job_type = _normalize_fix_job_type(result.get("job_type") or payload.get("job_type"))
    results = result.get("autofix_results") or []
    normalized_results = []
    rollback_supported = bool(results)
    rollback_reason = ""
    for item in results:
        item = dict(item or {})
        supported, reason = _rollback_support_for_result(item)
        item["rollback_supported"] = supported
        item["rollback_reason"] = reason
        normalized_results.append(item)
        if not supported:
            rollback_supported = False
            rollback_reason = reason
    return {
        "job_id": row.job_id,
        "job_type": job_type,
        "scan_id": result.get("scan_id") or payload.get("scan_id"),
        "agent_id": row.agent_id,
        "requested_by": requested_by or str(result.get("requested_by") or payload.get("requested_by") or row.user_id or ""),
        "status": row.status,
        "error": row.error or result.get("error") or "",
        "created_at": row.created_at.isoformat() if row.created_at else "",
        "completed_at": row.completed_at.isoformat() if row.completed_at else result.get("completed_at", ""),
        "total": len(normalized_results),
        "success_count": sum(1 for item in normalized_results if item.get("status") == "done"),
        "failed_count": sum(1 for item in normalized_results if item.get("status") != "done"),
        "rollback_supported": rollback_supported and job_type == "autofix" and row.status == "done",
        "rollback_reason": "" if rollback_supported else rollback_reason,
        "results": normalized_results,
    }


def _find_fix_jobs_for_scan(db: Session, scan_id: int, current_user: User) -> list[AgentJob]:
    query = db.query(AgentJob).order_by(AgentJob.created_at.desc())
    if not _has_admin_access(current_user):
        query = query.filter(AgentJob.user_id == current_user.id)
    rows = []
    for row in query.all():
        payload = row.payload or {}
        result = row.result or {}
        job_type = _normalize_fix_job_type(result.get("job_type") or payload.get("job_type"))
        if job_type not in ("autofix", "rollback"):
            continue
        if str(result.get("scan_id") or payload.get("scan_id") or "") != str(scan_id):
            continue
        rows.append(row)
    return rows


def _account_lockout_dependency_metadata(policy_key: str) -> dict:
    if policy_key == "LockoutBadCount":
        return {
            "autofix_group": "account_lockout",
            "autofix_group_label": "Account Lockout",
            "autofix_step": 1,
            "autofix_depends_on": [],
            "autofix_dependency_note": "Run this first. Duration and reset window depend on the threshold being enabled.",
        }
    if policy_key == "ResetLockoutCount":
        return {
            "autofix_group": "account_lockout",
            "autofix_group_label": "Account Lockout",
            "autofix_step": 2,
            "autofix_depends_on": [],
            "autofix_dependency_note": "Requires Account lockout threshold first. Select Step 1 together with this item.",
        }
    if policy_key == "LockoutDuration":
        return {
            "autofix_group": "account_lockout",
            "autofix_group_label": "Account Lockout",
            "autofix_step": 3,
            "autofix_depends_on": [],
            "autofix_dependency_note": "Run after threshold and reset window. Select Step 1 and Step 2 together with this item.",
        }
    return {}


def _security_policy_tool_for_key(policy_key: str) -> str:
    if policy_key in {
        "MinimumPasswordLength",
        "MaximumPasswordAge",
        "MinimumPasswordAge",
        "PasswordHistorySize",
        "LockoutDuration",
        "LockoutBadCount",
        "ResetLockoutCount",
    }:
        return "net accounts"
    return "secedit"


def _autofix_metadata_for_finding(item: dict) -> dict:
    supported, reason = _autofix_support_for_finding(item)
    if supported:
        registry_entries, _registry_reason = _registry_autofix_entries_for_finding(item)
        is_defender = "defender" in " ".join(str(item.get(k) or "") for k in ("category", "policy_path", "check_name", "source_key")).lower()
        action = "defender_registry" if is_defender else ("registry_multi" if len(registry_entries) > 1 else "registry")
        return {
            "autofix_supported": True,
            "autofix_reason": "",
            "autofix_action": action,
            "autofix_needs_input": False,
            "autofix_allowed_values": [],
            "autofix_default_value": "",
            "autofix_registry_entries": registry_entries,
        }

    if str(item.get("status") or "").strip().lower().startswith("fail") and _is_audit_policy_finding(item):
        subcategory = _audit_subcategory_for_finding(item)
        default_value = _normalize_audit_autofix_value(str(item.get("expected_value") or ""))
        if not subcategory:
            return {
                "autofix_supported": False,
                "autofix_reason": "missing audit subcategory",
                "autofix_action": "",
                "autofix_needs_input": False,
                "autofix_allowed_values": [],
                "autofix_default_value": "",
            }
        return {
            "autofix_supported": True,
            "autofix_reason": "",
            "autofix_action": "audit_policy",
            "autofix_needs_input": not bool(default_value),
            "autofix_allowed_values": [] if default_value else list(AUDIT_AUTOFIX_VALUES),
            "autofix_default_value": default_value or "Success",
            "autofix_subcategory": subcategory,
        }

    if _is_security_policy_finding(item):
        policy_key = _security_policy_key_for_finding(item)
        value = _normalize_security_policy_value(policy_key, str(item.get("expected_value") or ""))
        return {
            "autofix_supported": True,
            "autofix_reason": "",
            "autofix_action": "security_policy",
            "autofix_needs_input": False,
            "autofix_allowed_values": [],
            "autofix_default_value": value,
            "autofix_security_policy_key": policy_key,
            "autofix_tool": _security_policy_tool_for_key(policy_key),
            **_account_lockout_dependency_metadata(policy_key),
        }

    if str(item.get("status") or "").strip().lower().startswith("fail"):
        haystack = " ".join(str(item.get(k) or "") for k in ("category", "policy_path", "check_name", "source_key")).lower()
        if "password policy" in haystack or "account lockout" in haystack:
            policy_key = _security_policy_key_for_finding(item)
            policy_value = _normalize_security_policy_value(policy_key, str(item.get("expected_value") or ""))
            return {
                "autofix_supported": False,
                "autofix_reason": "security policy key not allowlisted" if not policy_key else "security policy value is not allowlisted",
                "autofix_action": "",
                "autofix_needs_input": False,
                "autofix_allowed_values": [],
                "autofix_default_value": policy_value,
            }

    if _is_user_rights_finding(item):
        privilege = _user_right_privilege_for_finding(item)
        accounts, _reason = _parse_user_right_accounts(str(item.get("expected_value") or ""))
        return {
            "autofix_supported": True,
            "autofix_reason": "",
            "autofix_action": "user_rights",
            "autofix_needs_input": False,
            "autofix_allowed_values": [],
            "autofix_default_value": ",".join(accounts),
            "autofix_privilege_name": privilege,
            "autofix_privilege_accounts": accounts,
            "autofix_tool": "secedit",
        }

    if str(item.get("status") or "").strip().lower().startswith("fail"):
        haystack = " ".join(str(item.get(k) or "") for k in ("category", "policy_path", "check_name", "source_key")).lower()
        if "user rights" in haystack or "user rights assignment" in haystack:
            privilege = _user_right_privilege_for_finding(item)
            _accounts, user_right_reason = _parse_user_right_accounts(str(item.get("expected_value") or ""))
            return {
                "autofix_supported": False,
                "autofix_reason": "user-right privilege not allowlisted" if not privilege else (user_right_reason or "complex user-right assignment"),
                "autofix_action": "",
                "autofix_needs_input": False,
                "autofix_allowed_values": [],
                "autofix_default_value": "",
            }

    if _is_service_startup_finding(item):
        default_value = _normalize_service_startup_value(str(item.get("expected_value") or ""))
        service_name = str(item.get("check_name") or item.get("source_key") or "").strip()
        if not service_name:
            return {
                "autofix_supported": False,
                "autofix_reason": "missing service name",
                "autofix_action": "",
                "autofix_needs_input": False,
                "autofix_allowed_values": [],
                "autofix_default_value": "",
            }
        return {
            "autofix_supported": True,
            "autofix_reason": "",
            "autofix_action": "service_startup",
            "autofix_needs_input": True,
            "autofix_allowed_values": list(SERVICE_STARTUP_AUTOFIX_VALUES),
            "autofix_default_value": default_value or "Disabled",
            "autofix_service_name": service_name,
        }

    if _is_firewall_state_finding(item):
        default_value = _normalize_firewall_state_value(str(item.get("expected_value") or ""))
        return {
            "autofix_supported": True,
            "autofix_reason": "",
            "autofix_action": "firewall_profile",
            "autofix_needs_input": not bool(default_value),
            "autofix_allowed_values": [] if default_value else list(FIREWALL_STATE_AUTOFIX_VALUES),
            "autofix_default_value": default_value or "On",
            "autofix_firewall_profile": _firewall_profile_for_finding(item),
        }

    return {
        "autofix_supported": False,
        "autofix_reason": reason,
        "autofix_action": "",
        "autofix_needs_input": False,
        "autofix_allowed_values": [],
        "autofix_default_value": "",
    }


def _annotate_autofix_support(findings: list[dict]) -> list[dict]:
    annotated = []
    for item in findings:
        row = dict(item)
        row.update(_autofix_metadata_for_finding(item))
        policy_key = _security_policy_key_for_finding(row)
        dependency_metadata = _account_lockout_dependency_metadata(policy_key)
        for key, value in dependency_metadata.items():
            row.setdefault(key, value)
        if policy_key and not row.get("autofix_security_policy_key"):
            row["autofix_security_policy_key"] = policy_key
        annotated.append(row)
    account_lockout_threshold_id = ""
    account_lockout_reset_id = ""
    for row in annotated:
        if row.get("autofix_group") == "account_lockout" and row.get("autofix_security_policy_key") == "LockoutBadCount":
            account_lockout_threshold_id = str(row.get("check_id") or row.get("source_key") or row.get("check_name") or "").strip()
        if row.get("autofix_group") == "account_lockout" and row.get("autofix_security_policy_key") == "ResetLockoutCount":
            account_lockout_reset_id = str(row.get("check_id") or row.get("source_key") or row.get("check_name") or "").strip()
    dependencies_for_duration = [item for item in (account_lockout_threshold_id, account_lockout_reset_id) if item]
    if account_lockout_threshold_id:
        for row in annotated:
            if row.get("autofix_group") == "account_lockout" and row.get("autofix_security_policy_key") == "ResetLockoutCount":
                row["autofix_depends_on"] = [account_lockout_threshold_id]
            if row.get("autofix_group") == "account_lockout" and row.get("autofix_security_policy_key") == "LockoutDuration":
                row["autofix_depends_on"] = dependencies_for_duration
    return annotated


def _find_agent_for_scan(scan: ScanResult, db: Session) -> AgentToken | None:
    hostname = (scan.hostname or "").strip()
    target_name = (scan.target_name or "").strip()
    candidates = []
    for value in (hostname, target_name):
        if value and value not in candidates:
            candidates.append(value)
    for value in candidates:
        agent = db.query(AgentToken).filter(AgentToken.agent_id == value).first()
        if agent:
            return agent
        agent = db.query(AgentToken).filter(AgentToken.hostname == value).first()
        if agent:
            return agent
    if target_name:
        prefix = target_name.split(" (", 1)[0].strip()
        if prefix:
            agent = db.query(AgentToken).filter(AgentToken.hostname == prefix).first()
            if agent:
                return agent
    if scan.parent_scan_id:
        jobs = (
            db.query(AgentJob)
            .filter(AgentJob.parent_scan_id == scan.parent_scan_id)
            .order_by(AgentJob.updated_at.desc())
            .all()
        )
        for job in jobs:
            result = job.result or {}
            if str(result.get("scan_id") or "") == str(scan.id):
                agent = db.query(AgentToken).filter(AgentToken.agent_id == job.agent_id).first()
                if agent:
                    return agent
    return None


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
    return normalize_score_breakdown(details.get("_score_breakdown"))


def _aggregate_score_breakdowns(results: list[dict]) -> tuple[int, dict | None]:
    passed = failed = total = excluded_manual = excluded_na = 0
    severity_failed = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    framework_breakdown = empty_framework_breakdown()
    for row in results:
        breakdown = row.get("score_breakdown") if isinstance(row, dict) else None
        breakdown = normalize_score_breakdown(breakdown)
        if not breakdown:
            continue
        passed += int(breakdown.get("passed_assessed_count", 0) or 0)
        failed += int(breakdown.get("failed_assessed_count", 0) or 0)
        total += int(breakdown.get("total_assessed_count", 0) or 0)
        excluded_manual += int(breakdown.get("excluded_manual_count", 0) or 0)
        excluded_na += int(breakdown.get("excluded_na_count", 0) or 0)
        for sev in severity_failed:
            severity_failed[sev] += int((breakdown.get("severity_failed") or {}).get(sev, 0))
        for family in ("nist", "cis"):
            source_family = (breakdown.get("framework_breakdown") or {}).get(family) or {}
            for code, values in source_family.items():
                target = framework_breakdown[family].setdefault(
                    code,
                    {
                        "passed_assessed_count": 0,
                        "failed_assessed_count": 0,
                        "total_assessed_count": 0,
                        "severity_failed": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                    },
                )
                target["passed_assessed_count"] += int(values.get("passed_assessed_count", 0) or 0)
                target["failed_assessed_count"] += int(values.get("failed_assessed_count", 0) or 0)
                target["total_assessed_count"] += int(values.get("total_assessed_count", 0) or 0)
                for sev in target["severity_failed"]:
                    target["severity_failed"][sev] += int((values.get("severity_failed") or {}).get(sev, 0) or 0)

    if total <= 0:
        return 0, None
    score = int((passed / total) * 100)
    return score, {
        "model": SCORE_MODEL,
        "passed_assessed_count": passed,
        "failed_assessed_count": failed,
        "total_assessed_count": total,
        "excluded_manual_count": excluded_manual,
        "excluded_na_count": excluded_na,
        "severity_failed": severity_failed,
        "framework_breakdown": framework_breakdown,
    }


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
    aggregate_passed = 0
    aggregate_failed = 0
    aggregate_total = 0
    aggregate_manual_excluded = 0
    aggregate_na_excluded = 0
    aggregate_severity_failed = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    aggregate_framework_breakdown = empty_framework_breakdown()
    for child in children:
        counts = _scan_counts_from_details(child.details)
        pass_count += counts["pass_count"]
        fail_count += counts["fail_count"]
        critical_count += counts["critical_count"]
        high_count += counts["high_count"]
        breakdown = _score_breakdown_from_details(child.details)
        if breakdown:
            aggregate_passed += breakdown["passed_assessed_count"]
            aggregate_failed += breakdown["failed_assessed_count"]
            aggregate_total += breakdown["total_assessed_count"]
            aggregate_manual_excluded += breakdown["excluded_manual_count"]
            aggregate_na_excluded += breakdown.get("excluded_na_count", 0)
            for sev in aggregate_severity_failed:
                aggregate_severity_failed[sev] += int((breakdown.get("severity_failed") or {}).get(sev, 0))
            for family in ("nist", "cis"):
                for code, values in ((breakdown.get("framework_breakdown") or {}).get(family) or {}).items():
                    target = aggregate_framework_breakdown[family].setdefault(
                        code,
                        {
                            "passed_assessed_count": 0,
                            "failed_assessed_count": 0,
                            "total_assessed_count": 0,
                            "severity_failed": {"critical": 0, "high": 0, "medium": 0, "low": 0},
                        },
                    )
                    target["passed_assessed_count"] += int(values.get("passed_assessed_count", 0) or 0)
                    target["failed_assessed_count"] += int(values.get("failed_assessed_count", 0) or 0)
                    target["total_assessed_count"] += int(values.get("total_assessed_count", 0) or 0)
                    for sev in target["severity_failed"]:
                        target["severity_failed"][sev] += int((values.get("severity_failed") or {}).get(sev, 0) or 0)
        if counts["fail_count"] > 0 or (child.score or 0) < 100:
            failed_host_count += 1
        if child.score is not None:
            score_total += int(child.score or 0)
            scored += 1

    score = (
        int((aggregate_passed / aggregate_total) * 100)
        if aggregate_total > 0
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
            "model": SCORE_MODEL,
            "passed_assessed_count": aggregate_passed,
            "failed_assessed_count": aggregate_failed,
            "total_assessed_count": aggregate_total,
            "excluded_manual_count": aggregate_manual_excluded,
            "excluded_na_count": aggregate_na_excluded,
            "severity_failed": aggregate_severity_failed,
            "framework_breakdown": aggregate_framework_breakdown,
        } if aggregate_total > 0 else None,
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
    job.role = "auto"
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
        role = resolve_scan_role(c.details, target_name=c.target_name or "")
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
            "detected_role": role,
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
    db = SessionLocal()
    try:
        log_activity(
            db,
            actor=current_user,
            action="scan_started",
            target_type="subnet",
            target_id=job_id,
            detail={"version": req.version, "role": req.role, "subnet": req.subnet, "total_hosts": len(hosts)},
        )
    finally:
        db.close()
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
            log_activity(
                db,
                action="login",
                target_type="user",
                target_id=form_data.username,
                status_value="failed",
                detail={"reason": "invalid_credentials"},
            )
            raise HTTPException(status_code=400, detail="Username or password incorrect")
        if not user.is_active:
            log_activity(
                db,
                actor=user,
                action="login",
                target_type="user",
                target_id=user.username,
                status_value="failed",
                detail={"reason": "inactive_account"},
            )
            raise HTTPException(status_code=403, detail="User account is inactive")
    access_token = create_access_token(data={"sub": user.username, "role": user.role})
    log_activity(
        db,
        actor=user,
        action="login",
        target_type="user",
        target_id=user.username,
        status_value="success",
        detail={"auth_provider": AUTH_PROVIDER},
    )
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
    db = SessionLocal()
    try:
        log_activity(
            db,
            actor=current_user,
            action="scan_started",
            target_type="local",
            target_id=job_id,
            detail={"version": req.version, "target": target_label},
        )
    finally:
        db.close()
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
    db = SessionLocal()
    try:
        log_activity(
            db,
            actor=current_user,
            action="scan_started",
            target_type="remote",
            target_id=job_id,
            detail={"version": req.version, "role": req.role, "target": target_label, "host": req.host},
        )
    finally:
        db.close()
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
                    result = dict(db_job.result or {})
                    if isinstance(result.get("findings"), list):
                        result["findings"] = _annotate_autofix_support(result["findings"])
                    resp["result"] = result
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
        result = dict(job.result or {})
        if isinstance(result.get("findings"), list):
            result["findings"] = _annotate_autofix_support(result["findings"])
        resp["result"] = result
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
    role = resolve_scan_role(scan.details, target_name=scan.target_name or "")
    if getattr(scan, "scan_type", "single") == "subnet":
        findings = []
        summary = _subnet_summary_from_children(scan, db, current_user)
    else:
        findings = enrich_scan_details(scan.details, version=scan.version or "", role=role)
        findings = _annotate_autofix_support(findings)
        summary = summarize_findings(findings)
    count_summary = summary if getattr(scan, "scan_type", "single") == "subnet" else _scan_counts_from_details(scan.details)
    score_breakdown = (
        count_summary.get("score_breakdown")
        if isinstance(count_summary, dict) and getattr(scan, "scan_type", "single") == "subnet"
        else _score_breakdown_from_details(scan.details)
    )
    matched_agent = None if getattr(scan, "scan_type", "single") == "subnet" else _find_agent_for_scan(scan, db)
    return {
        "id":            scan.id,
        "target_name":   scan.target_name,
        "score":         count_summary.get("score", scan.score) if isinstance(count_summary, dict) else scan.score,
        "scan_date":     scan.scan_date.isoformat(),
        "version":       scan.version or "",
        "detected_role": role if getattr(scan, "scan_type", "single") != "subnet" else "",
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
        "agent_id":      matched_agent.agent_id if matched_agent else "",
    }


@app.post("/api/scan/history/{scan_id}/autofix")
async def create_scan_autofix_job(
    scan_id: int,
    body: AutofixRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not _has_admin_access(current_user):
        raise HTTPException(status_code=403, detail="Admin permission required")
    requested_ids = [str(item).strip() for item in (body.check_ids or []) if str(item).strip()]
    if not requested_ids:
        raise HTTPException(status_code=400, detail="Select at least one check")

    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    if getattr(scan, "scan_type", "single") != "single":
        raise HTTPException(status_code=400, detail="Autofix supports single agent reports only")

    agent = _find_agent_for_scan(scan, db)
    if not agent:
        raise HTTPException(status_code=400, detail="Unable to match this scan to a registered agent")

    role = resolve_scan_role(scan.details, target_name=scan.target_name or "")
    findings = _annotate_autofix_support(enrich_scan_details(scan.details, version=scan.version or "", role=role))
    by_id = {}
    for item in findings:
        keys = [
            str(item.get("check_id") or "").strip(),
            str(item.get("source_key") or "").strip(),
            str(item.get("check_name") or "").strip(),
        ]
        for key in keys:
            if key:
                by_id[key] = item

    selected = []
    rejected = []
    requested_values = body.autofix_values or {}
    for check_id in requested_ids:
        item = by_id.get(check_id)
        if not item:
            rejected.append({"check_id": check_id, "reason": "check not found in scan"})
            continue
        if not item.get("autofix_supported"):
            rejected.append({"check_id": check_id, "reason": item.get("autofix_reason") or "unsupported check"})
            continue
        selected_item = {
            "check_id": item.get("check_id") or item.get("source_key") or check_id,
            "check_name": item.get("check_name") or item.get("source_key") or check_id,
            "category": item.get("category") or "General",
            "registry_path": item.get("registry_path") or "",
            "expected_value": item.get("expected_value") or "",
            "current_value": item.get("current_value") or "",
            "severity": item.get("severity") or "",
            "fix_type": item.get("autofix_action") or "registry",
        }
        if selected_item["fix_type"] in ("registry", "registry_multi", "defender_registry"):
            registry_entries = item.get("autofix_registry_entries")
            if not isinstance(registry_entries, list):
                registry_entries, registry_reason = _registry_autofix_entries_for_finding(item)
            else:
                registry_reason = ""
            if registry_reason or not registry_entries:
                rejected.append({"check_id": check_id, "reason": registry_reason or "unsupported registry value"})
                continue
            selected_item["registry_entries"] = registry_entries
        if selected_item["fix_type"] == "audit_policy":
            value_key = selected_item["check_id"]
            raw_value = requested_values.get(value_key) or requested_values.get(check_id) or item.get("autofix_default_value") or item.get("expected_value")
            audit_value = _normalize_audit_autofix_value(str(raw_value or ""))
            if not audit_value:
                rejected.append({"check_id": check_id, "reason": "invalid audit policy value"})
                continue
            selected_item["audit_value"] = audit_value
            selected_item["audit_subcategory"] = item.get("autofix_subcategory") or _audit_subcategory_for_finding(item)
            selected_item["expected_value"] = audit_value
        elif selected_item["fix_type"] == "service_startup":
            value_key = selected_item["check_id"]
            raw_value = requested_values.get(value_key) or requested_values.get(check_id) or item.get("autofix_default_value") or item.get("expected_value")
            startup_value = _normalize_service_startup_value(str(raw_value or ""))
            if not startup_value:
                rejected.append({"check_id": check_id, "reason": "invalid service startup value"})
                continue
            selected_item["service_name"] = item.get("autofix_service_name") or item.get("check_name") or item.get("source_key") or check_id
            selected_item["startup_type"] = startup_value
            selected_item["expected_value"] = startup_value
        elif selected_item["fix_type"] == "firewall_profile":
            value_key = selected_item["check_id"]
            raw_value = requested_values.get(value_key) or requested_values.get(check_id) or item.get("autofix_default_value") or item.get("expected_value")
            firewall_state = _normalize_firewall_state_value(str(raw_value or ""))
            firewall_profile = item.get("autofix_firewall_profile") or _firewall_profile_for_finding(item)
            if not firewall_state:
                rejected.append({"check_id": check_id, "reason": "invalid firewall state"})
                continue
            if not firewall_profile:
                rejected.append({"check_id": check_id, "reason": "missing firewall profile"})
                continue
            selected_item["firewall_profile"] = firewall_profile
            selected_item["firewall_state"] = firewall_state
            selected_item["expected_value"] = firewall_state
        elif selected_item["fix_type"] == "security_policy":
            policy_key = item.get("autofix_security_policy_key") or _security_policy_key_for_finding(item)
            policy_value = _normalize_security_policy_value(policy_key, str(item.get("autofix_default_value") or item.get("expected_value") or ""))
            if not policy_key:
                rejected.append({"check_id": check_id, "reason": "missing security policy key"})
                continue
            if not policy_value:
                rejected.append({"check_id": check_id, "reason": "security policy value is not allowlisted"})
                continue
            selected_item["security_policy_key"] = policy_key
            selected_item["security_policy_value"] = policy_value
            selected_item["expected_value"] = policy_value
        elif selected_item["fix_type"] == "user_rights":
            privilege_name = item.get("autofix_privilege_name") or _user_right_privilege_for_finding(item)
            accounts = item.get("autofix_privilege_accounts")
            if not isinstance(accounts, list):
                accounts, parse_reason = _parse_user_right_accounts(str(item.get("expected_value") or ""))
            else:
                parse_reason = ""
            if not privilege_name:
                rejected.append({"check_id": check_id, "reason": "missing user-right privilege"})
                continue
            if parse_reason:
                rejected.append({"check_id": check_id, "reason": parse_reason})
                continue
            selected_item["privilege_name"] = privilege_name
            selected_item["privilege_accounts"] = accounts
            selected_item["expected_value"] = ",".join(accounts)
        selected.append(selected_item)

    selected_policy_keys = {
        item.get("security_policy_key")
        for item in selected
        if item.get("fix_type") == "security_policy"
    }
    threshold_finding = next(
        (
            item
            for item in findings
            if _security_policy_key_for_finding(item) == "LockoutBadCount"
        ),
        None,
    )
    threshold_status = str((threshold_finding or {}).get("status") or "").strip().lower()
    threshold_is_zero = threshold_status.startswith("fail") and _is_zero_lockout_threshold((threshold_finding or {}).get("current_value") or "")
    if threshold_is_zero and "LockoutBadCount" not in selected_policy_keys:
        dependency_filtered = []
        for item in selected:
            if item.get("fix_type") == "security_policy" and item.get("security_policy_key") in ("LockoutDuration", "ResetLockoutCount"):
                rejected.append({
                    "check_id": item.get("check_id") or "",
                    "reason": "Account lockout threshold is currently Never/0; select Account lockout threshold with this check",
                })
                continue
            dependency_filtered.append(item)
        selected = dependency_filtered

    selected_ids = {str(item.get("check_id") or "").strip() for item in selected}
    dependency_filtered = []
    for item in selected:
        source_item = by_id.get(str(item.get("check_id") or "").strip()) or {}
        missing_dependencies = []
        for dep_id in source_item.get("autofix_depends_on") or []:
            dep_item = by_id.get(str(dep_id).strip()) or {}
            dep_status = str(dep_item.get("status") or "").strip().lower()
            dep_key = str(dep_item.get("check_id") or dep_item.get("source_key") or dep_item.get("check_name") or dep_id).strip()
            if dep_status.startswith("fail") and dep_key not in selected_ids:
                missing_dependencies.append(dep_item.get("check_name") or dep_key)
        if missing_dependencies:
            rejected.append({
                "check_id": item.get("check_id") or "",
                "reason": f"Select required checks first: {', '.join(missing_dependencies)}",
            })
            continue
        dependency_filtered.append(item)
    selected = dependency_filtered

    if not selected:
        raise HTTPException(
            status_code=400,
            detail={"message": "No selected checks are supported for autofix", "rejected": rejected},
        )
    selected.sort(key=_autofix_payload_order)

    job_id, job = _new_job()
    job.status = "running"
    job.progress = 5
    job.message = "Waiting for agent to pick up autofix job..."
    job.user_id = current_user.id
    job.target_agent_id = agent.agent_id
    job.version = scan.version or ""
    payload = {
        "job_id": job_id,
        "job_type": "autofix",
        "scan_id": scan.id,
        "version": scan.version or "",
        "role": role,
        "requested_by": current_user.username,
        "checks": selected,
    }

    now = datetime.datetime.now()
    row = AgentJob(
        job_id=job_id,
        agent_id=agent.agent_id,
        status="pending",
        version=scan.version or "",
        role=role,
        baseline_path="",
        payload=payload,
        attempts=0,
        user_id=current_user.id,
        parent_scan_id=None,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.commit()
    log_activity(
        db,
        actor=current_user,
        action="autofix_queued",
        target_type="scan",
        target_id=scan.id,
        detail={
            "job_id": job_id,
            "agent_id": agent.agent_id,
            "supported_count": len(selected),
            "rejected_count": len(rejected),
            "check_ids": [item.get("check_id") for item in selected],
        },
    )

    return {
        "job_id": job_id,
        "agent_id": agent.agent_id,
        "supported_count": len(selected),
        "rejected": rejected,
    }


@app.get("/api/scan/history/{scan_id}/autofix-jobs")
async def list_scan_autofix_jobs(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not _has_admin_access(current_user):
        raise HTTPException(status_code=403, detail="Admin permission required")
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")

    user_ids = {row.user_id for row in _find_fix_jobs_for_scan(db, scan_id, current_user) if row.user_id}
    users = {
        user.id: user.username
        for user in db.query(User).filter(User.id.in_(user_ids)).all()
    } if user_ids else {}
    return [
        _summarize_fix_job(row, requested_by=users.get(row.user_id, ""))
        for row in _find_fix_jobs_for_scan(db, scan_id, current_user)
    ]


@app.post("/api/scan/history/{scan_id}/autofix/{job_id}/rollback")
async def rollback_scan_autofix_job(
    scan_id: int,
    job_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not _has_admin_access(current_user):
        raise HTTPException(status_code=403, detail="Admin permission required")
    scan = db.query(ScanResult).filter(ScanResult.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")

    original = db.query(AgentJob).filter(AgentJob.job_id == job_id).first()
    if not original:
        raise HTTPException(status_code=404, detail="autofix job not found")
    original_payload = original.payload or {}
    original_result = original.result or {}
    if _normalize_fix_job_type(original_result.get("job_type") or original_payload.get("job_type")) != "autofix":
        raise HTTPException(status_code=400, detail="Only autofix jobs can be rolled back")
    if str(original_result.get("scan_id") or original_payload.get("scan_id") or "") != str(scan_id):
        raise HTTPException(status_code=400, detail="Autofix job does not belong to this scan")

    agent = _find_agent_for_scan(scan, db)
    if not agent or agent.agent_id != original.agent_id:
        raise HTTPException(status_code=400, detail="Unable to match rollback to the original agent")

    rollback_checks = []
    rejected = []
    for item in original_result.get("autofix_results") or []:
        supported, reason = _rollback_support_for_result(item)
        check_id = item.get("check_id") or item.get("check_name") or "unknown"
        if not supported:
            rejected.append({"check_id": check_id, "reason": reason})
            continue
        fix_type = item.get("fix_type") or "registry"
        rollback_item = {
            "check_id": check_id,
            "check_name": item.get("check_name") or check_id,
            "fix_type": fix_type,
            "fix_mode": "rollback",
            "old_value": item.get("old_value") or "",
            "new_value": item.get("new_value") or "",
            "registry_path": item.get("registry_path") or "",
        }
        if fix_type == "service_startup":
            rollback_item["service_name"] = item.get("service_name") or item.get("check_name") or check_id
            rollback_item["startup_type"] = _normalize_service_startup_value(str(item.get("old_value") or ""))
        elif fix_type == "audit_policy":
            rollback_item["audit_subcategory"] = item.get("audit_subcategory") or ""
            rollback_item["audit_value"] = _normalize_audit_autofix_value(str(item.get("old_value") or ""))
        elif fix_type == "firewall_profile":
            rollback_item["firewall_profile"] = item.get("firewall_profile") or ""
            rollback_item["firewall_state"] = _normalize_firewall_state_value(str(item.get("old_value") or ""))
        elif fix_type in ("registry_multi", "defender_registry"):
            rollback_item["registry_entries"] = item.get("registry_entries") or []
        elif fix_type == "security_policy":
            rollback_item["security_policy_key"] = item.get("security_policy_key") or ""
            rollback_item["security_policy_value"] = str(item.get("old_value") or "")
            rollback_item["expected_value"] = str(item.get("old_value") or "")
        elif fix_type == "user_rights":
            rollback_item["privilege_name"] = item.get("privilege_name") or ""
            accounts, parse_reason = _parse_user_right_accounts(str(item.get("old_value") or ""))
            if parse_reason:
                rejected.append({"check_id": check_id, "reason": parse_reason})
                continue
            rollback_item["privilege_accounts"] = accounts
            rollback_item["expected_value"] = ",".join(accounts)
        rollback_checks.append(rollback_item)

    if not rollback_checks:
        raise HTTPException(
            status_code=400,
            detail={"message": "No checks in this job can be rolled back", "rejected": rejected},
        )

    rollback_job_id, job = _new_job()
    job.status = "running"
    job.progress = 5
    job.message = "Waiting for agent to pick up rollback job..."
    job.user_id = current_user.id
    job.target_agent_id = agent.agent_id
    job.version = scan.version or ""
    role = resolve_scan_role(scan.details, target_name=scan.target_name or "")
    payload = {
        "job_id": rollback_job_id,
        "job_type": "rollback",
        "scan_id": scan.id,
        "original_job_id": original.job_id,
        "version": scan.version or "",
        "role": role,
        "requested_by": current_user.username,
        "checks": rollback_checks,
    }
    now = datetime.datetime.now()
    row = AgentJob(
        job_id=rollback_job_id,
        agent_id=agent.agent_id,
        status="pending",
        version=scan.version or "",
        role=role,
        baseline_path="",
        payload=payload,
        attempts=0,
        user_id=current_user.id,
        parent_scan_id=None,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.commit()
    log_activity(
        db,
        actor=current_user,
        action="rollback_queued",
        target_type="scan",
        target_id=scan.id,
        detail={
            "job_id": rollback_job_id,
            "original_job_id": original.job_id,
            "agent_id": agent.agent_id,
            "rollback_count": len(rollback_checks),
            "rejected_count": len(rejected),
        },
    )
    return {
        "job_id": rollback_job_id,
        "agent_id": agent.agent_id,
        "rollback_count": len(rollback_checks),
        "rejected": rejected,
    }


def _normalize_compare_part(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _finding_comparison_key(item: dict) -> str:
    setting_parts = [
        item.get("policy_path"),
        item.get("registry_path"),
        item.get("check_name"),
        item.get("category"),
    ]
    setting_key = "|".join(
        part for part in (_normalize_compare_part(value) for value in setting_parts) if part
    )
    if setting_key:
        return setting_key
    fallback_parts = [
        item.get("check_id"),
        item.get("source_key"),
        item.get("check_name"),
        item.get("category"),
    ]
    return "|".join(
        part for part in (_normalize_compare_part(value) for value in fallback_parts) if part
    )


def _comparison_item(item: dict, key: str, change_type: str, other: dict | None = None) -> dict:
    row = dict(item)
    row["comparison_key"] = key
    row["change_type"] = change_type
    if change_type == "fixed":
        row["base_status"] = item.get("status", "")
        row["base_value"] = item.get("current_value", "")
        row["current_status"] = "Pass"
        row["current_value"] = ""
        return row
    row["current_status"] = item.get("status", "")
    row["current_value"] = item.get("current_value", "")
    if other:
        row["base_status"] = other.get("status", "")
        row["base_value"] = other.get("current_value", "")
    else:
        row.setdefault("base_status", "")
        row.setdefault("base_value", "")
    return row


def _failed_finding_map(scan: ScanResult) -> dict[str, dict]:
    role = resolve_scan_role(scan.details, target_name=scan.target_name or "")
    details = scan.details or {}
    findings = enrich_scan_details(details, version=scan.version or "", role=role)
    rows = {}
    for item in findings:
        status = str(item.get("status", "")).lower()
        if not status.startswith("fail"):
            continue
        key = _finding_comparison_key(item)
        if not key:
            continue
        rows[str(key)] = item
    return rows


def _scan_compare_host(scan: ScanResult) -> str:
    return _normalize_compare_part(scan.hostname or scan.target_name or "")


def _scan_history_payload(scan: ScanResult, current: ScanResult | None = None) -> dict:
    score_delta = None
    same_baseline = False
    if current:
        score_delta = (scan.score or 0) - (current.score or 0)
        same_baseline = (scan.version or "") == (current.version or "")
    return {
        "id": scan.id,
        "hostname": scan.hostname or "",
        "target_name": scan.target_name or "",
        "score": scan.score or 0,
        "scan_date": scan.scan_date.isoformat() if scan.scan_date else None,
        "version": scan.version or "",
        "scan_type": getattr(scan, "scan_type", "single") or "single",
        "same_baseline": same_baseline,
        "score_delta_preview": score_delta,
    }


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


@app.get("/api/scan/history/{scan_id}/compare-candidates")
async def get_compare_candidates(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(ScanResult).filter(ScanResult.id == scan_id)
    if not _has_admin_access(current_user):
        query = query.filter(ScanResult.user_id == current_user.id)
    current = query.first()
    if not current:
        raise HTTPException(status_code=404, detail="scan not found")
    if getattr(current, "scan_type", "single") != "single":
        raise HTTPException(status_code=400, detail="comparison supports single-machine scans only")

    host = _scan_compare_host(current)
    if not host:
        return []

    candidates = db.query(ScanResult).filter(
        ScanResult.id != current.id,
        ScanResult.scan_type != "subnet",
        ScanResult.scan_date < current.scan_date,
    )
    if not _has_admin_access(current_user):
        candidates = candidates.filter(ScanResult.user_id == current_user.id)
    rows = [
        row for row in candidates.order_by(ScanResult.scan_date.desc()).limit(200).all()
        if _scan_compare_host(row) == host
    ]
    rows.sort(key=lambda row: (
        0 if (row.version or "") == (current.version or "") else 1,
        -(row.scan_date.timestamp() if row.scan_date else 0),
    ))
    return [_scan_history_payload(row, current=current) for row in rows[:50]]


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
        "current_scan_date": current.scan_date.isoformat() if current.scan_date else None,
        "base_scan_date": base.scan_date.isoformat() if base.scan_date else None,
        "version": current.version or "",
        "base_version": base.version or "",
        "baseline_compatible": (current.version or "") == (base.version or ""),
        "score": current.score,
        "base_score": base.score,
        "score_delta": (current.score or 0) - (base.score or 0),
        "current_failed_count": len(current_failed),
        "base_failed_count": len(base_failed),
        "fixed": [_comparison_item(base_failed[k], k, "fixed") for k in fixed_keys],
        "newly_failed": [_comparison_item(current_failed[k], k, "newly_failed") for k in new_keys],
        "still_failing": [
            _comparison_item(current_failed[k], k, "still_failing", other=base_failed.get(k))
            for k in still_keys
        ],
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
    job.role = "auto"
    job.target_agent_id = agent_id
    job.baseline_match_type = baseline_info.get("match_type", "")
    job.baseline_warning = baseline_info.get("warning", "")
    
    enqueue(agent_id, job_id, resolved_version, baseline_path)
    db = SessionLocal()
    try:
        log_activity(
            db,
            actor=current_user,
            action="scan_started",
            target_type="agent",
            target_id=job_id,
            detail={
                "agent_id": agent_id,
                "hostname": agent["hostname"],
                "version": resolved_version,
                "role": "auto",
                "baseline_match_type": baseline_info.get("match_type", ""),
            },
        )
    finally:
        db.close()
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
        child_job.role = "auto"
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
    db = SessionLocal()
    try:
        log_activity(
            db,
            actor=current_user,
            action="scan_started",
            target_type="agent_subnet",
            target_id=job_id,
            detail={
                "subnet": req.subnet,
                "version": req.version,
                "role": "auto",
                "parent_scan_id": parent_scan_id,
                "total_agents": len(matched),
                "online_agents": len(online_agents),
            },
        )
    finally:
        db.close()

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
            "detected_role": a.detected_role or "",
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
