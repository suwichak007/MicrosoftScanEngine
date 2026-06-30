"""
admin_routes.py
---------------
FastAPI router สำหรับ User Management (Admin only)

Endpoints:
  GET    /api/admin/users              — ดู list users ทั้งหมด
  PATCH  /api/admin/users/{user_id}/role     — เปลี่ยน role
  POST   /api/admin/users/{user_id}/reset-password — reset password
  DELETE /api/admin/users/{user_id}    — ลบ user
"""

import os
import re
import shutil
import sys
import datetime
import uuid
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.activity_routes import log_activity
from app.core.security import get_current_user, get_password_hash
from app.core.scan.scanner.baseline_config import list_available_versions, _load_json
from app.core.severity_mapping import get_mapping_from_db
from app.models.baseline_version import BaselineVersion
from app.models.scan_schedule import ScanSchedule
from app.models.user import User

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tools.convert_baselines import analyze_workbook, convert_workbook, write_definition

router = APIRouter(prefix="/api/admin", tags=["admin"])
BASELINE_UPLOAD_DIR = ROOT_DIR / "baselines" / "uploads"
BASELINE_OUTPUT_DIR = Path(os.environ.get("BASELINES_DIR", ROOT_DIR / "baselines" / "generated"))


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """เฉพาะ admin เท่านั้นที่เข้าถึงได้"""
    if current_user.role not in ("admin", "owner"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="ต้องการสิทธิ์ admin",
        )
    return current_user


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RoleUpdate(BaseModel):
    role: str  # "admin" | "viewer"

class PasswordReset(BaseModel):
    new_password: str


class ScheduleIn(BaseModel):
    name: str
    scan_type: Literal["agent", "agent-subnet"]
    agent_id: str = ""
    subnet: str = ""
    version: str = "auto"
    role: str = "auto"
    frequency: Literal["hourly", "daily", "weekly"] = "daily"
    time: str = "09:00"
    day_of_week: int | None = None
    enabled: bool = True


class BaselineConfirmIn(BaseModel):
    upload_id: str
    target_columns: dict[str, list[str]] = {}
    target_roles: dict[str, dict[str, list[str]]] = {}


def _safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._ -]+", "_", Path(name).name).strip(" .")
    return cleaned or "baseline.xlsx"


def _pending_upload_path(upload_id: str) -> Path:
    if not re.match(r"^[a-f0-9]{32}-.+\.xlsx$", upload_id, re.IGNORECASE):
        raise HTTPException(status_code=400, detail="Invalid pending upload id")
    return BASELINE_UPLOAD_DIR / ".uploading" / Path(upload_id).name


def _save_uploaded_baseline(file: UploadFile, filename: str) -> Path:
    BASELINE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    temp_dir = BASELINE_UPLOAD_DIR / ".uploading"
    temp_dir.mkdir(parents=True, exist_ok=True)
    upload_id = f"{uuid.uuid4().hex}-{filename}"
    return temp_dir / upload_id


async def _write_upload_file(file: UploadFile, path: Path) -> None:
    with path.open("wb") as f:
        while chunk := await file.read(1024 * 1024):
            f.write(chunk)


def _store_converted_baseline(
    definition: dict,
    source_path: Path,
    source_filename: str,
    db: Session | None = None,
    actor: User | None = None,
) -> dict:
    BASELINE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    BASELINE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

    check_count = len(definition.get("checks", []))
    if check_count == 0:
        raise HTTPException(status_code=400, detail="No checks were found. Please review the Excel baseline format.")

    json_path = write_definition(definition, BASELINE_OUTPUT_DIR, "json")
    yaml_path = write_definition(definition, BASELINE_OUTPUT_DIR, "yaml")

    saved_path = BASELINE_UPLOAD_DIR / source_filename
    if saved_path.exists():
        saved_path.unlink()
    shutil.move(str(source_path), str(saved_path))
    _load_json.cache_clear()

    result = {
        "ok": True,
        "baseline_id": definition.get("baseline_id", ""),
        "baseline_name": definition.get("baseline_name", ""),
        "os_family": definition.get("os_family", ""),
        "source_file": source_filename,
        "check_count": check_count,
        "generated_files": [json_path.name, yaml_path.name],
    }
    if db is not None:
        log_activity(
            db,
            actor=actor,
            action="baseline_uploaded",
            target_type="baseline",
            target_id=result["baseline_id"] or json_path.name,
            detail=result,
        )
    return result


def _parse_time(value: str | None, frequency: str) -> tuple[int, int]:
    raw = (value or "").strip()
    if frequency == "hourly":
        minute = int(raw) if raw.isdigit() else 0
        if minute < 0 or minute > 59:
            raise ValueError("hourly time must be minute 0-59")
        return 0, minute
    match = re.match(r"^(\d{1,2}):(\d{2})$", raw)
    if not match:
        raise ValueError("time must use HH:MM")
    hour = int(match.group(1))
    minute = int(match.group(2))
    if hour > 23 or minute > 59:
        raise ValueError("time must use HH:MM")
    return hour, minute


def compute_next_run(frequency: str, time_value: str | None, day_of_week: int | None, from_dt: datetime.datetime | None = None) -> datetime.datetime:
    now = from_dt or datetime.datetime.now()
    hour, minute = _parse_time(time_value, frequency)

    if frequency == "hourly":
        candidate = now.replace(minute=minute, second=0, microsecond=0)
        if candidate <= now:
            candidate += datetime.timedelta(hours=1)
        return candidate

    candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if frequency == "daily":
        if candidate <= now:
            candidate += datetime.timedelta(days=1)
        return candidate

    if frequency == "weekly":
        dow = 0 if day_of_week is None else int(day_of_week)
        if dow < 0 or dow > 6:
            raise ValueError("day_of_week must be 0-6")
        days_ahead = (dow - now.weekday()) % 7
        candidate = candidate + datetime.timedelta(days=days_ahead)
        if candidate <= now:
            candidate += datetime.timedelta(days=7)
        return candidate

    raise ValueError("frequency must be hourly, daily, or weekly")


def _schedule_to_dict(row: ScanSchedule) -> dict:
    return {
        "id": row.id,
        "name": row.name,
        "scan_type": row.scan_type,
        "agent_id": row.agent_id or "",
        "subnet": row.subnet or "",
        "version": row.version or "auto",
        "role": "auto",
        "frequency": row.frequency or "daily",
        "time": row.time or "",
        "day_of_week": row.day_of_week,
        "enabled": bool(row.enabled),
        "last_run": row.last_run.isoformat() if row.last_run else None,
        "next_run": row.next_run.isoformat() if row.next_run else None,
        "last_job_id": row.last_job_id or "",
        "last_error": row.last_error or "",
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


def _apply_schedule(row: ScanSchedule, body: ScheduleIn, user_id: int | None = None) -> None:
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="schedule name is required")
    if body.scan_type == "agent" and not body.agent_id.strip():
        raise HTTPException(status_code=400, detail="agent_id is required")
    if body.scan_type == "agent-subnet" and not body.subnet.strip():
        raise HTTPException(status_code=400, detail="subnet is required")

    try:
        next_run = compute_next_run(body.frequency, body.time, body.day_of_week) if body.enabled else None
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    row.name = name
    row.scan_type = body.scan_type
    row.agent_id = body.agent_id.strip() if body.scan_type == "agent" else ""
    row.subnet = body.subnet.strip() if body.scan_type == "agent-subnet" else ""
    row.version = body.version.strip() or "auto"
    row.role = "auto"
    row.frequency = body.frequency
    row.time = body.time.strip()
    row.day_of_week = body.day_of_week if body.frequency == "weekly" else None
    row.enabled = body.enabled
    row.next_run = next_run
    row.updated_at = datetime.datetime.now()
    if user_id is not None:
        row.user_id = user_id


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("/users")
def list_users(
    db:    Session = Depends(get_db),
    admin: User    = Depends(require_admin),
):
    """ดู list users ทั้งหมด"""
    users = db.query(User).order_by(User.id).all()
    return [
        {
            "id":        u.id,
            "username":  u.username,
            "role":      u.role,
            "is_active": u.is_active,
        }
        for u in users
    ]


@router.get("/baselines")
def list_baselines(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    return list_available_versions(str(BASELINE_OUTPUT_DIR))


@router.post("/baselines/analyze")
async def analyze_baseline(
    file: UploadFile = File(...),
    admin: User = Depends(require_admin),
):
    filename = _safe_filename(file.filename or "")
    if not filename.lower().endswith(".xlsx"):
        raise HTTPException(status_code=400, detail="Only .xlsx baseline files are supported")

    temp_path = _save_uploaded_baseline(file, filename)
    try:
        await _write_upload_file(file, temp_path)
        analysis = analyze_workbook(temp_path, source_filename=filename)
        analysis["upload_id"] = temp_path.name
        return analysis
    except HTTPException:
        if temp_path.exists():
            temp_path.unlink()
        raise
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        raise HTTPException(status_code=400, detail=f"Analyze baseline failed: {e}")


@router.post("/baselines/upload/confirm")
def confirm_baseline_upload(
    body: BaselineConfirmIn,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    temp_path = _pending_upload_path(body.upload_id)
    if not temp_path.exists():
        raise HTTPException(status_code=404, detail="Pending upload not found. Please choose the Excel file again.")

    source_filename = re.sub(r"^[a-f0-9]{32}-", "", temp_path.name, flags=re.IGNORECASE)
    try:
        definition = convert_workbook(
            temp_path,
            target_column_overrides=body.target_columns,
            target_role_overrides=body.target_roles,
            severity_mapping=get_mapping_from_db(db),
            source_filename=source_filename,
        )
        return _store_converted_baseline(definition, temp_path, source_filename, db=db, actor=admin)
    except HTTPException:
        if temp_path.exists():
            temp_path.unlink()
        raise
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        raise HTTPException(status_code=400, detail=f"Convert baseline failed: {e}")


@router.post("/baselines/upload")
async def upload_baseline(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    filename = _safe_filename(file.filename or "")
    if not filename.lower().endswith(".xlsx"):
        raise HTTPException(status_code=400, detail="รองรับเฉพาะไฟล์ .xlsx เท่านั้น")

    BASELINE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    BASELINE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    temp_dir = BASELINE_UPLOAD_DIR / ".uploading"
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / filename
    saved_path = BASELINE_UPLOAD_DIR / filename

    try:
        with temp_path.open("wb") as f:
            while chunk := await file.read(1024 * 1024):
                f.write(chunk)

        definition = convert_workbook(
            temp_path,
            severity_mapping=get_mapping_from_db(db),
        )
        check_count = len(definition.get("checks", []))
        if check_count == 0:
            raise HTTPException(status_code=400, detail="ไฟล์นี้แปลงได้ 0 checks จึงไม่บันทึก baseline")

        json_path = write_definition(definition, BASELINE_OUTPUT_DIR, "json")
        yaml_path = write_definition(definition, BASELINE_OUTPUT_DIR, "yaml")
        if saved_path.exists():
            saved_path.unlink()
        shutil.move(str(temp_path), str(saved_path))
        _load_json.cache_clear()

        result = {
            "ok": True,
            "baseline_id": definition.get("baseline_id", ""),
            "baseline_name": definition.get("baseline_name", ""),
            "os_family": definition.get("os_family", ""),
            "source_file": filename,
            "check_count": check_count,
            "generated_files": [json_path.name, yaml_path.name],
        }
        log_activity(
            db,
            actor=admin,
            action="baseline_uploaded",
            target_type="baseline",
            target_id=result["baseline_id"] or json_path.name,
            detail=result,
        )
        return result
    except HTTPException:
        if temp_path.exists():
            temp_path.unlink()
        raise
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        raise HTTPException(status_code=400, detail=f"แปลง baseline ไม่สำเร็จ: {e}")


@router.delete("/baselines/{filename}")
def delete_baseline(
    filename: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    safe_name = Path(filename).name
    if safe_name != filename or not safe_name.lower().endswith(".json"):
        raise HTTPException(status_code=400, detail="Invalid baseline filename")

    json_path = BASELINE_OUTPUT_DIR / safe_name
    if not json_path.exists():
        raise HTTPException(status_code=404, detail="Baseline not found")

    source_file = ""
    try:
        data = _load_json(str(json_path))
        source_file = Path(data.get("source_file") or "").name
    except Exception:
        source_file = ""

    stem = json_path.stem
    removed = []
    for path in [
        json_path,
        BASELINE_OUTPUT_DIR / f"{stem}.yaml",
        BASELINE_OUTPUT_DIR / f"{stem}.yml",
    ]:
        if path.exists() and path.is_file():
            path.unlink()
            removed.append(path.name)

    if source_file:
        upload_path = BASELINE_UPLOAD_DIR / source_file
        if upload_path.exists() and upload_path.is_file():
            upload_path.unlink()
            removed.append(upload_path.name)

    _load_json.cache_clear()
    active = (
        db.query(BaselineVersion)
        .filter(BaselineVersion.filename == safe_name, BaselineVersion.is_active == True)
        .first()
    )
    if active:
        active.is_active = False
        db.commit()
    log_activity(
        db,
        actor=admin,
        action="baseline_deleted",
        target_type="baseline",
        target_id=safe_name,
        detail={"removed": removed},
    )
    return {"ok": True, "filename": safe_name, "removed": removed}


@router.get("/schedules")
def list_schedules(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    rows = db.query(ScanSchedule).order_by(ScanSchedule.created_at.desc()).all()
    return [_schedule_to_dict(row) for row in rows]


@router.post("/schedules")
def create_schedule(
    body: ScheduleIn,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    row = ScanSchedule(created_at=datetime.datetime.now())
    _apply_schedule(row, body, admin.id)
    db.add(row)
    db.commit()
    db.refresh(row)
    log_activity(
        db,
        actor=admin,
        action="schedule_created",
        target_type="schedule",
        target_id=row.id,
        detail=_schedule_to_dict(row),
    )
    return _schedule_to_dict(row)


@router.put("/schedules/{schedule_id}")
def update_schedule(
    schedule_id: int,
    body: ScheduleIn,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    row = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="schedule not found")
    _apply_schedule(row, body)
    db.commit()
    db.refresh(row)
    log_activity(
        db,
        actor=admin,
        action="schedule_updated",
        target_type="schedule",
        target_id=row.id,
        detail=_schedule_to_dict(row),
    )
    return _schedule_to_dict(row)


@router.delete("/schedules/{schedule_id}")
def delete_schedule(
    schedule_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    row = db.query(ScanSchedule).filter(ScanSchedule.id == schedule_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="schedule not found")
    detail = _schedule_to_dict(row)
    db.delete(row)
    db.commit()
    log_activity(
        db,
        actor=admin,
        action="schedule_deleted",
        target_type="schedule",
        target_id=schedule_id,
        detail=detail,
    )
    return {"ok": True, "id": schedule_id}


@router.patch("/users/{user_id}/role")
def update_role(
    user_id: int,
    body:    RoleUpdate,
    db:      Session = Depends(get_db),
    admin:   User    = Depends(require_admin),
):
    """เปลี่ยน role ของ user"""
    if body.role not in ("admin", "viewer"):
        raise HTTPException(status_code=400, detail="role ต้องเป็น admin หรือ viewer เท่านั้น")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="ไม่พบ user")

    # ป้องกัน admin ลด role ตัวเอง
    if user.id == admin.id and body.role != admin.role:
        raise HTTPException(status_code=400, detail="ไม่สามารถลด role ของตัวเองได้")

    if user.role == "admin" and body.role != "admin":
        privileged_count = db.query(User).filter(User.role.in_(("admin", "owner")), User.is_active == True).count()
        if privileged_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot remove the last active admin or owner")

    actor_is_owner = admin.role == "owner"
    target_is_privileged = user.role in ("admin", "owner")
    if target_is_privileged and not actor_is_owner:
        raise HTTPException(status_code=403, detail="Only owner can manage admin or owner roles")

    if user.role == "owner" and body.role != "owner":
        owner_count = db.query(User).filter(User.role == "owner", User.is_active == True).count()
        if owner_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot remove the last active owner")

    old_role = user.role
    user.role = body.role
    db.commit()
    log_activity(
        db,
        actor=admin,
        action="user_role_changed",
        target_type="user",
        target_id=user.id,
        detail={"username": user.username, "old_role": old_role, "new_role": body.role},
    )
    return {"ok": True, "user_id": user_id, "role": body.role}


@router.post("/users/{user_id}/reset-password")
def reset_password(
    user_id: int,
    body:    PasswordReset,
    db:      Session = Depends(get_db),
    admin:   User    = Depends(require_admin),
):
    """Reset password ของ user"""
    if len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password ต้องมีอย่างน้อย 6 ตัวอักษร")

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="ไม่พบ user")

    if not user.hashed_password:
        raise HTTPException(status_code=400, detail="LDAP user password must be managed in LDAP/AD")
    if user.role == "owner":
        raise HTTPException(status_code=403, detail="Owner password cannot be reset from User Management")
    if user.role == "admin" and admin.role != "owner":
        raise HTTPException(status_code=403, detail="Only owner can reset admin passwords")

    user.hashed_password = get_password_hash(body.new_password)
    db.commit()
    log_activity(
        db,
        actor=admin,
        action="user_password_reset",
        target_type="user",
        target_id=user.id,
        detail={"username": user.username, "role": user.role},
    )
    return {"ok": True, "user_id": user_id}


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    db:      Session = Depends(get_db),
    admin:   User    = Depends(require_admin),
):
    """ลบ user"""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="ไม่พบ user")

    # ป้องกัน admin ลบตัวเอง
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="ไม่สามารถลบตัวเองได้")

    if user.role == "owner":
        raise HTTPException(status_code=403, detail="Owner accounts cannot be deleted")
    if user.role == "admin" and admin.role != "owner":
        raise HTTPException(status_code=403, detail="Only owner can delete admin accounts")
    if user.role == "admin":
        privileged_count = db.query(User).filter(User.role.in_(("admin", "owner")), User.is_active == True).count()
        if privileged_count <= 1:
            raise HTTPException(status_code=400, detail="Cannot remove the last active admin or owner")

    detail = {"username": user.username, "role": user.role}
    db.delete(user)
    db.commit()
    log_activity(
        db,
        actor=admin,
        action="user_deleted",
        target_type="user",
        target_id=user_id,
        detail=detail,
    )
    return {"ok": True, "user_id": user_id}
