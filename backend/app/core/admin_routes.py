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
import json
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.security import get_current_user, get_password_hash
from app.core.scan.scanner.baseline_config import list_available_versions, _load_json
from app.core.severity_mapping import (
    get_mapping_from_db,
    preview_from_definition,
    save_mapping_to_db,
    severity_counts,
)
from app.models.baseline_version import BaselineVersion
from app.models.scan_schedule import ScanSchedule
from app.models.severity_mapping import SeverityMapping
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
    if current_user.role != "admin":
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
    target_columns: dict[str, list[str]]


class SeverityMappingIn(BaseModel):
    category_mapping: dict[str, str]
    keyword_overrides: dict[str, list[str]]


def _safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._ -]+", "_", Path(name).name).strip(" .")
    return cleaned or "baseline.xlsx"


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
    row.role = body.role.strip() or "auto"
    row.frequency = body.frequency
    row.time = body.time.strip()
    row.day_of_week = body.day_of_week if body.frequency == "weekly" else None
    row.enabled = body.enabled
    row.next_run = next_run
    row.updated_at = datetime.datetime.now()
    if user_id is not None:
        row.user_id = user_id


def _baseline_version_to_dict(row: BaselineVersion) -> dict:
    return {
        "id": row.id,
        "baseline_id": row.baseline_id,
        "version_no": row.version_no,
        "display_name": row.display_name,
        "filename": row.filename,
        "json_path": row.json_path,
        "yaml_path": row.yaml_path,
        "source_file": row.source_file,
        "check_count": row.check_count or 0,
        "severity_counts": row.severity_counts or {},
        "target_columns": row.target_columns or {},
        "is_active": bool(row.is_active),
        "uploaded_by": row.uploaded_by,
        "uploaded_at": row.uploaded_at.isoformat() if row.uploaded_at else None,
        "rolled_back_from": row.rolled_back_from,
    }


def _active_alias_paths(baseline_id: str) -> tuple[Path, Path]:
    return BASELINE_OUTPUT_DIR / f"{baseline_id}.json", BASELINE_OUTPUT_DIR / f"{baseline_id}.yaml"


def _write_active_alias(definition: dict, source_json: Path, source_yaml: Path | None = None) -> tuple[Path, Path]:
    BASELINE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    active_json, active_yaml = _active_alias_paths(definition["baseline_id"])
    if source_json.resolve() != active_json.resolve():
        shutil.copy2(source_json, active_json)
    if source_yaml and source_yaml.exists():
        if source_yaml.resolve() != active_yaml.resolve():
            shutil.copy2(source_yaml, active_yaml)
    else:
        write_definition(definition, BASELINE_OUTPUT_DIR, "yaml")
    _load_json.cache_clear()
    return active_json, active_yaml


def _register_baseline_version(
    db: Session,
    definition: dict,
    json_path: Path,
    yaml_path: Path,
    source_path: Path,
    target_columns: dict,
    admin: User,
    rolled_back_from: int | None = None,
) -> BaselineVersion:
    baseline_id = definition["baseline_id"]
    current_max = (
        db.query(BaselineVersion)
        .filter(BaselineVersion.baseline_id == baseline_id)
        .order_by(BaselineVersion.version_no.desc())
        .first()
    )
    version_no = (current_max.version_no + 1) if current_max else 1
    db.query(BaselineVersion).filter(BaselineVersion.baseline_id == baseline_id).update({"is_active": False})
    row = BaselineVersion(
        baseline_id=baseline_id,
        version_no=version_no,
        display_name=definition.get("baseline_name") or baseline_id,
        filename=f"{baseline_id}.json",
        json_path=str(json_path),
        yaml_path=str(yaml_path),
        source_file=str(source_path),
        check_count=len(definition.get("checks", [])),
        severity_counts=severity_counts(definition.get("checks", [])),
        target_columns=target_columns,
        is_active=True,
        uploaded_by=admin.id,
        uploaded_at=datetime.datetime.now(),
        rolled_back_from=rolled_back_from,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _seed_versions_from_active_files(db: Session) -> None:
    if db.query(BaselineVersion).first():
        return
    for info in list_available_versions(str(BASELINE_OUTPUT_DIR)):
        filename = info.get("filename") or ""
        if not filename.endswith(".json"):
            continue
        path = BASELINE_OUTPUT_DIR / filename
        if not path.exists():
            continue
        try:
            data = _load_json(str(path))
        except Exception:
            continue
        baseline_id = data.get("baseline_id") or Path(filename).stem
        version_dir = BASELINE_OUTPUT_DIR / baseline_id
        version_dir.mkdir(parents=True, exist_ok=True)
        version_json = version_dir / "v1.json"
        if not version_json.exists():
            shutil.copy2(path, version_json)
        root_yaml = BASELINE_OUTPUT_DIR / f"{Path(filename).stem}.yaml"
        version_yaml = version_dir / "v1.yaml"
        if root_yaml.exists() and not version_yaml.exists():
            shutil.copy2(root_yaml, version_yaml)
        row = BaselineVersion(
            baseline_id=baseline_id,
            version_no=1,
            display_name=data.get("baseline_name") or info.get("display_name") or baseline_id,
            filename=filename,
            json_path=str(version_json),
            yaml_path=str(version_yaml) if version_yaml.exists() else "",
            source_file=data.get("source_file") or "",
            check_count=len(data.get("checks", [])),
            severity_counts=severity_counts(data.get("checks", [])),
            target_columns={},
            is_active=True,
            uploaded_by=None,
            uploaded_at=datetime.datetime.now(),
        )
        db.add(row)
    db.commit()


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


@router.get("/severity-mapping")
def get_severity_mapping(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    return get_mapping_from_db(db)


@router.put("/severity-mapping")
def update_severity_mapping(
    body: SeverityMappingIn,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    return save_mapping_to_db(db, body.dict(), admin.id)


@router.get("/baselines")
def list_baselines(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    _seed_versions_from_active_files(db)
    active_versions = {
        row.filename: row
        for row in db.query(BaselineVersion).filter(BaselineVersion.is_active == True).all()
    }
    rows = []
    for item in list_available_versions(str(BASELINE_OUTPUT_DIR)):
        row = active_versions.get(item.get("filename", ""))
        enriched = dict(item)
        if row:
            enriched.update({
                "baseline_id": row.baseline_id,
                "active_version_no": row.version_no,
                "severity_counts": row.severity_counts or {},
                "uploaded_at": row.uploaded_at.isoformat() if row.uploaded_at else None,
            })
        rows.append(enriched)
    return rows


@router.post("/baselines/analyze")
async def analyze_baseline(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    filename = _safe_filename(file.filename or "")
    if not filename.lower().endswith(".xlsx"):
        raise HTTPException(status_code=400, detail="Only .xlsx files are supported")

    BASELINE_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    temp_dir = BASELINE_UPLOAD_DIR / ".pending"
    temp_dir.mkdir(parents=True, exist_ok=True)
    upload_id = uuid.uuid4().hex
    upload_dir = temp_dir / upload_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    temp_path = upload_dir / filename

    try:
        with temp_path.open("wb") as f:
            while chunk := await file.read(1024 * 1024):
                f.write(chunk)
        analysis = analyze_workbook(temp_path)
        try:
            preview_definition = convert_workbook(temp_path, severity_mapping=get_mapping_from_db(db))
            analysis["severity_preview"] = preview_from_definition(preview_definition)
            analysis["check_count"] = len(preview_definition.get("checks", []))
        except Exception as preview_error:
            analysis["severity_preview"] = {
                "check_count": 0,
                "severity_counts": {},
                "category_counts": [],
                "sample_checks": [],
                "warnings": [f"Preview failed: {preview_error}"],
            }
            analysis["check_count"] = 0
        analysis["upload_id"] = upload_id
        analysis["source_file"] = filename
        return analysis
    except Exception as e:
        if upload_dir.exists():
            shutil.rmtree(upload_dir)
        raise HTTPException(status_code=400, detail=f"Analyze baseline failed: {e}")


@router.post("/baselines/upload/confirm")
def confirm_baseline_upload(
    body: BaselineConfirmIn,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    temp_dir = BASELINE_UPLOAD_DIR / ".pending"
    candidates = sorted((temp_dir / body.upload_id).glob("*.xlsx")) if (temp_dir / body.upload_id).exists() else []
    if not candidates and temp_dir.exists():
        candidates = sorted(temp_dir.glob(f"{body.upload_id}-*.xlsx"))
    if not candidates:
        raise HTTPException(status_code=404, detail="Pending upload not found")

    original_pending_path = candidates[0]
    temp_path = original_pending_path
    filename = temp_path.name
    if temp_path.parent == temp_dir and temp_path.name.startswith(f"{body.upload_id}-"):
        filename = temp_path.name[len(body.upload_id) + 1:]
        clean_path = temp_dir / filename
        shutil.copy2(temp_path, clean_path)
        temp_path = clean_path
    BASELINE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    try:
        definition = convert_workbook(
            temp_path,
            target_column_overrides=body.target_columns,
            severity_mapping=get_mapping_from_db(db),
        )
        check_count = len(definition.get("checks", []))
        if check_count == 0:
            raise HTTPException(status_code=400, detail="Converted baseline has 0 checks")

        baseline_id = definition["baseline_id"]
        current_max = (
            db.query(BaselineVersion)
            .filter(BaselineVersion.baseline_id == baseline_id)
            .order_by(BaselineVersion.version_no.desc())
            .first()
        )
        version_no = (current_max.version_no + 1) if current_max else 1
        version_dir = BASELINE_OUTPUT_DIR / baseline_id
        upload_version_dir = BASELINE_UPLOAD_DIR / baseline_id / f"v{version_no}"
        version_dir.mkdir(parents=True, exist_ok=True)
        upload_version_dir.mkdir(parents=True, exist_ok=True)

        json_path = write_definition(definition, version_dir, "json")
        yaml_path = write_definition(definition, version_dir, "yaml")
        final_json = version_dir / f"v{version_no}.json"
        final_yaml = version_dir / f"v{version_no}.yaml"
        if final_json.exists():
            final_json.unlink()
        if final_yaml.exists():
            final_yaml.unlink()
        json_path.rename(final_json)
        yaml_path.rename(final_yaml)

        saved_path = upload_version_dir / filename
        shutil.move(str(temp_path), str(saved_path))
        if original_pending_path.exists() and original_pending_path != temp_path:
            original_pending_path.unlink()
        pending_dir = temp_dir / body.upload_id
        if pending_dir.exists():
            shutil.rmtree(pending_dir)
        active_json, active_yaml = _write_active_alias(definition, final_json, final_yaml)
        row = _register_baseline_version(
            db,
            definition,
            final_json,
            final_yaml,
            saved_path,
            body.target_columns,
            admin,
        )
        preview = preview_from_definition(definition)

        return {
            "ok": True,
            "baseline_id": definition.get("baseline_id", ""),
            "baseline_name": definition.get("baseline_name", ""),
            "os_family": definition.get("os_family", ""),
            "source_file": filename,
            "check_count": check_count,
            "version_no": row.version_no,
            "active_files": [active_json.name, active_yaml.name],
            "generated_files": [str(final_json), str(final_yaml)],
            "severity_preview": preview,
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Convert baseline failed: {e}")


@router.post("/baselines/upload")
async def upload_baseline(
    file: UploadFile = File(...),
    target_columns: str | None = Form(None),
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

        overrides = None
        if target_columns:
            overrides = json.loads(target_columns)
        definition = convert_workbook(
            temp_path,
            target_column_overrides=overrides,
            severity_mapping=get_mapping_from_db(db),
        )
        check_count = len(definition.get("checks", []))
        if check_count == 0:
            raise HTTPException(status_code=400, detail="ไฟล์นี้แปลงได้ 0 checks จึงไม่บันทึก baseline")

        json_path = write_definition(definition, BASELINE_OUTPUT_DIR, "json")
        yaml_path = write_definition(definition, BASELINE_OUTPUT_DIR, "yaml")
        shutil.move(str(temp_path), str(saved_path))
        _load_json.cache_clear()

        return {
            "ok": True,
            "baseline_id": definition.get("baseline_id", ""),
            "baseline_name": definition.get("baseline_name", ""),
            "os_family": definition.get("os_family", ""),
            "source_file": filename,
            "check_count": check_count,
            "generated_files": [json_path.name, yaml_path.name],
        }
    except HTTPException:
        if temp_path.exists():
            temp_path.unlink()
        raise
    except Exception as e:
        if temp_path.exists():
            temp_path.unlink()
        raise HTTPException(status_code=400, detail=f"แปลง baseline ไม่สำเร็จ: {e}")


@router.get("/baselines/{baseline_id}/versions")
def list_baseline_versions(
    baseline_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    _seed_versions_from_active_files(db)
    rows = (
        db.query(BaselineVersion)
        .filter(BaselineVersion.baseline_id == baseline_id)
        .order_by(BaselineVersion.version_no.desc())
        .all()
    )
    return [_baseline_version_to_dict(row) for row in rows]


@router.post("/baselines/{baseline_id}/versions/{version_no}/activate")
def activate_baseline_version(
    baseline_id: str,
    version_no: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    row = (
        db.query(BaselineVersion)
        .filter(BaselineVersion.baseline_id == baseline_id, BaselineVersion.version_no == version_no)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Baseline version not found")
    json_path = Path(row.json_path)
    if not json_path.exists():
        raise HTTPException(status_code=404, detail="Baseline version file not found")
    data = _load_json(str(json_path))
    _write_active_alias(data, json_path, Path(row.yaml_path) if row.yaml_path else None)
    db.query(BaselineVersion).filter(BaselineVersion.baseline_id == baseline_id).update({"is_active": False})
    row.is_active = True
    db.commit()
    db.refresh(row)
    return {"ok": True, "active": _baseline_version_to_dict(row)}


@router.post("/baselines/{baseline_id}/rollback")
def rollback_baseline(
    baseline_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    active = (
        db.query(BaselineVersion)
        .filter(BaselineVersion.baseline_id == baseline_id, BaselineVersion.is_active == True)
        .first()
    )
    query = db.query(BaselineVersion).filter(BaselineVersion.baseline_id == baseline_id)
    if active:
        query = query.filter(BaselineVersion.version_no < active.version_no)
    target = query.order_by(BaselineVersion.version_no.desc()).first()
    if not target:
        raise HTTPException(status_code=400, detail="No previous baseline version to rollback")
    json_path = Path(target.json_path)
    if not json_path.exists():
        raise HTTPException(status_code=404, detail="Rollback baseline file not found")
    data = _load_json(str(json_path))
    _write_active_alias(data, json_path, Path(target.yaml_path) if target.yaml_path else None)
    db.query(BaselineVersion).filter(BaselineVersion.baseline_id == baseline_id).update({"is_active": False})
    target.is_active = True
    target.rolled_back_from = active.version_no if active else None
    db.commit()
    db.refresh(target)
    return {"ok": True, "active": _baseline_version_to_dict(target)}


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
    db.delete(row)
    db.commit()
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
    if user.id == admin.id and body.role != "admin":
        raise HTTPException(status_code=400, detail="ไม่สามารถลด role ของตัวเองได้")

    user.role = body.role
    db.commit()
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

    user.hashed_password = get_password_hash(body.new_password)
    db.commit()
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

    db.delete(user)
    db.commit()
    return {"ok": True, "user_id": user_id}
