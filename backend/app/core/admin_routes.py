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
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.security import get_current_user, get_password_hash
from app.core.scan.scanner.baseline_config import list_available_versions, _load_json
from app.models.user import User

ROOT_DIR = Path(__file__).resolve().parents[3]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from tools.convert_baselines import convert_workbook, write_definition

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


def _safe_filename(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._ -]+", "_", Path(name).name).strip(" .")
    return cleaned or "baseline.xlsx"


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
def list_baselines(admin: User = Depends(require_admin)):
    return list_available_versions(str(BASELINE_OUTPUT_DIR))


@router.post("/baselines/upload")
async def upload_baseline(
    file: UploadFile = File(...),
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

        definition = convert_workbook(temp_path)
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
