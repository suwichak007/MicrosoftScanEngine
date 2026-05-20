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

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.security import get_current_user, get_password_hash
from app.models.user import User

router = APIRouter(prefix="/api/admin", tags=["admin"])


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
