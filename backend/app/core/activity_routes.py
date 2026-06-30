from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.security import get_current_user
from app.models.activity_log import ActivityLog
from app.models.user import User

router = APIRouter(prefix="/api/admin/activity", tags=["activity"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def require_admin_or_owner(current_user: User = Depends(get_current_user)) -> User:
    if current_user.role not in ("admin", "owner"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin permission required")
    return current_user


def log_activity(
    db: Session,
    *,
    actor: User | None = None,
    action: str,
    target_type: str = "",
    target_id: str | int = "",
    status_value: str = "success",
    detail: dict | None = None,
) -> None:
    try:
        row = ActivityLog(
            actor_id=getattr(actor, "id", None),
            actor_username=getattr(actor, "username", "") or "",
            actor_role=getattr(actor, "role", "") or "",
            action=action,
            target_type=target_type,
            target_id=str(target_id or ""),
            status=status_value,
            detail=detail or {},
        )
        db.add(row)
        db.commit()
    except Exception:
        db.rollback()


def _activity_to_dict(row: ActivityLog) -> dict:
    return {
        "id": row.id,
        "actor_id": row.actor_id,
        "actor_username": row.actor_username or "",
        "actor_role": row.actor_role or "",
        "action": row.action,
        "target_type": row.target_type or "",
        "target_id": row.target_id or "",
        "status": row.status or "",
        "detail": row.detail or {},
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("")
def list_activity(
    limit: int = 100,
    action: str = "",
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin_or_owner),
):
    size = max(1, min(int(limit or 100), 500))
    query = db.query(ActivityLog)
    if action.strip():
        query = query.filter(ActivityLog.action == action.strip())
    rows = query.order_by(ActivityLog.created_at.desc(), ActivityLog.id.desc()).limit(size).all()
    return [_activity_to_dict(row) for row in rows]
