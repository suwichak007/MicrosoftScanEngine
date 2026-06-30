from sqlalchemy import Column, DateTime, Integer, String, JSON
from app.core.database import Base
import datetime


class ActivityLog(Base):
    __tablename__ = "activity_logs"

    id = Column(Integer, primary_key=True, index=True)
    actor_id = Column(Integer, index=True, nullable=True)
    actor_username = Column(String, index=True, default="")
    actor_role = Column(String, default="")
    action = Column(String, index=True, nullable=False)
    target_type = Column(String, index=True, default="")
    target_id = Column(String, index=True, default="")
    status = Column(String, index=True, default="success")
    detail = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
