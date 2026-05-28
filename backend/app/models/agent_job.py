import datetime

from sqlalchemy import Column, DateTime, Integer, JSON, String

from app.core.database import Base


class AgentJob(Base):
    __tablename__ = "agent_jobs"

    job_id = Column(String, primary_key=True, index=True)
    agent_id = Column(String, index=True, nullable=False)
    status = Column(String, index=True, default="pending")
    version = Column(String, nullable=True)
    role = Column(String, nullable=True)
    baseline_path = Column(String, nullable=True)
    payload = Column(JSON, nullable=True)
    result = Column(JSON, nullable=True)
    error = Column(String, nullable=True)
    attempts = Column(Integer, default=0)
    user_id = Column(Integer, nullable=True)
    parent_scan_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now)
    picked_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, default=datetime.datetime.now)
