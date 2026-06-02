import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String

from app.core.database import Base


class ScanSchedule(Base):
    __tablename__ = "scan_schedules"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    scan_type = Column(String, nullable=False)  # agent | agent-subnet
    agent_id = Column(String, nullable=True)
    subnet = Column(String, nullable=True)
    version = Column(String, default="auto")
    role = Column(String, default="Member Server")
    frequency = Column(String, default="daily")  # hourly | daily | weekly
    time = Column(String, nullable=True)  # HH:MM for daily/weekly, MM for hourly
    day_of_week = Column(Integer, nullable=True)  # 0=Mon ... 6=Sun
    enabled = Column(Boolean, default=True)
    user_id = Column(Integer, nullable=True)
    last_run = Column(DateTime, nullable=True)
    next_run = Column(DateTime, nullable=True)
    last_job_id = Column(String, nullable=True)
    last_error = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.datetime.now)
    updated_at = Column(DateTime, default=datetime.datetime.now)
