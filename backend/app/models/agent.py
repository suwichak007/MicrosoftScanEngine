from sqlalchemy import Column, String, DateTime, JSON
import datetime
from app.core.database import Base

class AgentToken(Base):
    __tablename__ = "agent_tokens"

    agent_id   = Column(String, primary_key=True, index=True)
    token      = Column(String, unique=True, index=True)
    hostname   = Column(String)
    ip_addresses = Column(JSON, nullable=True)
    agent_version = Column(String, nullable=True)
    os_name = Column(String, nullable=True)
    os_version = Column(String, nullable=True)
    os_build = Column(String, nullable=True)
    os_release = Column(String, nullable=True)
    os_family = Column(String, nullable=True)
    detected_role = Column(String, nullable=True)
    last_error = Column(String, nullable=True)
    last_error_at = Column(DateTime, nullable=True)
    registered = Column(DateTime, default=datetime.datetime.now)
    last_seen  = Column(DateTime, nullable=True)
