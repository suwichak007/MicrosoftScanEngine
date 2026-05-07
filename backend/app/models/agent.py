from sqlalchemy import Column, String, DateTime
import datetime
from app.core.database import Base

class AgentToken(Base):
    __tablename__ = "agent_tokens"

    agent_id   = Column(String, primary_key=True, index=True)
    token      = Column(String, unique=True, index=True)
    hostname   = Column(String)
    registered = Column(DateTime, default=datetime.datetime.now)
    last_seen  = Column(DateTime, nullable=True)