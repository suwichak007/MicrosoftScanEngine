import datetime

from sqlalchemy import Column, DateTime, Integer, JSON

from app.core.database import Base


class SeverityMapping(Base):
    __tablename__ = "severity_mappings"

    id = Column(Integer, primary_key=True, index=True)
    category_mapping = Column(JSON, default=dict)
    keyword_overrides = Column(JSON, default=dict)
    updated_by = Column(Integer, nullable=True)
    updated_at = Column(DateTime, default=datetime.datetime.now)
