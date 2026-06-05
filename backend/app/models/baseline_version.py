import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, String

from app.core.database import Base


class BaselineVersion(Base):
    __tablename__ = "baseline_versions"

    id = Column(Integer, primary_key=True, index=True)
    baseline_id = Column(String, index=True, nullable=False)
    version_no = Column(Integer, nullable=False)
    display_name = Column(String, nullable=False)
    filename = Column(String, nullable=False)
    json_path = Column(String, nullable=False)
    yaml_path = Column(String, nullable=True)
    source_file = Column(String, nullable=True)
    check_count = Column(Integer, default=0)
    severity_counts = Column(JSON, default=dict)
    target_columns = Column(JSON, default=dict)
    is_active = Column(Boolean, default=False)
    uploaded_by = Column(Integer, nullable=True)
    uploaded_at = Column(DateTime, default=datetime.datetime.now)
    rolled_back_from = Column(Integer, nullable=True)
