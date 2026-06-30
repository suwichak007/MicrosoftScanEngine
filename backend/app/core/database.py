import os
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker


SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./sql_app.db")


def get_database_dialect(database_url: str | None = None) -> str:
    url = database_url or SQLALCHEMY_DATABASE_URL
    if url.startswith("sqlite"):
        return "sqlite"
    if url.startswith("postgresql") or url.startswith("postgres"):
        return "postgresql"
    return url.split(":", 1)[0] or "unknown"


def mask_database_url(database_url: str | None = None) -> str:
    url = database_url or SQLALCHEMY_DATABASE_URL
    if "://" not in url:
        return url
    parsed = urlsplit(url)
    if parsed.password is None:
        return url
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    user = parsed.username or ""
    netloc = f"{user}:***@{host}" if user else host
    return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))


engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False} if get_database_dialect() == "sqlite" else {},
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
