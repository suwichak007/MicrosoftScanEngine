#!/usr/bin/env python
"""One-time migration from the legacy SQLite runtime DB to PostgreSQL.

Example:
  python tools/migrate_sqlite_to_postgres.py ^
    --sqlite runtime/sql_app.db ^
    --database-url postgresql+psycopg://scan_user:password@host:5432/microsoft_scan_engine
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Iterable

from sqlalchemy import create_engine, func, inspect, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.sql.sqltypes import Integer


ROOT_DIR = Path(__file__).resolve().parents[1]
BACKEND_DIR = ROOT_DIR / "backend"
sys.path.insert(0, str(BACKEND_DIR))

from app.core.database import Base  # noqa: E402

# Import models so SQLAlchemy registers every table in Base.metadata.
from app.models.agent import AgentToken  # noqa: F401,E402
from app.models.agent_job import AgentJob  # noqa: F401,E402
from app.models.activity_log import ActivityLog  # noqa: F401,E402
from app.models.baseline_version import BaselineVersion  # noqa: F401,E402
from app.models.scan import ScanResult  # noqa: F401,E402
from app.models.scan_schedule import ScanSchedule  # noqa: F401,E402
from app.models.severity_mapping import SeverityMapping  # noqa: F401,E402
from app.models.user import User  # noqa: F401,E402


TABLE_ORDER = [
    "users",
    "scan_results",
    "agent_tokens",
    "agent_jobs",
    "activity_logs",
    "scan_schedules",
    "baseline_versions",
    "severity_mappings",
]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Migrate SecureScan SQLite data to PostgreSQL.")
    parser.add_argument("--sqlite", required=True, help="Path to the source SQLite DB, e.g. runtime/sql_app.db")
    parser.add_argument("--database-url", required=True, help="Target PostgreSQL SQLAlchemy URL")
    parser.add_argument("--force", action="store_true", help="Delete target rows before importing")
    return parser.parse_args()


def sqlite_url(path: str) -> str:
    db_path = Path(path)
    if not db_path.is_absolute():
        db_path = ROOT_DIR / db_path
    if not db_path.exists():
        raise SystemExit(f"SQLite source not found: {db_path}")
    return f"sqlite:///{db_path.as_posix()}"


def count_rows(engine: Engine, table_name: str) -> int:
    table = Base.metadata.tables[table_name]
    with engine.connect() as conn:
        return int(conn.execute(select(func.count()).select_from(table)).scalar_one())


def available_source_tables(source_engine: Engine) -> set[str]:
    return set(inspect(source_engine).get_table_names())


def target_has_data(target_engine: Engine, table_names: Iterable[str]) -> bool:
    return any(count_rows(target_engine, table_name) > 0 for table_name in table_names)


def reset_postgres_sequences(target_engine: Engine, table_names: Iterable[str]) -> None:
    if target_engine.dialect.name != "postgresql":
        return
    with target_engine.begin() as conn:
        for table_name in table_names:
            table = Base.metadata.tables[table_name]
            integer_pk = [
                col.name
                for col in table.primary_key.columns
                if isinstance(col.type, Integer)
            ]
            if len(integer_pk) != 1:
                continue
            column_name = integer_pk[0]
            conn.execute(text(
                f"""
                SELECT setval(
                    pg_get_serial_sequence('{table_name}', '{column_name}'),
                    GREATEST(COALESCE((SELECT MAX("{column_name}") FROM "{table_name}"), 0), 1),
                    true
                )
                WHERE pg_get_serial_sequence('{table_name}', '{column_name}') IS NOT NULL
                """
            ))


def migrate(source_engine: Engine, target_engine: Engine, force: bool) -> None:
    source_tables = available_source_tables(source_engine)
    table_names = [name for name in TABLE_ORDER if name in Base.metadata.tables]

    print("Creating target schema if needed...")
    Base.metadata.create_all(bind=target_engine)

    if target_has_data(target_engine, table_names):
        if not force:
            raise SystemExit(
                "Target PostgreSQL database already contains data. "
                "Re-run with --force only if you intentionally want to replace target rows."
            )
        print("Force enabled: deleting target rows before import...")
        with target_engine.begin() as conn:
            for table_name in reversed(table_names):
                conn.execute(Base.metadata.tables[table_name].delete())

    print("Migrating rows...")
    migrated: dict[str, int] = {}
    with source_engine.connect() as source_conn, target_engine.begin() as target_conn:
        for table_name in table_names:
            if table_name not in source_tables:
                print(f"  {table_name}: skipped, source table not found")
                migrated[table_name] = 0
                continue
            table = Base.metadata.tables[table_name]
            rows = [dict(row._mapping) for row in source_conn.execute(table.select()).fetchall()]
            if rows:
                target_conn.execute(table.insert(), rows)
            migrated[table_name] = len(rows)
            print(f"  {table_name}: {len(rows)} rows")

    reset_postgres_sequences(target_engine, table_names)

    print("Verifying target counts...")
    for table_name in table_names:
        target_count = count_rows(target_engine, table_name)
        expected = migrated.get(table_name, 0)
        status = "OK" if target_count == expected else f"expected {expected}"
        print(f"  {table_name}: {target_count} rows ({status})")


def main() -> None:
    args = parse_args()
    if not args.database_url.startswith(("postgresql://", "postgresql+psycopg://", "postgres://")):
        raise SystemExit("Target --database-url must be a PostgreSQL URL.")

    os.environ.setdefault("DATABASE_URL", args.database_url)
    source_engine = create_engine(sqlite_url(args.sqlite))
    target_engine = create_engine(args.database_url)
    migrate(source_engine, target_engine, args.force)
    print("Migration complete.")


if __name__ == "__main__":
    main()
