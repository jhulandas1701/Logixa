"""Durable event storage for the pipeline.

processor.py wants a SQLAlchemy SessionLocal + EventRecord model to persist
every normalized event to. An MVP doesn't need a separate database service —
SQLite on the same /data volume already used for profiles and lineage is
enough, and it's a drop-in swap for Postgres later (just change DATABASE_URL).
"""
import os
from datetime import datetime
from pathlib import Path

from sqlalchemy import Column, DateTime, Float, String, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

DATA_DIR = Path(os.getenv("PIPELINE_DATA_DIR", "/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'logixa.db'}")

_connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=_connect_args, future=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)
Base = declarative_base()


class EventRecord(Base):
    __tablename__ = "events"

    event_id = Column(String, primary_key=True)
    raw_event_id = Column(String, index=True, nullable=True)
    source_profile = Column(String, nullable=True)
    parser_version = Column(String, nullable=True)
    schema_version = Column(String, nullable=True)
    confidence = Column(Float, default=0.0)
    status = Column(String, default="normalized")
    raw_event = Column(Text, nullable=True)
    normalized_json = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


Base.metadata.create_all(bind=engine)
