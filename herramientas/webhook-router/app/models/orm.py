from sqlalchemy import Column, Integer, String, Float, ForeignKey
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

class DeduplicationEntry(Base):
    __tablename__ = "deduplication_cache"

    key = Column(String, primary_key=True, index=True)
    first_seen = Column(Float, nullable=False)
    last_seen = Column(Float, nullable=False)
    count = Column(Integer, nullable=False)

class RemediationRecord(Base):
    __tablename__ = "remediation_history"

    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(Integer, nullable=False)
    source = Column(String, nullable=False)
    service = Column(String, nullable=False)
    command = Column(String, nullable=False)
    status = Column(Integer, nullable=False)
    result = Column(String, nullable=False)
    host = Column(String, nullable=False)

class EventCounter(Base):
    __tablename__ = "event_counters"

    severity = Column(String, primary_key=True, index=True)
    count = Column(Integer, nullable=False, default=0)

class User(Base):
    __tablename__ = "users"

    username = Column(String, primary_key=True, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False, default="viewer")

class UserSession(Base):
    __tablename__ = "user_sessions"

    token = Column(String, primary_key=True, index=True)
    username = Column(String, ForeignKey("users.username", ondelete="CASCADE"), nullable=False)
    created_at = Column(Float, nullable=False)
    expires_at = Column(Float, nullable=False)
