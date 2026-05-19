import os
import time
import logging
from typing import Dict, List, Tuple, Any, Optional
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, update, delete, func, insert

from app.models.orm import Base, DeduplicationEntry, RemediationRecord, EventCounter, User, UserSession
from app.core.config import settings

logger = logging.getLogger("webhook-gateway.database")

class DatabaseManager:
    """
    Manages all SQLite operations asynchronously for the Webhook Gateway.
    Handles persistent deduplication states, event telemetry counters, and remediation history.
    """
    def __init__(self):
        db_url = f"sqlite+aiosqlite:///{settings.DB_FILE}"
        # Ensure parent directory of DB exists
        os.makedirs(os.path.dirname(os.path.abspath(settings.DB_FILE)), exist_ok=True)
        
        self.engine = create_async_engine(db_url, echo=False)
        self.async_session = sessionmaker(self.engine, class_=AsyncSession, expire_on_commit=False)

    async def initialize_database(self) -> None:
        """Initializes the database schema if tables do not exist."""
        try:
            async with self.engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            
            # Initialize event counters with zero if missing
            async with self.async_session() as session:
                for severity in ["INFO", "WARNING", "CRITICAL"]:
                    stmt = select(EventCounter).where(EventCounter.severity == severity)
                    result = await session.execute(stmt)
                    if not result.scalar_one_or_none():
                        session.add(EventCounter(severity=severity, count=0))
                await session.commit()
            logger.info("SQLite database initialized successfully.")
        except Exception as e:
            logger.error(f"Critical error initializing SQLite database: {e}")

    # ======================================================================
    # DEDUPLICATION LOGIC
    # ======================================================================
    async def get_deduplication_entry(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieves a cached deduplication record."""
        try:
            async with self.async_session() as session:
                stmt = select(DeduplicationEntry).where(DeduplicationEntry.key == key)
                result = await session.execute(stmt)
                row = result.scalar_one_or_none()
                if row:
                    return {
                        "first_seen": row.first_seen,
                        "last_seen": row.last_seen,
                        "count": row.count
                    }
        except Exception as e:
            logger.error(f"Failed to fetch deduplication cache for key '{key}': {e}")
        return None

    async def save_deduplication_entry(self, key: str, first_seen: float, last_seen: float, count: int) -> None:
        """Saves or updates a deduplication record."""
        try:
            async with self.async_session() as session:
                stmt = select(DeduplicationEntry).where(DeduplicationEntry.key == key)
                result = await session.execute(stmt)
                row = result.scalar_one_or_none()
                if row:
                    row.first_seen = first_seen
                    row.last_seen = last_seen
                    row.count = count
                else:
                    session.add(DeduplicationEntry(key=key, first_seen=first_seen, last_seen=last_seen, count=count))
                await session.commit()
        except Exception as e:
            logger.error(f"Failed to save deduplication entry for key '{key}': {e}")

    async def clear_deduplication_cache(self) -> None:
        """Clears all records in deduplication table."""
        try:
            async with self.async_session() as session:
                await session.execute(delete(DeduplicationEntry))
                await session.commit()
        except Exception as e:
            logger.error(f"Failed to clear deduplication cache: {e}")

    # ======================================================================
    # REMEDIATION LEDGER LOGS
    # ======================================================================
    async def add_remediation_record(self, source: str, service: str, command: str, status: int, result: str, host: str) -> None:
        """Appends a completed automatic self-healing operation to the audit log."""
        try:
            async with self.async_session() as session:
                record = RemediationRecord(
                    timestamp=int(time.time()),
                    source=source,
                    service=service,
                    command=command,
                    status=status,
                    result=result,
                    host=host
                )
                session.add(record)
                await session.commit()
        except Exception as e:
            logger.error(f"Failed to write remediation audit log: {e}")

    # ======================================================================
    # METRICS & TELEMETRY
    # ======================================================================
    async def increment_event_counter(self, severity: str) -> None:
        """Increments processed event telemetry counters for dashboard views."""
        try:
            async with self.async_session() as session:
                stmt = select(EventCounter).where(EventCounter.severity == severity)
                result = await session.execute(stmt)
                row = result.scalar_one_or_none()
                if row:
                    row.count += 1
                else:
                    session.add(EventCounter(severity=severity, count=1))
                await session.commit()
        except Exception as e:
            logger.error(f"Failed to increment telemetry event counter: {e}")

    async def get_event_counters(self) -> Dict[str, int]:
        """Collects total processed event metrics categorized by severity level."""
        counters = {"INFO": 0, "WARNING": 0, "CRITICAL": 0}
        try:
            async with self.async_session() as session:
                stmt = select(EventCounter)
                result = await session.execute(stmt)
                for row in result.scalars():
                    counters[row.severity] = row.count
        except Exception as e:
            logger.error(f"Failed to fetch event telemetry: {e}")
        return counters

    async def get_remediation_statistics(self) -> Tuple[int, int]:
        """Calculates successful and failed remediation job counts."""
        try:
            async with self.async_session() as session:
                succeeded_stmt = select(func.count(RemediationRecord.id)).where(RemediationRecord.status == 0)
                failed_stmt = select(func.count(RemediationRecord.id)).where(RemediationRecord.status != 0)
                
                succeeded_res = await session.execute(succeeded_stmt)
                failed_res = await session.execute(failed_stmt)
                
                return succeeded_res.scalar() or 0, failed_res.scalar() or 0
        except Exception as e:
            logger.error(f"Failed to retrieve remediation stats: {e}")
            return 0, 0

    async def get_recent_remediations(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Returns the most recent remediation history records."""
        try:
            async with self.async_session() as session:
                stmt = select(RemediationRecord).order_by(RemediationRecord.id.desc()).limit(limit)
                result = await session.execute(stmt)
                records = []
                for row in result.scalars():
                    records.append({
                        "id": row.id,
                        "timestamp": row.timestamp,
                        "source": row.source,
                        "service": row.service,
                        "command": row.command,
                        "status": row.status,
                        "result": row.result,
                        "host": row.host
                    })
                return records
        except Exception as e:
            logger.error(f"Failed to retrieve recent remediations: {e}")
            return []

    # ======================================================================
    # IDENTITY & ACCESS MANAGEMENT (RBAC)
    # ======================================================================
    async def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieves a user profile."""
        try:
            async with self.async_session() as session:
                stmt = select(User).where(User.username == username)
                result = await session.execute(stmt)
                row = result.scalar_one_or_none()
                if row:
                    return {
                        "username": row.username,
                        "password_hash": row.password_hash,
                        "role": row.role
                    }
        except Exception as e:
            logger.error(f"Failed to read user '{username}': {e}")
        return None

    async def create_user(self, username: str, password_hash: str, role: str = "viewer") -> bool:
        """Registers a new administrative user with strict role privileges."""
        try:
            async with self.async_session() as session:
                user = User(username=username, password_hash=password_hash, role=role)
                session.add(user)
                await session.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to create user '{username}': {e}")
            return False

    async def update_user_role(self, username: str, role: str) -> bool:
        """Modifies authorization privileges of a system user."""
        try:
            async with self.async_session() as session:
                stmt = select(User).where(User.username == username)
                result = await session.execute(stmt)
                user = result.scalar_one_or_none()
                if user:
                    user.role = role
                    await session.commit()
                    return True
        except Exception as e:
            logger.error(f"Failed to update role for '{username}': {e}")
            return False

    async def get_all_users(self) -> List[Dict[str, Any]]:
        """Retrieves all registered user profiles."""
        try:
            async with self.async_session() as session:
                stmt = select(User)
                result = await session.execute(stmt)
                return [{"username": u.username, "role": u.role} for u in result.scalars()]
        except Exception as e:
            logger.error(f"Failed to fetch users: {e}")
            return []

    async def has_users(self) -> bool:
        """Checks if there are any users in the database."""
        try:
            async with self.async_session() as session:
                stmt = select(func.count(User.username))
                result = await session.execute(stmt)
                return (result.scalar() or 0) > 0
        except Exception as e:
            logger.error(f"Failed to check users status: {e}")
            return False

    # ======================================================================
    # PERSISTENT SESSION CONTROLLERS
    # ======================================================================
    async def create_session(self, token: str, username: str, expires_at: float) -> bool:
        """Persists a new authenticated session token."""
        try:
            async with self.async_session() as session:
                sess = UserSession(
                    token=token,
                    username=username,
                    created_at=time.time(),
                    expires_at=expires_at
                )
                session.add(sess)
                await session.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to create user session for '{username}': {e}")
            return False

    async def get_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Retrieves and validates an active user session token."""
        try:
            async with self.async_session() as session:
                stmt = select(UserSession).where(UserSession.token == token)
                result = await session.execute(stmt)
                row = result.scalar_one_or_none()
                if row:
                    return {
                        "token": row.token,
                        "username": row.username,
                        "created_at": row.created_at,
                        "expires_at": row.expires_at
                    }
        except Exception as e:
            logger.error(f"Failed to read session: {e}")
        return None

    async def delete_session(self, token: str) -> bool:
        """Removes an active session (logout)."""
        try:
            async with self.async_session() as session:
                stmt = delete(UserSession).where(UserSession.token == token)
                await session.execute(stmt)
                await session.commit()
                return True
        except Exception as e:
            logger.error(f"Failed to delete session: {e}")
            return False

db_manager = DatabaseManager()
