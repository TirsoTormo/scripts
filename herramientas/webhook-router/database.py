import os
import sqlite3
import time
import logging
import hashlib
import secrets
from typing import Dict, List, Tuple, Any, Optional

logger = logging.getLogger("webhook-gateway.database")

DB_FILE = "gateway.db"

# ======================================================================
# CRYPTOGRAPHIC SECURITY UTILITIES (PBKDF2 SHA-256)
# ======================================================================
def hash_password(password: str) -> str:
    """Generates a secure NIST-compliant PBKDF2 SHA-256 password hash."""
    salt = secrets.token_hex(16)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000)
    return f"pbkdf2_sha256$100000${salt}${hash_bytes.hex()}"

def verify_password(password: str, hashed: str) -> bool:
    """Validates password input against stored PBKDF2 hash safely."""
    try:
        parts = hashed.split('$')
        if len(parts) != 4 or parts[0] != 'pbkdf2_sha256':
            return False
        iterations = int(parts[1])
        salt = parts[2]
        key_hash = parts[3]
        
        test_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations)
        return secrets.compare_digest(test_hash.hex(), key_hash)
    except Exception:
        return False


class DatabaseManager:
    """
    Manages all SQLite operations for the Webhook Gateway.
    Handles persistent deduplication states, event telemetry counters, and remediation history.
    """
    def __init__(self):
        self.db_path = os.path.abspath(DB_FILE)
        self.initialize_database()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize_database(self):
        """Initializes the database schema if tables do not exist."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # 1. Deduplication cache persistence table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS deduplication_cache (
                        key TEXT PRIMARY KEY,
                        first_seen REAL NOT NULL,
                        last_seen REAL NOT NULL,
                        count INTEGER NOT NULL
                    )
                """)
                
                # 2. Historical remediation log table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS remediation_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp INTEGER NOT NULL,
                        source TEXT NOT NULL,
                        service TEXT NOT NULL,
                        command TEXT NOT NULL,
                        status INTEGER NOT NULL,
                        result TEXT NOT NULL,
                        host TEXT NOT NULL
                    )
                """)
                
                # 3. Telemetry event counters table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS event_counters (
                        severity TEXT PRIMARY KEY,
                        count INTEGER NOT NULL DEFAULT 0
                    )
                """)
                
                # 4. Users RBAC table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        username TEXT PRIMARY KEY,
                        password_hash TEXT NOT NULL,
                        role TEXT NOT NULL DEFAULT 'viewer'
                    )
                """)
                
                # 5. User sessions table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS user_sessions (
                        token TEXT PRIMARY KEY,
                        username TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        expires_at REAL NOT NULL,
                        FOREIGN KEY(username) REFERENCES users(username) ON DELETE CASCADE
                    )
                """)
                
                # Initialize event counters with zero if missing
                for severity in ["INFO", "WARNING", "CRITICAL"]:
                    cursor.execute("""
                        INSERT OR IGNORE INTO event_counters (severity, count)
                        VALUES (?, 0)
                    """, (severity,))
                
                conn.commit()
            logger.info("SQLite database initialized successfully.")
        except Exception as e:
            logger.error(f"Critical error initializing SQLite database: {e}")

    # ======================================================================
    # DEDUPLICATION LOGIC
    # ======================================================================
    def get_deduplication_entry(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieves a cached deduplication record."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT first_seen, last_seen, count FROM deduplication_cache WHERE key = ?", 
                    (key,)
                )
                row = cursor.fetchone()
                if row:
                    return dict(row)
        except Exception as e:
            logger.error(f"Failed to fetch deduplication cache for key '{key}': {e}")
        return None

    def save_deduplication_entry(self, key: str, first_seen: float, last_seen: float, count: int):
        """Saves or updates a deduplication record."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO deduplication_cache (key, first_seen, last_seen, count)
                    VALUES (?, ?, ?, ?)
                """, (key, first_seen, last_seen, count))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to save deduplication entry for key '{key}': {e}")

    def clear_deduplication_cache(self):
        """Wipes all active deduplication entries."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM deduplication_cache")
                conn.commit()
            logger.info("Wiped SQLite deduplication cache.")
        except Exception as e:
            logger.error(f"Failed to wipe deduplication cache: {e}")

    # ======================================================================
    # TELEMETRY AND STATISTICS LOGIC
    # ======================================================================
    def increment_event_counter(self, severity: str):
        """Increments the processed event counter for the specified severity level."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE event_counters 
                    SET count = count + 1 
                    WHERE severity = ?
                """, (severity.upper(),))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to increment event counter for severity '{severity}': {e}")

    def get_event_counters(self) -> Dict[str, int]:
        """Fetches total processed counts for all severity levels."""
        counters = {"INFO": 0, "WARNING": 0, "CRITICAL": 0}
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT severity, count FROM event_counters")
                for row in cursor.fetchall():
                    counters[row["severity"]] = row["count"]
        except Exception as e:
            logger.error(f"Failed to retrieve event statistics: {e}")
        return counters

    # ======================================================================
    # REMEDIATION LOGGING LOGIC
    # ======================================================================
    def add_remediation_record(self, source: str, service: str, command: str, status: int, result: str, host: str):
        """Appends a new SSH execution event record to the database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO remediation_history (timestamp, source, service, command, status, result, host)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (int(time.time()), source, service, command, status, result, host))
                conn.commit()
            logger.info(f"Logged SSH remediation record to SQLite: {source} -> {service}")
        except Exception as e:
            logger.error(f"Failed to log remediation record: {e}")

    def get_remediation_statistics(self) -> Tuple[int, int]:
        """Returns the count of (successful_remediations, failed_remediations)."""
        success = 0
        failed = 0
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM remediation_history WHERE status = 0")
                success = cursor.fetchone()["count"]
                
                cursor.execute("SELECT COUNT(*) as count FROM remediation_history WHERE status != 0")
                failed = cursor.fetchone()["count"]
        except Exception as e:
            logger.error(f"Failed to query remediation statistics: {e}")
        return success, failed

    def get_recent_remediations(self, limit: int = 5) -> List[Dict[str, Any]]:
        """Fetches the last N remediation attempts sorted chronologically."""
        records = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT timestamp, source, service, command, status, result, host 
                    FROM remediation_history 
                    ORDER BY id DESC 
                    LIMIT ?
                """, (limit,))
                for row in cursor.fetchall():
                    records.append(dict(row))
        except Exception as e:
            logger.error(f"Failed to query recent remediations: {e}")
        return records

    # ======================================================================
    # USER MANAGEMENT (RBAC) LOGIC
    # ======================================================================
    def has_users(self) -> bool:
        """Checks if there are any active users registered in the database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) as count FROM users")
                return cursor.fetchone()["count"] > 0
        except Exception as e:
            logger.error(f"Failed to check users presence: {e}")
            return False

    def create_user(self, username: str, password_hash: str, role: str = "viewer") -> bool:
        """Registers a new user inside the SQLite database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users (username, password_hash, role)
                    VALUES (?, ?, ?)
                """, (username.lower().strip(), password_hash, role.lower().strip()))
                conn.commit()
            logger.info(f"Registered new user in database: {username} ({role})")
            return True
        except Exception as e:
            logger.error(f"Failed to create user '{username}': {e}")
            return False

    def get_user(self, username: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single user record from SQLite by username."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT username, password_hash, role FROM users WHERE username = ?", (username.lower().strip(),))
                row = cursor.fetchone()
                if row:
                    return dict(row)
        except Exception as e:
            logger.error(f"Failed to fetch user '{username}': {e}")
        return None

    def get_all_users(self) -> List[Dict[str, Any]]:
        """Fetches a list of all registered users (excluding password hashes for safety)."""
        users_list = []
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT username, role FROM users ORDER BY username ASC")
                for row in cursor.fetchall():
                    users_list.append(dict(row))
        except Exception as e:
            logger.error(f"Failed to retrieve user registry: {e}")
        return users_list

    def update_user_role(self, username: str, role: str) -> bool:
        """Modifies a user's authorization rank (role)."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET role = ? WHERE username = ?", (role.lower().strip(), username.lower().strip()))
                conn.commit()
            logger.info(f"Updated user role for '{username}' to '{role}'")
            return True
        except Exception as e:
            logger.error(f"Failed to update user role for '{username}': {e}")
            return False

    def update_user_password(self, username: str, password_hash: str) -> bool:
        """Updates a user's credential password hash."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?", (password_hash, username.lower().strip()))
                conn.commit()
            logger.info(f"Updated password hash for '{username}'")
            return True
        except Exception as e:
            logger.error(f"Failed to update password for '{username}': {e}")
            return False

    def delete_user(self, username: str) -> bool:
        """Removes a user and cascades their active sessions from the database."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM users WHERE username = ?", (username.lower().strip(),))
                conn.commit()
            logger.info(f"Deleted user '{username}' from registry.")
            return True
        except Exception as e:
            logger.error(f"Failed to delete user '{username}': {e}")
            return False

    # ======================================================================
    # SESSION MANAGEMENT LOGIC
    # ======================================================================
    def create_session(self, token: str, username: str, expires_in_seconds: int = 86400) -> bool:
        """Stores a newly generated login session token inside SQLite."""
        try:
            now = time.time()
            expires_at = now + expires_in_seconds
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO user_sessions (token, username, created_at, expires_at)
                    VALUES (?, ?, ?, ?)
                """, (token, username.lower().strip(), now, expires_at))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to record session for user '{username}': {e}")
            return False

    def get_session(self, token: str) -> Optional[Dict[str, Any]]:
        """Validates and retrieves a session token, cascading expired entries."""
        try:
            now = time.time()
            with self._get_connection() as conn:
                cursor = conn.cursor()
                
                # Automatically delete expired sessions before query
                cursor.execute("DELETE FROM user_sessions WHERE expires_at < ?", (now,))
                
                cursor.execute("""
                    SELECT s.token, s.username, s.expires_at, u.role
                    FROM user_sessions s
                    JOIN users u ON s.username = u.username
                    WHERE s.token = ? AND s.expires_at > ?
                """, (token, now))
                row = cursor.fetchone()
                if row:
                    return dict(row)
        except Exception as e:
            logger.error(f"Failed to fetch session details for token '{token}': {e}")
        return None

    def delete_session(self, token: str) -> bool:
        """Wipes a session token on logout."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM user_sessions WHERE token = ?", (token,))
                conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to remove session: {e}")
            return False


# Initialize database manager singleton
db_manager = DatabaseManager()
