"""
PostgreSQL database connection and helpers for user authentication.
Uses psycopg2 with a thread-safe connection pool so multiple users can use
the app concurrently without exhausting database connections.
Set DATABASE_URL env var or default to localhost.
"""
import logging
import os
import threading

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

log = logging.getLogger(__name__)

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/logviewer",
)

# Pool sizes: enough for concurrent signup/login/search (search doesn't use DB)
POOL_MIN_CONN = 2
POOL_MAX_CONN = 20

_pool = None
_pool_lock = threading.Lock()


def _get_pool():
    """Create or return the thread-safe connection pool (lazy init)."""
    log.info("[ENTER] _get_pool input=(none)")
    global _pool
    if _pool is not None:
        log.info("[EXIT] _get_pool output=existing_pool")
        return _pool
    with _pool_lock:
        if _pool is not None:
            log.info("[EXIT] _get_pool output=existing_pool")
            return _pool
        try:
            import psycopg2.pool
            _pool = psycopg2.pool.ThreadedConnectionPool(
                POOL_MIN_CONN,
                POOL_MAX_CONN,
                DATABASE_URL,
            )
            log.info("[EXIT] _get_pool output=pool_created min=%s max=%s", POOL_MIN_CONN, POOL_MAX_CONN)
            return _pool
        except Exception as e:
            log.error("Database pool failed: %s", e)
            raise


class _PooledConnectionWrapper:
    """Wraps a pooled connection so .close() returns it to the pool instead of closing."""

    def __init__(self, conn, pool):
        self._conn = conn
        self._pool = pool

    def close(self):
        if self._pool and self._conn:
            try:
                self._pool.putconn(self._conn)
            except Exception:
                pass
            self._conn = None
            self._pool = None

    def cursor(self, *args, **kwargs):
        return self._conn.cursor(*args, **kwargs)

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def __getattr__(self, name):
        return getattr(self._conn, name)


def get_connection():
    """
    Get a database connection from the pool. Safe for concurrent use.
    Caller must call .close() when done; the connection is returned to the pool.
    """
    log.info("[ENTER] get_connection input=(none)")
    pool = _get_pool()
    conn = pool.getconn()
    log.info("[EXIT] get_connection output=PooledConnectionWrapper")
    return _PooledConnectionWrapper(conn, pool)


def init_db():
    """Create users table if it does not exist. Uses the connection pool."""
    log.info("[ENTER] init_db input=(none)")
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()
        log.info("[EXIT] init_db output=ok (users table ready)")
    finally:
        conn.close()
