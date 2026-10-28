"""Database setup: engine and sessions configured via DATABASE_URL."""

import os

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

# SQLite fallback keeps local development working without a PostgreSQL server;
# deployments always set DATABASE_URL (postgresql+psycopg://...).
DEFAULT_URL = "sqlite:///./secaudit-web.db"


class Base(DeclarativeBase):
    pass


_engine = None
_session_factory = None


def database_url() -> str:
    return os.environ.get("DATABASE_URL", DEFAULT_URL)


def get_engine():
    global _engine, _session_factory
    if _engine is None:
        url = database_url()
        kwargs = {"pool_pre_ping": True}
        if url.startswith("sqlite"):
            kwargs = {"connect_args": {"check_same_thread": False}}
        _engine = create_engine(url, **kwargs)
        if url.startswith("sqlite"):
            # SQLite ignores foreign keys unless told otherwise per connection,
            # and then ON DELETE CASCADE does nothing: deleting an audit would
            # leave its divergences, paths and runs behind. PostgreSQL always
            # enforces them, so development behaves like production.
            event.listen(_engine, "connect", _enable_sqlite_foreign_keys)
        _session_factory = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def _enable_sqlite_foreign_keys(dbapi_connection, _record) -> None:
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_session():
    get_engine()
    return _session_factory()


def reset_engine() -> None:
    """Dispose the cached engine so DATABASE_URL is re-read (used by tests)."""
    global _engine, _session_factory
    if _engine is not None:
        _engine.dispose()
    _engine = None
    _session_factory = None
