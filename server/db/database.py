"""
SPAZE Server - Database Connection

Async SQLAlchemy engine + session factory for PostgreSQL.
"""

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from server.config import get_settings

settings = get_settings()

# Async engine for FastAPI
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    pool_size=10,
    max_overflow=20,
)

# Session factory
async_session = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db():
    """FastAPI dependency — yields a database session."""
    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Create all tables (called on server startup)."""
    from server.db.models import Base as ModelsBase
    async with engine.begin() as conn:
        await conn.run_sync(ModelsBase.metadata.create_all)
        # Additive migrations for columns added after the tables existed
        for stmt in MIGRATIONS:
            await conn.execute(text(stmt))


# Idempotent column additions (PostgreSQL)
MIGRATIONS = [
    "ALTER TABLE badges ADD COLUMN IF NOT EXISTS tok_last_counter BIGINT",
    "ALTER TABLE badges ADD COLUMN IF NOT EXISTS tok_offset_ref DOUBLE PRECISION",
    "ALTER TABLE badges ADD COLUMN IF NOT EXISTS tok_ref_time DOUBLE PRECISION",
    "ALTER TABLE badges ADD COLUMN IF NOT EXISTS tok_last_counter_time DOUBLE PRECISION",
    "ALTER TABLE devices ADD COLUMN IF NOT EXISTS api_secret VARCHAR(128)",
    "ALTER TABLE devices ADD COLUMN IF NOT EXISTS anchor_secret VARCHAR(128)",
    # wrapped secrets are longer than the original 64-hex column
    "ALTER TABLE badges ALTER COLUMN hmac_secret TYPE VARCHAR(128)",
    "ALTER TABLE devices ALTER COLUMN api_secret TYPE VARCHAR(128)",
]


async def close_db():
    """Close engine (called on server shutdown)."""
    await engine.dispose()
