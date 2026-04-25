"""
SPAZE Server - FastAPI Backend
Zero-Trust proximity-based access control server.

Provides:
- Badge/User/Device/Policy management (admin APIs)
- JWT authentication with RBAC
- Key distribution for agent ↔ server communication
- Redis key caching
- Audit logging
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from server.config import get_settings
from server.db.database import init_db, close_db
from server.cache import close_redis

from server.api import auth, badges, users, devices, policies, keys, audit

settings = get_settings()

# Logging
logging.basicConfig(
    level=logging.DEBUG if settings.DEBUG else logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("spaze-server")


# ============================================================
# Lifespan
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown events."""
    logger.info("=" * 50)
    logger.info("🚀 SPAZE Server starting...")
    logger.info(f"   Version: {settings.APP_VERSION}")
    logger.info(f"   Debug: {settings.DEBUG}")
    logger.info("=" * 50)

    # Create database tables
    await init_db()
    logger.info("✅ Database tables ready")

    yield

    # Shutdown
    logger.info("Shutting down SPAZE Server...")
    await close_db()
    await close_redis()
    logger.info("Server stopped")


# ============================================================
# App
# ============================================================

app = FastAPI(
    title=settings.APP_NAME,
    description="Zero-Trust proximity-based file access control backend",
    version=settings.APP_VERSION,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite dev server
        "http://localhost:3000",   # React dev server
        "http://localhost:8080",   # Alt
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Routers
# ============================================================

app.include_router(auth.router,     prefix="/api/auth",           tags=["Authentication"])
app.include_router(badges.router,   prefix="/api/admin/badges",   tags=["Badges"])
app.include_router(users.router,    prefix="/api/admin/users",    tags=["Users"])
app.include_router(devices.router,  prefix="/api/admin/devices",  tags=["Devices"])
app.include_router(policies.router, prefix="/api/admin/policies", tags=["Policies"])
app.include_router(keys.router,     prefix="/api/keys",           tags=["Key Distribution"])
app.include_router(audit.router,    prefix="/api/audit",          tags=["Audit"])


# ============================================================
# Health
# ============================================================

@app.get("/health")
async def health_check():
    """Basic health check."""
    return {"status": "ok", "service": "spaze-server", "version": settings.APP_VERSION}
