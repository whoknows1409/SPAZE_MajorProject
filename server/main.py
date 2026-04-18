"""
SecureZone Server - FastAPI Backend
Zero-Trust proximity-based access control server.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="SecureZone Server",
    description="Zero-Trust proximity-based file access control backend",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Dashboard dev server
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health_check():
    return {"status": "ok", "service": "securezone-server"}


# TODO: Include routers
# from api import badges, keys, policies, audit
# app.include_router(badges.router, prefix="/api/admin/badges", tags=["badges"])
# app.include_router(keys.router, prefix="/api/keys", tags=["keys"])
# app.include_router(policies.router, prefix="/api/admin/policies", tags=["policies"])
# app.include_router(audit.router, prefix="/api/audit", tags=["audit"])
