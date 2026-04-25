"""
SPAZE Server - Badge Management API

Admin endpoints for badge registration and management.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.db.database import get_db
from server.db.models import Badge, BadgeStatus, User
from server.auth.dependencies import get_current_user, require_role

router = APIRouter()


# ============================================================
# Schemas
# ============================================================

class BadgeCreate(BaseModel):
    mac_address: str
    badge_name: Optional[str] = None
    hmac_secret: Optional[str] = None


class BadgeUpdate(BaseModel):
    badge_name: Optional[str] = None
    status: Optional[str] = None
    hmac_secret: Optional[str] = None


class BadgeResponse(BaseModel):
    id: int
    mac_address: str
    badge_name: Optional[str]
    status: str
    registered_at: datetime
    assigned_user: Optional[str] = None

    class Config:
        from_attributes = True


# ============================================================
# Endpoints
# ============================================================

@router.post("/", response_model=BadgeResponse)
async def register_badge(
    req: BadgeCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin"])),
):
    """Register a new badge (admin only)."""
    # Check duplicate MAC
    existing = await db.execute(
        select(Badge).where(Badge.mac_address == req.mac_address)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Badge MAC already registered")

    badge = Badge(
        mac_address=req.mac_address,
        badge_name=req.badge_name,
        hmac_secret=req.hmac_secret,
        status=BadgeStatus.ACTIVE,
    )
    db.add(badge)
    await db.flush()
    await db.refresh(badge)

    return BadgeResponse(
        id=badge.id,
        mac_address=badge.mac_address,
        badge_name=badge.badge_name,
        status=badge.status.value,
        registered_at=badge.registered_at,
    )


@router.get("/", response_model=list[BadgeResponse])
async def list_badges(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin", "manager"])),
):
    """List all registered badges."""
    from sqlalchemy.orm import selectinload

    result = await db.execute(
        select(Badge).options(selectinload(Badge.user)).order_by(Badge.id)
    )
    badges = result.scalars().all()

    response = []
    for badge in badges:
        user_name = None
        if badge.user:
            user_name = badge.user.name
        response.append(BadgeResponse(
            id=badge.id,
            mac_address=badge.mac_address,
            badge_name=badge.badge_name,
            status=badge.status.value,
            registered_at=badge.registered_at,
            assigned_user=user_name,
        ))
    return response


@router.patch("/{badge_id}", response_model=BadgeResponse)
async def update_badge(
    badge_id: int,
    req: BadgeUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin"])),
):
    """Update badge status or info (admin only)."""
    result = await db.execute(select(Badge).where(Badge.id == badge_id))
    badge = result.scalar_one_or_none()

    if not badge:
        raise HTTPException(status_code=404, detail="Badge not found")

    if req.badge_name is not None:
        badge.badge_name = req.badge_name
    if req.hmac_secret is not None:
        badge.hmac_secret = req.hmac_secret
    if req.status is not None:
        try:
            badge.status = BadgeStatus(req.status)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid status: {req.status}")

    await db.flush()
    await db.refresh(badge)

    return BadgeResponse(
        id=badge.id,
        mac_address=badge.mac_address,
        badge_name=badge.badge_name,
        status=badge.status.value,
        registered_at=badge.registered_at,
    )
