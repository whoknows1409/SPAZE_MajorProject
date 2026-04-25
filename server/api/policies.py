"""
SPAZE Server - Access Policy API

Admin endpoints for granting/revoking badge→device access.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.db.database import get_db
from server.db.models import AccessPolicy, Badge, Device, User
from server.auth.dependencies import require_role

router = APIRouter()


# ============================================================
# Schemas
# ============================================================

class PolicyCreate(BaseModel):
    badge_id: int
    device_id: int
    allowed_directories: Optional[str] = None  # JSON string
    expires_at: Optional[datetime] = None


class PolicyResponse(BaseModel):
    id: int
    badge_id: int
    badge_mac: Optional[str] = None
    device_id: int
    device_hostname: Optional[str] = None
    allowed_directories: Optional[str]
    granted_by: int
    is_active: bool
    expires_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================
# Endpoints
# ============================================================

@router.post("/", response_model=PolicyResponse)
async def create_policy(
    req: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin", "manager"])),
):
    """Grant a badge access to a device (admin/manager only)."""
    # Validate badge
    badge_result = await db.execute(select(Badge).where(Badge.id == req.badge_id))
    badge = badge_result.scalar_one_or_none()
    if not badge:
        raise HTTPException(status_code=400, detail="Badge not found")

    # Validate device
    device_result = await db.execute(select(Device).where(Device.id == req.device_id))
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=400, detail="Device not found")

    policy = AccessPolicy(
        badge_id=req.badge_id,
        device_id=req.device_id,
        allowed_directories=req.allowed_directories,
        granted_by=admin.id,
        expires_at=req.expires_at,
    )
    db.add(policy)
    await db.flush()
    await db.refresh(policy)

    return PolicyResponse(
        id=policy.id,
        badge_id=policy.badge_id,
        badge_mac=badge.mac_address,
        device_id=policy.device_id,
        device_hostname=device.hostname,
        allowed_directories=policy.allowed_directories,
        granted_by=policy.granted_by,
        is_active=policy.is_active,
        expires_at=policy.expires_at,
        created_at=policy.created_at,
    )


@router.get("/", response_model=list[PolicyResponse])
async def list_policies(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin", "manager"])),
):
    """List all access policies."""
    from sqlalchemy.orm import selectinload

    result = await db.execute(
        select(AccessPolicy)
        .options(selectinload(AccessPolicy.badge), selectinload(AccessPolicy.device))
        .order_by(AccessPolicy.id)
    )
    policies = result.scalars().all()

    response = []
    for policy in policies:
        badge_mac = None
        device_hostname = None
        if policy.badge:
            badge_mac = policy.badge.mac_address
        if policy.device:
            device_hostname = policy.device.hostname
        response.append(PolicyResponse(
            id=policy.id,
            badge_id=policy.badge_id,
            badge_mac=badge_mac,
            device_id=policy.device_id,
            device_hostname=device_hostname,
            allowed_directories=policy.allowed_directories,
            granted_by=policy.granted_by,
            is_active=policy.is_active,
            expires_at=policy.expires_at,
            created_at=policy.created_at,
        ))
    return response


@router.delete("/{policy_id}")
async def revoke_policy(
    policy_id: int,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin", "manager"])),
):
    """Revoke an access policy."""
    result = await db.execute(select(AccessPolicy).where(AccessPolicy.id == policy_id))
    policy = result.scalar_one_or_none()

    if not policy:
        raise HTTPException(status_code=404, detail="Policy not found")

    policy.is_active = False
    await db.flush()

    return {"message": "Policy revoked", "policy_id": policy_id}
