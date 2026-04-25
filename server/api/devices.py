"""
SPAZE Server - Device Management API

Register and manage anchor devices (workstations).
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.db.database import get_db
from server.db.models import Device, User
from server.auth.dependencies import require_role

router = APIRouter()


# ============================================================
# Schemas
# ============================================================

class DeviceCreate(BaseModel):
    hostname: str
    mac_address: str
    location: Optional[str] = None


class DeviceResponse(BaseModel):
    id: int
    hostname: str
    mac_address: str
    location: Optional[str]
    is_active: bool
    registered_at: datetime

    class Config:
        from_attributes = True


# ============================================================
# Endpoints
# ============================================================

@router.post("/", response_model=DeviceResponse)
async def register_device(
    req: DeviceCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin"])),
):
    """Register a new device/workstation (admin only)."""
    existing = await db.execute(
        select(Device).where(Device.mac_address == req.mac_address)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Device MAC already registered")

    device = Device(
        hostname=req.hostname,
        mac_address=req.mac_address,
        location=req.location,
    )
    db.add(device)
    await db.flush()
    await db.refresh(device)

    return DeviceResponse(
        id=device.id,
        hostname=device.hostname,
        mac_address=device.mac_address,
        location=device.location,
        is_active=device.is_active,
        registered_at=device.registered_at,
    )


@router.get("/", response_model=list[DeviceResponse])
async def list_devices(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin", "manager"])),
):
    """List all registered devices."""
    result = await db.execute(select(Device).order_by(Device.id))
    devices = result.scalars().all()

    return [
        DeviceResponse(
            id=d.id,
            hostname=d.hostname,
            mac_address=d.mac_address,
            location=d.location,
            is_active=d.is_active,
            registered_at=d.registered_at,
        )
        for d in devices
    ]
