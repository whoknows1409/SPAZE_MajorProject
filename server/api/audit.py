"""
SPAZE Server - Audit Log API

Endpoints for recording and querying audit events.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from server.db.database import get_db
from server.db.models import AuditLog, Badge, Device, User, GeofenceEvent, GeofenceEventType
from server.auth.dependencies import require_role

router = APIRouter()


# ============================================================
# Schemas
# ============================================================

class AuditLogCreate(BaseModel):
    badge_mac: str
    device_hostname: str
    action: str  # vault_unlock, vault_lock, file_decrypt, file_encrypt, etc.
    details: Optional[str] = None
    file_path: Optional[str] = None
    rssi_value: Optional[int] = None
    ip_address: Optional[str] = None


class AuditLogResponse(BaseModel):
    id: int
    badge_mac: Optional[str] = None
    device_hostname: Optional[str] = None
    action: str
    details: Optional[str]
    file_path: Optional[str]
    rssi_value: Optional[int]
    timestamp: datetime

    class Config:
        from_attributes = True


class GeofenceEventCreate(BaseModel):
    badge_mac: str
    anchor_id: str
    event_type: str  # enter or exit
    rssi_value: Optional[int] = None


# ============================================================
# Endpoints
# ============================================================

@router.post("/log")
async def create_audit_log(
    req: AuditLogCreate,
    db: AsyncSession = Depends(get_db),
):
    """Agent reports an audit event."""
    # Resolve badge
    badge_id = None
    badge_result = await db.execute(
        select(Badge).where(Badge.mac_address == req.badge_mac)
    )
    badge = badge_result.scalar_one_or_none()
    if badge:
        badge_id = badge.id

    # Resolve device
    device_id = None
    device_result = await db.execute(
        select(Device).where(Device.hostname == req.device_hostname)
    )
    device = device_result.scalar_one_or_none()
    if device:
        device_id = device.id

    log = AuditLog(
        badge_id=badge_id,
        device_id=device_id,
        action=req.action,
        details=req.details,
        file_path=req.file_path,
        rssi_value=req.rssi_value,
        ip_address=req.ip_address,
    )
    db.add(log)
    await db.flush()

    return {"message": "Audit log recorded", "id": log.id}


@router.get("/logs", response_model=list[AuditLogResponse])
async def get_audit_logs(
    limit: int = Query(50, le=500),
    action: Optional[str] = None,
    badge_mac: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin", "manager"])),
):
    """Query audit logs (admin/manager only)."""
    from sqlalchemy.orm import selectinload

    query = (
        select(AuditLog)
        .options(selectinload(AuditLog.badge))
        .order_by(desc(AuditLog.timestamp))
        .limit(limit)
    )

    if action:
        query = query.where(AuditLog.action == action)

    if badge_mac:
        badge_result = await db.execute(
            select(Badge).where(Badge.mac_address == badge_mac)
        )
        badge = badge_result.scalar_one_or_none()
        if badge:
            query = query.where(AuditLog.badge_id == badge.id)

    result = await db.execute(query)
    logs = result.scalars().all()

    response = []
    for log in logs:
        badge_mac_val = None
        if log.badge:
            badge_mac_val = log.badge.mac_address
        response.append(AuditLogResponse(
            id=log.id,
            badge_mac=badge_mac_val,
            action=log.action,
            details=log.details,
            file_path=log.file_path,
            rssi_value=log.rssi_value,
            timestamp=log.timestamp,
        ))
    return response


@router.post("/geofence")
async def record_geofence_event(
    req: GeofenceEventCreate,
    db: AsyncSession = Depends(get_db),
):
    """Record a badge enter/exit geofence event from the agent."""
    badge_result = await db.execute(
        select(Badge).where(Badge.mac_address == req.badge_mac)
    )
    badge = badge_result.scalar_one_or_none()
    if not badge:
        raise HTTPException(status_code=400, detail="Badge not registered")

    try:
        event_type = GeofenceEventType(req.event_type)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid event type: {req.event_type}")

    event = GeofenceEvent(
        badge_id=badge.id,
        anchor_id=req.anchor_id,
        event_type=event_type,
        rssi_value=req.rssi_value,
    )
    db.add(event)
    await db.flush()

    return {"message": "Geofence event recorded", "id": event.id}


@router.get("/stats")
async def get_stats(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin"])),
):
    """Get dashboard stats (admin only)."""
    from sqlalchemy import func

    badge_count = await db.execute(select(func.count(Badge.id)))
    user_count = await db.execute(select(func.count(User.id)))
    device_count = await db.execute(select(func.count(Device.id)))
    log_count = await db.execute(select(func.count(AuditLog.id)))

    return {
        "total_badges": badge_count.scalar(),
        "total_users": user_count.scalar(),
        "total_devices": device_count.scalar(),
        "total_audit_logs": log_count.scalar(),
    }
