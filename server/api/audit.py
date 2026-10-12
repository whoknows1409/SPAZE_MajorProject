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
from server.security.deps import require_device_signature

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
    signed_device: Optional[Device] = Depends(require_device_signature),
):
    """Agent reports an audit event (signed in PAKL mode)."""
    if signed_device is not None and signed_device.hostname != req.device_hostname:
        raise HTTPException(status_code=403, detail="Device mismatch")
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


@router.get("/analytics")
async def get_analytics(
    days: int = Query(7, le=30),
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin"])),
):
    """Get analytics data for dashboard charts."""
    from sqlalchemy import func, cast, Date
    from datetime import timedelta

    cutoff = datetime.utcnow() - timedelta(days=days)

    # ── 1. Activity over time (events per day) ──
    daily_query = (
        select(
            cast(AuditLog.timestamp, Date).label("date"),
            AuditLog.action,
            func.count().label("count"),
        )
        .where(AuditLog.timestamp >= cutoff)
        .group_by(cast(AuditLog.timestamp, Date), AuditLog.action)
        .order_by(cast(AuditLog.timestamp, Date))
    )
    daily_result = await db.execute(daily_query)
    daily_rows = daily_result.all()

    # Build day-by-day dict
    activity_map = {}
    for row in daily_rows:
        day_str = row.date.isoformat() if hasattr(row.date, 'isoformat') else str(row.date)
        if day_str not in activity_map:
            activity_map[day_str] = {"date": day_str, "unlocks": 0, "locks": 0, "key_requests": 0, "denials": 0}
        if "unlock" in row.action:
            activity_map[day_str]["unlocks"] += row.count
        elif "lock" in row.action:
            activity_map[day_str]["locks"] += row.count
        elif "delivered" in row.action or "stored" in row.action:
            activity_map[day_str]["key_requests"] += row.count
        elif "denied" in row.action:
            activity_map[day_str]["denials"] += row.count

    activity_timeline = list(activity_map.values())

    # ── 2. Action breakdown (for pie chart) ──
    action_query = (
        select(AuditLog.action, func.count().label("count"))
        .where(AuditLog.timestamp >= cutoff)
        .group_by(AuditLog.action)
    )
    action_result = await db.execute(action_query)
    action_breakdown = [
        {"action": row.action.replace("_", " ").title(), "count": row.count}
        for row in action_result.all()
    ]

    # ── 3. RSSI distribution (for bar chart) ──
    rssi_query = (
        select(AuditLog.rssi_value)
        .where(AuditLog.rssi_value.isnot(None))
        .where(AuditLog.timestamp >= cutoff)
    )
    rssi_result = await db.execute(rssi_query)
    rssi_values = [row[0] for row in rssi_result.all()]

    # Bucket into ranges
    rssi_buckets = {
        "Strong (> -50)": 0,
        "Good (-50 to -65)": 0,
        "Fair (-65 to -80)": 0,
        "Weak (< -80)": 0,
    }
    for val in rssi_values:
        if val > -50:
            rssi_buckets["Strong (> -50)"] += 1
        elif val > -65:
            rssi_buckets["Good (-50 to -65)"] += 1
        elif val > -80:
            rssi_buckets["Fair (-65 to -80)"] += 1
        else:
            rssi_buckets["Weak (< -80)"] += 1

    rssi_distribution = [{"range": k, "count": v} for k, v in rssi_buckets.items()]

    # ── 4. Hourly pattern (for area chart) ──
    hourly_query = (
        select(
            func.extract("hour", AuditLog.timestamp).label("hour"),
            func.count().label("count"),
        )
        .where(AuditLog.timestamp >= cutoff)
        .group_by(func.extract("hour", AuditLog.timestamp))
        .order_by(func.extract("hour", AuditLog.timestamp))
    )
    hourly_result = await db.execute(hourly_query)
    hourly_map = {int(row.hour): row.count for row in hourly_result.all()}
    hourly_activity = [
        {"hour": f"{h:02d}:00", "events": hourly_map.get(h, 0)}
        for h in range(24)
    ]

    return {
        "activity_timeline": activity_timeline,
        "action_breakdown": action_breakdown,
        "rssi_distribution": rssi_distribution,
        "hourly_activity": hourly_activity,
    }
