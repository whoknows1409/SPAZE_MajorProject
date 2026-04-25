"""
SPAZE Server - Key Distribution API

Agent ↔ Server key exchange endpoints.
The agent requests keys when badge is in range, and stores keys for new files.
"""

import base64
import logging
from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from server.db.database import get_db
from server.db.models import (
    Badge, Device, AccessPolicy, FileKey, BadgeStatus, AuditLog,
)
from server.cache import cache_keys, get_cached_keys

logger = logging.getLogger("spaze-server.keys")

router = APIRouter()


# ============================================================
# Schemas
# ============================================================

class KeyRequest(BaseModel):
    badge_mac: str
    device_hostname: str


class KeyStoreRequest(BaseModel):
    badge_mac: str
    device_hostname: str
    file_path: str
    encrypted_fek: str  # Base64-encoded encrypted key


class KeyDeleteRequest(BaseModel):
    badge_mac: str
    device_hostname: str
    file_path: str


class KeyResponse(BaseModel):
    authorized: bool
    keys: dict = {}  # {filename: base64_key}
    message: str = ""


# ============================================================
# Endpoints
# ============================================================

@router.post("/request", response_model=KeyResponse)
async def request_keys(
    req: KeyRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Agent requests FEKs for decryption.
    
    Flow:
    1. Validate badge is active
    2. Check RBAC policy: does this badge have access to this device?
    3. Return all FEKs for this device (from cache or DB)
    """
    # 1. Validate badge
    badge_result = await db.execute(
        select(Badge).where(Badge.mac_address == req.badge_mac)
    )
    badge = badge_result.scalar_one_or_none()

    if not badge:
        return KeyResponse(authorized=False, message="Badge not registered")
    if badge.status != BadgeStatus.ACTIVE:
        return KeyResponse(authorized=False, message=f"Badge is {badge.status.value}")

    # 2. Find device
    device_result = await db.execute(
        select(Device).where(Device.hostname == req.device_hostname)
    )
    device = device_result.scalar_one_or_none()

    if not device:
        return KeyResponse(authorized=False, message="Device not registered")

    # 3. Check access policy
    policy_result = await db.execute(
        select(AccessPolicy).where(
            and_(
                AccessPolicy.badge_id == badge.id,
                AccessPolicy.device_id == device.id,
                AccessPolicy.is_active == True,
            )
        )
    )
    policy = policy_result.scalars().first()

    if not policy:
        # Log denied access
        audit = AuditLog(
            badge_id=badge.id,
            device_id=device.id,
            action="key_request_denied",
            details=f"No active policy for badge {req.badge_mac} on device {req.device_hostname}",
            timestamp=datetime.utcnow(),
        )
        db.add(audit)
        return KeyResponse(authorized=False, message="No access policy found")

    # Check expiry
    if policy.expires_at and policy.expires_at < datetime.utcnow():
        return KeyResponse(authorized=False, message="Access policy expired")

    # 4. Try cache first
    cached = await get_cached_keys(req.badge_mac, req.device_hostname)
    if cached:
        # Log access
        audit = AuditLog(
            badge_id=badge.id,
            device_id=device.id,
            action="keys_delivered",
            details=f"{len(cached)} keys from cache",
            timestamp=datetime.utcnow(),
        )
        db.add(audit)
        return KeyResponse(authorized=True, keys=cached, message="Keys from cache")

    # 5. Fetch from DB
    key_result = await db.execute(
        select(FileKey).where(FileKey.device_id == device.id)
    )
    file_keys = key_result.scalars().all()

    keys_dict = {}
    for fk in file_keys:
        keys_dict[fk.file_path] = base64.b64encode(fk.encrypted_fek).decode("utf-8")

    # Cache for next time
    if keys_dict:
        await cache_keys(req.badge_mac, req.device_hostname, keys_dict)

    # Log access
    audit = AuditLog(
        badge_id=badge.id,
        device_id=device.id,
        action="keys_delivered",
        details=f"{len(keys_dict)} keys from database",
        timestamp=datetime.utcnow(),
    )
    db.add(audit)

    return KeyResponse(authorized=True, keys=keys_dict, message=f"{len(keys_dict)} keys delivered")


@router.post("/store")
async def store_key(
    req: KeyStoreRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Agent stores a new FEK after encrypting a new file.
    """
    # Find device
    device_result = await db.execute(
        select(Device).where(Device.hostname == req.device_hostname)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=400, detail="Device not registered")

    # Decode the key
    try:
        fek_bytes = base64.b64decode(req.encrypted_fek)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 key")

    # Check if key already exists for this file + device
    existing = await db.execute(
        select(FileKey).where(
            and_(
                FileKey.file_path == req.file_path,
                FileKey.device_id == device.id,
            )
        )
    )
    file_key = existing.scalar_one_or_none()

    if file_key:
        file_key.encrypted_fek = fek_bytes
        file_key.updated_at = datetime.utcnow()
    else:
        file_key = FileKey(
            file_path=req.file_path,
            encrypted_fek=fek_bytes,
            device_id=device.id,
        )
        db.add(file_key)

    await db.flush()

    return {"message": "Key stored", "file_path": req.file_path}


@router.post("/delete")
async def delete_key(
    req: KeyDeleteRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Agent reports a file was deleted — remove the FEK from server.
    """
    device_result = await db.execute(
        select(Device).where(Device.hostname == req.device_hostname)
    )
    device = device_result.scalar_one_or_none()
    if not device:
        raise HTTPException(status_code=400, detail="Device not registered")

    result = await db.execute(
        select(FileKey).where(
            and_(
                FileKey.file_path == req.file_path,
                FileKey.device_id == device.id,
            )
        )
    )
    file_key = result.scalar_one_or_none()

    if file_key:
        await db.delete(file_key)
        return {"message": "Key deleted", "file_path": req.file_path}
    else:
        return {"message": "Key not found", "file_path": req.file_path}
