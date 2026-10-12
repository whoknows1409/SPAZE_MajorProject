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
from server.cache import get_cached_keys, cache_keys, invalidate_keys
from server.security import pakl
from server.security.deps import (
    pakl_enabled, master_key, require_device_signature, verify_presence,
    create_lease, get_lease, extend_lease, end_lease, allow_cr_retry, audit,
    cr_enabled, issue_challenge, check_cr,
)
from server.config import get_settings

logger = logging.getLogger("spaze-server.keys")

router = APIRouter()
settings = get_settings()


# ============================================================
# Schemas
# ============================================================

class KeyRequest(BaseModel):
    badge_mac: str
    device_hostname: str
    presence_token: Optional[str] = None  # PAKL: rolling badge token (hex)
    cr: Optional[dict] = None             # PAKL-CR: answer to a server challenge


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
    lease_id: Optional[str] = None     # PAKL only
    lease_ttl: Optional[float] = None  # PAKL only
    challenge: Optional[str] = None    # PAKL-CR: challenge for the next renewal


class LeaseRenewRequest(BaseModel):
    badge_mac: str
    device_hostname: str
    lease_id: str
    presence_token: Optional[str] = None
    cr: Optional[dict] = None


class LeaseRenewResponse(BaseModel):
    renewed: bool
    retry: bool = False
    message: str = ""
    lease_ttl: Optional[float] = None
    challenge: Optional[str] = None


class ChallengeRequest(BaseModel):
    badge_mac: str
    device_hostname: str


def _check_signed_device(signed_device: Optional[Device], hostname: str):
    """In PAKL mode the signing device must be the device named in the body."""
    if signed_device is not None and signed_device.hostname != hostname:
        raise HTTPException(status_code=403, detail="Device mismatch")


def _unwrap_all(stored: dict, device_id: int) -> dict:
    """Convert {file: base64(stored blob)} into {file: base64(FEK)}."""
    mk = master_key()
    out = {}
    for path, blob_b64 in stored.items():
        fek = pakl.unwrap_fek(mk, base64.b64decode(blob_b64), device_id, path)
        out[path] = base64.b64encode(fek).decode("utf-8")
    return out


# ============================================================
# Endpoints
# ============================================================

@router.post("/request", response_model=KeyResponse)
async def request_keys(
    req: KeyRequest,
    db: AsyncSession = Depends(get_db),
    signed_device: Optional[Device] = Depends(require_device_signature),
):
    """
    Agent requests FEKs for decryption.
    
    Flow:
    1. Validate badge is active
    2. Check RBAC policy: does this badge have access to this device?
    3. Return all FEKs for this device (from cache or DB)

    PAKL mode additionally requires a valid device signature and a fresh
    presence token, and returns a short lease that must be renewed.
    """
    _check_signed_device(signed_device, req.device_hostname)
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
        db.add(AuditLog(
            badge_id=badge.id,
            device_id=device.id,
            action="key_request_denied",
            details=f"No active policy for badge {req.badge_mac} on device {req.device_hostname}",
            timestamp=datetime.utcnow(),
        ))
        return KeyResponse(authorized=False, message="No access policy found")

    # Check expiry
    if policy.expires_at and policy.expires_at < datetime.utcnow():
        return KeyResponse(authorized=False, message="Access policy expired")

    # PAKL: physical presence must be proven with a fresh badge token
    lease_id = None
    if pakl_enabled():
        ok, reason = await verify_presence(db, badge, req.presence_token)
        if not ok:
            audit(db, "key_request_denied", f"Presence check failed: {reason}",
                  badge.id, device.id)
            return KeyResponse(authorized=False, message=f"Presence check failed: {reason}")
        if cr_enabled():
            ok, reason = await check_cr(badge, device, req.cr)
            if not ok:
                audit(db, "key_request_denied", f"Challenge-response failed: {reason}",
                      badge.id, device.id)
                return KeyResponse(authorized=False, message=f"Challenge-response failed: {reason}")
        lease_id = await create_lease(badge, device)
    lease_ttl = settings.LEASE_TTL_S if lease_id else None
    next_chal = await issue_challenge(badge, device) if (lease_id and cr_enabled()) else None

    # 4. Try cache first (cache holds stored blobs, wrapped when MASTER_KEY is set)
    cached = await get_cached_keys(req.badge_mac, req.device_hostname)
    if cached:
        db.add(AuditLog(
            badge_id=badge.id,
            device_id=device.id,
            action="keys_delivered",
            details=f"{len(cached)} keys from cache",
            timestamp=datetime.utcnow(),
        ))
        return KeyResponse(authorized=True, keys=_unwrap_all(cached, device.id),
                           message="Keys from cache",
                           lease_id=lease_id, lease_ttl=lease_ttl, challenge=next_chal)

    # 5. Fetch from DB
    key_result = await db.execute(
        select(FileKey).where(FileKey.device_id == device.id)
    )
    file_keys = key_result.scalars().all()

    stored = {}
    for fk in file_keys:
        stored[fk.file_path] = base64.b64encode(fk.encrypted_fek).decode("utf-8")

    # Cache for next time
    if stored:
        await cache_keys(req.badge_mac, req.device_hostname, stored)

    db.add(AuditLog(
        badge_id=badge.id,
        device_id=device.id,
        action="keys_delivered",
        details=f"{len(stored)} keys from database",
        timestamp=datetime.utcnow(),
    ))

    return KeyResponse(authorized=True, keys=_unwrap_all(stored, device.id),
                       message=f"{len(stored)} keys delivered",
                       lease_id=lease_id, lease_ttl=lease_ttl, challenge=next_chal)


@router.post("/challenge")
async def get_challenge(
    req: ChallengeRequest,
    db: AsyncSession = Depends(get_db),
    signed_device: Optional[Device] = Depends(require_device_signature),
):
    """PAKL-CR: issue a single-use challenge to be answered by the badge before key release."""
    if not cr_enabled():
        raise HTTPException(status_code=404, detail="Challenge-response not enabled")
    _check_signed_device(signed_device, req.device_hostname)
    badge = (await db.execute(select(Badge).where(Badge.mac_address == req.badge_mac))).scalar_one_or_none()
    if badge is None or badge.status != BadgeStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="Badge not active")
    return {"challenge": await issue_challenge(badge, signed_device),
            "ttl": settings.CHALLENGE_TTL_S}


@router.post("/renew", response_model=LeaseRenewResponse)
async def renew_lease(
    req: LeaseRenewRequest,
    db: AsyncSession = Depends(get_db),
    signed_device: Optional[Device] = Depends(require_device_signature),
):
    """
    PAKL: extend a key lease. Every renewal re-checks badge status,
    policy and a fresh presence token, so revocation or badge absence
    is enforced within one renewal period.
    """
    if not pakl_enabled():
        return LeaseRenewResponse(renewed=True, message="Leases disabled (baseline mode)")
    _check_signed_device(signed_device, req.device_hostname)

    lease = await get_lease(req.lease_id)
    if lease is None:
        return LeaseRenewResponse(renewed=False, message="Lease expired or unknown")

    badge = await db.get(Badge, lease["badge_id"])
    device = await db.get(Device, lease["device_id"])
    if (badge is None or device is None or device.id != signed_device.id
            or badge.mac_address != req.badge_mac):
        await end_lease(req.lease_id)
        return LeaseRenewResponse(renewed=False, message="Lease does not match request")

    reason = None
    if badge.status != BadgeStatus.ACTIVE:
        reason = f"Badge is {badge.status.value}"
    elif not device.is_active:
        reason = "Device is inactive"
    else:
        policy = (await db.execute(
            select(AccessPolicy).where(and_(
                AccessPolicy.badge_id == badge.id,
                AccessPolicy.device_id == device.id,
                AccessPolicy.is_active == True,
            ))
        )).scalars().first()
        if policy is None:
            reason = "No active access policy"
        elif policy.expires_at and policy.expires_at < datetime.utcnow():
            reason = "Access policy expired"
        else:
            ok, presence_reason = await verify_presence(db, badge, req.presence_token)
            if not ok:
                reason = f"Presence check failed: {presence_reason}"
            elif cr_enabled():
                ok, cr_reason = await check_cr(badge, device, req.cr)
                if not ok:
                    reason = f"Challenge-response failed: {cr_reason}"
                    # A genuine answer that was only too slow gets one immediate
                    # retry: a badge occasionally misses a radio slot, while a
                    # relay adds its delay to every exchange. The lease is not
                    # extended, so it still lapses at its TTL.
                    if cr_reason.startswith("cr_rtt_exceeded") and await allow_cr_retry(req.lease_id):
                        audit(db, "lease_cr_retry", reason, badge.id, device.id)
                        return LeaseRenewResponse(renewed=False, retry=True, message=reason,
                                                  challenge=await issue_challenge(badge, device))

    if reason is not None:
        await end_lease(req.lease_id)
        audit(db, "lease_denied", reason, badge.id, device.id)
        return LeaseRenewResponse(renewed=False, message=reason)

    await extend_lease(req.lease_id)
    next_chal = await issue_challenge(badge, device) if cr_enabled() else None
    return LeaseRenewResponse(renewed=True, message="Lease renewed",
                              lease_ttl=settings.LEASE_TTL_S, challenge=next_chal)


@router.post("/store")
async def store_key(
    req: KeyStoreRequest,
    db: AsyncSession = Depends(get_db),
    signed_device: Optional[Device] = Depends(require_device_signature),
):
    """
    Agent stores a new FEK after encrypting a new file.
    The FEK is wrapped with the server master key when one is configured.
    """
    _check_signed_device(signed_device, req.device_hostname)
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

    mk = master_key()
    if mk is not None:
        fek_bytes = pakl.wrap_fek(mk, fek_bytes, device.id, req.file_path)

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

    # Invalidate cache so next key request fetches fresh data from DB
    await invalidate_keys(req.badge_mac, req.device_hostname)

    return {"message": "Key stored", "file_path": req.file_path}


@router.post("/delete")
async def delete_key(
    req: KeyDeleteRequest,
    db: AsyncSession = Depends(get_db),
    signed_device: Optional[Device] = Depends(require_device_signature),
):
    """
    Agent reports a file was deleted — remove the FEK from server.
    """
    _check_signed_device(signed_device, req.device_hostname)
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
        # Invalidate cache so deleted key is not served
        await invalidate_keys(req.badge_mac, req.device_hostname)
        return {"message": "Key deleted", "file_path": req.file_path}
    else:
        return {"message": "Key not found", "file_path": req.file_path}
