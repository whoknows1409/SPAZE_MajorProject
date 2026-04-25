"""
SPAZE Server - Redis Cache

Caches File Encryption Keys (FEKs) with TTL to avoid
repeated DB lookups during active sessions.
"""

import json
import logging
from typing import Optional

import redis.asyncio as redis

from server.config import get_settings

logger = logging.getLogger("spaze-server.cache")

settings = get_settings()

# Async Redis connection pool
_redis_pool: Optional[redis.Redis] = None


async def get_redis() -> redis.Redis:
    """Get or create a Redis connection."""
    global _redis_pool
    if _redis_pool is None:
        _redis_pool = redis.from_url(
            settings.REDIS_URL,
            decode_responses=True,
        )
    return _redis_pool


async def close_redis():
    """Close Redis connection pool (called on shutdown)."""
    global _redis_pool
    if _redis_pool is not None:
        await _redis_pool.close()
        _redis_pool = None


# ============================================================
# Key Caching
# ============================================================

async def cache_keys(badge_mac: str, device_hostname: str, keys: dict):
    """
    Cache FEKs for a badge+device pair.
    
    Args:
        badge_mac: Badge MAC address
        device_hostname: Device hostname
        keys: Dict of {filename: base64_encoded_key}
    """
    r = await get_redis()
    cache_key = f"spaze:keys:{badge_mac}:{device_hostname}"
    await r.set(cache_key, json.dumps(keys), ex=settings.REDIS_KEY_TTL)
    logger.debug(f"Cached {len(keys)} keys for {badge_mac}@{device_hostname}")


async def get_cached_keys(badge_mac: str, device_hostname: str) -> Optional[dict]:
    """
    Retrieve cached FEKs for a badge+device pair.
    Returns dict of {filename: base64_key} or None if not cached.
    """
    r = await get_redis()
    cache_key = f"spaze:keys:{badge_mac}:{device_hostname}"
    data = await r.get(cache_key)
    if data:
        logger.debug(f"Cache HIT for {badge_mac}@{device_hostname}")
        return json.loads(data)
    logger.debug(f"Cache MISS for {badge_mac}@{device_hostname}")
    return None


async def invalidate_keys(badge_mac: str, device_hostname: str):
    """Remove cached keys (e.g., on policy revocation)."""
    r = await get_redis()
    cache_key = f"spaze:keys:{badge_mac}:{device_hostname}"
    await r.delete(cache_key)
    logger.info(f"Invalidated cache for {badge_mac}@{device_hostname}")


# ============================================================
# Session Tracking
# ============================================================

async def record_active_session(badge_mac: str, device_hostname: str):
    """Mark a badge as actively decrypted on a device."""
    r = await get_redis()
    session_key = f"spaze:session:{badge_mac}:{device_hostname}"
    await r.set(session_key, "active", ex=600)  # 10 min TTL


async def clear_session(badge_mac: str, device_hostname: str):
    """Clear active session marker."""
    r = await get_redis()
    session_key = f"spaze:session:{badge_mac}:{device_hostname}"
    await r.delete(session_key)


async def get_active_sessions() -> list[str]:
    """List all active decrypt sessions."""
    r = await get_redis()
    keys = []
    async for key in r.scan_iter("spaze:session:*"):
        parts = key.replace("spaze:session:", "").split(":")
        if len(parts) == 2:
            keys.append(f"{parts[0]}@{parts[1]}")
    return keys
