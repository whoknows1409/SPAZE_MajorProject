"""
SPAZE Server - User Management API

Admin endpoints for user CRUD and badge assignment.
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from server.db.database import get_db
from server.db.models import User, UserRole, Badge
from server.auth.jwt import hash_password
from server.auth.dependencies import get_current_user, require_role

router = APIRouter()


# ============================================================
# Schemas
# ============================================================

class UserCreate(BaseModel):
    name: str
    email: str
    password: str
    role: str = "employee"
    badge_id: Optional[int] = None


class UserUpdate(BaseModel):
    name: Optional[str] = None
    role: Optional[str] = None
    badge_id: Optional[int] = None
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    badge_id: Optional[int]
    badge_mac: Optional[str] = None
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ============================================================
# Endpoints
# ============================================================

@router.post("/", response_model=UserResponse)
async def create_user(
    req: UserCreate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin"])),
):
    """Create a new user (admin only)."""
    # Check duplicate email
    existing = await db.execute(select(User).where(User.email == req.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    # Validate role
    try:
        role = UserRole(req.role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {req.role}")

    # Validate badge if provided
    badge_mac = None
    if req.badge_id:
        badge_result = await db.execute(select(Badge).where(Badge.id == req.badge_id))
        badge = badge_result.scalar_one_or_none()
        if not badge:
            raise HTTPException(status_code=400, detail="Badge not found")
        badge_mac = badge.mac_address

    user = User(
        name=req.name,
        email=req.email,
        password_hash=hash_password(req.password),
        role=role,
        badge_id=req.badge_id,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)

    return UserResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        role=user.role.value,
        badge_id=user.badge_id,
        badge_mac=badge_mac,
        is_active=user.is_active,
        created_at=user.created_at,
    )


@router.get("/", response_model=list[UserResponse])
async def list_users(
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin", "manager"])),
):
    """List all users."""
    from sqlalchemy.orm import selectinload

    result = await db.execute(
        select(User).options(selectinload(User.badge)).order_by(User.id)
    )
    users = result.scalars().all()

    response = []
    for user in users:
        badge_mac = None
        if user.badge_id and user.badge:
            badge_mac = user.badge.mac_address
        response.append(UserResponse(
            id=user.id,
            name=user.name,
            email=user.email,
            role=user.role.value,
            badge_id=user.badge_id,
            badge_mac=badge_mac,
            is_active=user.is_active,
            created_at=user.created_at,
        ))
    return response


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: int,
    req: UserUpdate,
    db: AsyncSession = Depends(get_db),
    admin: User = Depends(require_role(["admin"])),
):
    """Update user (admin only)."""
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if req.name is not None:
        user.name = req.name
    if req.role is not None:
        try:
            user.role = UserRole(req.role)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid role: {req.role}")
    if req.badge_id is not None:
        user.badge_id = req.badge_id
    if req.is_active is not None:
        user.is_active = req.is_active

    await db.flush()
    await db.refresh(user)

    return UserResponse(
        id=user.id,
        name=user.name,
        email=user.email,
        role=user.role.value,
        badge_id=user.badge_id,
        is_active=user.is_active,
        created_at=user.created_at,
    )
