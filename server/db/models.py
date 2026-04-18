"""
SecureZone Database Models
SQLAlchemy ORM models for the Zero-Trust access control system.
"""

import enum
from datetime import datetime

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, Enum, LargeBinary, ARRAY
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class UserRole(enum.Enum):
    ADMIN = "admin"
    MANAGER = "manager"
    EMPLOYEE = "employee"


class BadgeStatus(enum.Enum):
    ACTIVE = "active"
    REVOKED = "revoked"
    LOST = "lost"


class GeofenceEventType(enum.Enum):
    ENTER = "enter"
    EXIT = "exit"


class Badge(Base):
    __tablename__ = "badges"

    id = Column(Integer, primary_key=True, index=True)
    mac_address = Column(String(17), unique=True, nullable=False)
    public_key = Column(Text, nullable=True)
    status = Column(Enum(BadgeStatus), default=BadgeStatus.ACTIVE, nullable=False)
    registered_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", back_populates="badge", uselist=False)
    access_policies = relationship("AccessPolicy", back_populates="badge")
    audit_logs = relationship("AuditLog", back_populates="badge")
    geofence_events = relationship("GeofenceEvent", back_populates="badge")


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)
    email = Column(String(255), unique=True, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.EMPLOYEE, nullable=False)
    badge_id = Column(Integer, ForeignKey("badges.id"), unique=True, nullable=True)

    badge = relationship("Badge", back_populates="user")
    granted_policies = relationship("AccessPolicy", back_populates="granted_by_user",
                                     foreign_keys="AccessPolicy.granted_by")


class Device(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), nullable=False)
    mac_address = Column(String(17), unique=True, nullable=False)
    location = Column(String(255), nullable=True)
    registered_at = Column(DateTime, default=datetime.utcnow)

    access_policies = relationship("AccessPolicy", back_populates="device")
    file_keys = relationship("FileKey", back_populates="device")


class AccessPolicy(Base):
    __tablename__ = "access_policies"

    id = Column(Integer, primary_key=True, index=True)
    badge_id = Column(Integer, ForeignKey("badges.id"), nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)
    allowed_directories = Column(Text, nullable=True)  # JSON array stored as text
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    badge = relationship("Badge", back_populates="access_policies")
    device = relationship("Device", back_populates="access_policies")
    granted_by_user = relationship("User", back_populates="granted_policies",
                                    foreign_keys=[granted_by])


class FileKey(Base):
    __tablename__ = "file_keys"

    id = Column(Integer, primary_key=True, index=True)
    file_path = Column(Text, nullable=False)
    encrypted_fek = Column(LargeBinary, nullable=False)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=False)

    device = relationship("Device", back_populates="file_keys")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    badge_id = Column(Integer, ForeignKey("badges.id"), nullable=True)
    device_id = Column(Integer, ForeignKey("devices.id"), nullable=True)
    action = Column(String(100), nullable=False)
    file_path = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(45), nullable=True)
    rssi_value = Column(Integer, nullable=True)

    badge = relationship("Badge", back_populates="audit_logs")


class GeofenceEvent(Base):
    __tablename__ = "geofence_events"

    id = Column(Integer, primary_key=True, index=True)
    badge_id = Column(Integer, ForeignKey("badges.id"), nullable=False)
    anchor_id = Column(String(50), nullable=False)
    event_type = Column(Enum(GeofenceEventType), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

    badge = relationship("Badge", back_populates="geofence_events")
