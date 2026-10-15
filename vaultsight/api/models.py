"""Database models and session setup for VaultSight."""

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, Integer, DateTime, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

Base = declarative_base()


class UserDB(Base):
    """Registered application user with role-based access."""
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="viewer", nullable=False)  # "viewer" | "analyst" | "admin"
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("ScanDB", back_populates="owner", cascade="all, delete-orphan")


class ScanDB(Base):
    """Scan execution job isolated per user."""
    __tablename__ = "scans"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    owner_id = Column(String, ForeignKey("users.id"), nullable=False, index=True)
    target_type = Column(String, nullable=False)  # "filesystem" | "sqlite" | "s3"
    target_path = Column(String, nullable=False)
    status = Column(String, default="COMPLETED")
    findings_count = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0)
    risk_level = Column(String, default="INFO")
    created_at = Column(DateTime, default=datetime.utcnow)

    owner = relationship("UserDB", back_populates="scans")
    findings = relationship("FindingDB", back_populates="scan", cascade="all, delete-orphan")


class FindingDB(Base):
    """Individual sensitive data finding tied to a scan."""
    __tablename__ = "findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False, index=True)
    detector = Column(String, nullable=False)
    category = Column(String, nullable=False)
    confidence = Column(Float, nullable=False)
    location = Column(String, nullable=False)
    redacted_preview = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanDB", back_populates="findings")


def get_engine(db_url: str = "sqlite:///./vaultsight.db"):
    return create_engine(db_url, connect_args={"check_same_thread": False})


def init_db(engine):
    Base.metadata.create_all(bind=engine)


SessionLocal = sessionmaker(autocommit=False, autoflush=False)
