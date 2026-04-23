"""
Sentinel – SQLAlchemy ORM Models
"""
from sqlalchemy import (
    Column, Integer, String, Float, DateTime, Boolean,
    ForeignKey, Text, Enum as SAEnum
)
from sqlalchemy.orm import relationship
from datetime import datetime, timezone
import enum

from backend.database import Base


class SeverityLevel(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingStatus(str, enum.Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FIXED = "FIXED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ResourceType(str, enum.Enum):
    S3 = "S3"
    IAM = "IAM"
    SECURITY_GROUP = "SECURITY_GROUP"
    EC2 = "EC2"


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, index=True)
    started_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    completed_at = Column(DateTime, nullable=True)
    status = Column(String(20), default="RUNNING")  # RUNNING / COMPLETED / FAILED
    triggered_by = Column(String(50), default="scheduler")  # scheduler / manual
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

    findings = relationship("Finding", back_populates="scan_run")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_run_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    resource_type = Column(SAEnum(ResourceType), nullable=False)
    resource_id = Column(String(500), nullable=False)
    resource_name = Column(String(500), nullable=True)
    rule_id = Column(String(100), nullable=False)
    severity = Column(SAEnum(SeverityLevel), nullable=False)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=False)
    suggested_fix = Column(Text, nullable=False)
    ml_risk_score = Column(Float, default=0.0)
    region = Column(String(50), nullable=True)
    extra_data = Column(Text, nullable=True)   # JSON string for extra metadata
    status = Column(SAEnum(FindingStatus), default=FindingStatus.OPEN)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                        onupdate=lambda: datetime.now(timezone.utc))

    scan_run = relationship("ScanRun", back_populates="findings")


class AlertConfig(Base):
    __tablename__ = "alert_configs"

    id = Column(Integer, primary_key=True, index=True)
    alert_type = Column(String(20), nullable=False)  # email / slack
    enabled = Column(Boolean, default=True)
    target = Column(String(500), nullable=False)      # email address or webhook URL
    min_severity = Column(SAEnum(SeverityLevel), default=SeverityLevel.HIGH)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
