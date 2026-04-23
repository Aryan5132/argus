"""
Sentinel – Pydantic Schemas (request/response)
"""
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime
from backend.models import SeverityLevel, FindingStatus, ResourceType


# ── Scan Run ──────────────────────────────────────────────────────
class ScanRunBase(BaseModel):
    triggered_by: str = "manual"


class ScanRunOut(BaseModel):
    id: int
    started_at: datetime
    completed_at: Optional[datetime]
    status: str
    triggered_by: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    error_message: Optional[str]

    model_config = {"from_attributes": True}


# ── Finding ───────────────────────────────────────────────────────
class FindingOut(BaseModel):
    id: int
    scan_run_id: int
    resource_type: ResourceType
    resource_id: str
    resource_name: Optional[str]
    rule_id: str
    severity: SeverityLevel
    title: str
    description: str
    suggested_fix: str
    ml_risk_score: float
    region: Optional[str]
    status: FindingStatus
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class FindingStatusUpdate(BaseModel):
    status: FindingStatus


# ── Stats ─────────────────────────────────────────────────────────
class StatsOut(BaseModel):
    total_findings: int
    open_findings: int
    critical: int
    high: int
    medium: int
    low: int
    fixed: int
    acknowledged: int
    total_scans: int
    last_scan_at: Optional[datetime]
    findings_by_resource: dict
    findings_trend: List[dict]  # [{date, count}]


# ── Alert ─────────────────────────────────────────────────────────
class AlertConfigIn(BaseModel):
    alert_type: str  # email / slack
    enabled: bool = True
    target: str
    min_severity: SeverityLevel = SeverityLevel.HIGH


class AlertConfigOut(AlertConfigIn):
    id: int
    created_at: datetime

    model_config = {"from_attributes": True}


class TestAlertIn(BaseModel):
    alert_type: str  # email / slack
