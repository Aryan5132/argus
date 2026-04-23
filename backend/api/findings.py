"""
Sentinel – Findings API Router
"""
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Optional, List
from backend.database import get_db
from backend.models import Finding, SeverityLevel, FindingStatus, ResourceType
from backend.schemas import FindingOut, FindingStatusUpdate
from datetime import datetime

router = APIRouter(prefix="/api/v1/findings", tags=["Findings"])


@router.get("", response_model=dict)
def list_findings(
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    severity: Optional[str] = Query(default=None),
    resource_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    search: Optional[str] = Query(default=None),
    scan_run_id: Optional[int] = Query(default=None),
):
    """List findings with pagination and filtering."""
    query = db.query(Finding)

    if severity:
        query = query.filter(Finding.severity == SeverityLevel(severity))
    if resource_type:
        query = query.filter(Finding.resource_type == ResourceType(resource_type))
    if status:
        query = query.filter(Finding.status == FindingStatus(status))
    if scan_run_id:
        query = query.filter(Finding.scan_run_id == scan_run_id)
    if search:
        query = query.filter(
            Finding.title.ilike(f"%{search}%") |
            Finding.resource_id.ilike(f"%{search}%") |
            Finding.description.ilike(f"%{search}%")
        )

    total = query.count()
    findings = (
        query.order_by(desc(Finding.created_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": (total + page_size - 1) // page_size,
        "items": [FindingOut.model_validate(f) for f in findings],
    }


@router.get("/{finding_id}", response_model=FindingOut)
def get_finding(finding_id: int, db: Session = Depends(get_db)):
    """Get a single finding by ID."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Finding not found")
    return FindingOut.model_validate(finding)


@router.put("/{finding_id}/status", response_model=FindingOut)
def update_finding_status(
    finding_id: int,
    body: FindingStatusUpdate,
    db: Session = Depends(get_db),
):
    """Update the status of a finding (OPEN / ACKNOWLEDGED / FIXED / FALSE_POSITIVE)."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Finding not found")
    finding.status = body.status
    finding.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(finding)
    return FindingOut.model_validate(finding)
