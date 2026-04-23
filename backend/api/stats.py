"""
Sentinel – Stats API Router
"""
import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.database import get_db
from backend.models import Finding, ScanRun, FindingStatus, SeverityLevel, ResourceType
from backend.schemas import StatsOut
from backend.scanner.aws_client import aws_client

router = APIRouter(prefix="/api/v1/stats", tags=["Stats"])
logger = logging.getLogger(__name__)


@router.get("", response_model=StatsOut)
def get_stats(db: Session = Depends(get_db)):
    """Dashboard summary statistics."""

    total = db.query(Finding).count()
    open_cnt = db.query(Finding).filter(Finding.status == FindingStatus.OPEN).count()
    critical = db.query(Finding).filter(Finding.severity == SeverityLevel.CRITICAL, Finding.status == FindingStatus.OPEN).count()
    high = db.query(Finding).filter(Finding.severity == SeverityLevel.HIGH, Finding.status == FindingStatus.OPEN).count()
    medium = db.query(Finding).filter(Finding.severity == SeverityLevel.MEDIUM, Finding.status == FindingStatus.OPEN).count()
    low = db.query(Finding).filter(Finding.severity == SeverityLevel.LOW, Finding.status == FindingStatus.OPEN).count()
    fixed = db.query(Finding).filter(Finding.status == FindingStatus.FIXED).count()
    acked = db.query(Finding).filter(Finding.status == FindingStatus.ACKNOWLEDGED).count()

    total_scans = db.query(ScanRun).count()
    last_scan = db.query(ScanRun).order_by(ScanRun.started_at.desc()).first()

    # Findings by resource type
    by_resource = {}
    for rt in ResourceType:
        cnt = db.query(Finding).filter(
            Finding.resource_type == rt,
            Finding.status == FindingStatus.OPEN,
        ).count()
        if cnt > 0:
            by_resource[rt.value] = cnt

    # Findings trend: last 24 hours (fill missing hours)
    trend = []
    try:
        from datetime import datetime, timedelta, timezone
        date_expr = func.strftime("%Y-%m-%d %H:00:00", Finding.created_at)
        trend_rows = (
            db.query(
                date_expr.label("date"),
                func.count(Finding.id).label("count"),
            )
            .group_by(date_expr)
            .order_by(date_expr)
            .all()
        )
        row_dict = {str(r.date): r.count for r in trend_rows if r.date}
        now = datetime.now(timezone.utc)
        top_of_hour = now.replace(minute=0, second=0, microsecond=0)
        for i in range(23, -1, -1):
            h_dt = top_of_hour - timedelta(hours=i)
            h_str = h_dt.strftime("%Y-%m-%d %H:00:00")
            trend.append({"date": h_str, "count": row_dict.get(h_str, 0)})
    except Exception as exc:
        logger.warning("Failed to build findings trend; returning empty trend: %s", exc)

    return StatsOut(
        total_findings=total,
        open_findings=open_cnt,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        fixed=fixed,
        acknowledged=acked,
        total_scans=total_scans,
        last_scan_at=last_scan.started_at if last_scan else None,
        findings_by_resource=by_resource,
        findings_trend=trend,
    )


@router.get("/aws-status")
def aws_connection_status():
    """Return real-time AWS connection status."""
    return {
        "connected": aws_client.connected,
        "account_id": getattr(aws_client, "account_id", "N/A"),
        "region": aws_client.region,
        "mode": "live" if aws_client.connected else "demo",
    }
