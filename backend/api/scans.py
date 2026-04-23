"""
Sentinel – Scans API Router
"""
from fastapi import APIRouter, Depends, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import desc
from backend.database import get_db
from backend.models import ScanRun
from backend.schemas import ScanRunOut
from backend.scanner.orchestrator import run_full_scan
from backend.scheduler.jobs import get_scheduler_status

router = APIRouter(prefix="/api/v1/scans", tags=["Scans"])


@router.get("", response_model=dict)
def list_scans(
    db: Session = Depends(get_db),
    page: int = 1,
    page_size: int = 10,
):
    """List all scan run history."""
    total = db.query(ScanRun).count()
    scans = (
        db.query(ScanRun)
        .order_by(desc(ScanRun.started_at))
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "total": total,
        "items": [ScanRunOut.model_validate(s) for s in scans],
    }


@router.post("/trigger", response_model=dict)
def trigger_scan(background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    """Manually trigger a full AWS scan (runs asynchronously)."""
    from backend.database import SessionLocal

    def _run():
        _db = SessionLocal()
        try:
            run_full_scan(_db, triggered_by="manual")
        finally:
            _db.close()

    background_tasks.add_task(_run)
    return {"message": "Scan triggered successfully. Results will appear shortly.", "status": "started"}


@router.get("/scheduler/status", response_model=dict)
def scheduler_status():
    """Get scheduler status and next run time."""
    return get_scheduler_status()


@router.get("/{scan_id}", response_model=ScanRunOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(ScanRun).filter(ScanRun.id == scan_id).first()
    if not scan:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanRunOut.model_validate(scan)
