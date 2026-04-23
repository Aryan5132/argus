"""
Sentinel – APScheduler Background Jobs
"""
import logging
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from backend.config import settings
from backend.database import SessionLocal

logger = logging.getLogger(__name__)
_scheduler = BackgroundScheduler()


def _scheduled_scan_job():
    """Job function called by APScheduler."""
    from backend.scanner.orchestrator import run_full_scan
    db = SessionLocal()
    try:
        run_full_scan(db, triggered_by="scheduler")
    except Exception as e:
        logger.error(f"Scheduled scan failed: {e}", exc_info=True)
    finally:
        db.close()


def start_scheduler():
    """Initialize and start the background scan scheduler."""
    if _scheduler.running:
        return

    _scheduler.add_job(
        _scheduled_scan_job,
        trigger=IntervalTrigger(hours=settings.scan_interval_hours),
        id="full_aws_scan",
        name="Full AWS Security Scan",
        replace_existing=True,
        max_instances=1,
    )
    _scheduler.start()
    logger.info(
        f"⏰ Scheduler started – scans every {settings.scan_interval_hours} hour(s)"
    )


def stop_scheduler():
    if _scheduler.running:
        _scheduler.shutdown(wait=False)
        logger.info("Scheduler stopped")


def get_scheduler_status() -> dict:
    jobs = _scheduler.get_jobs()
    job_info = []
    for job in jobs:
        job_info.append({
            "id": job.id,
            "name": job.name,
            "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
        })
    return {
        "running": _scheduler.running,
        "jobs": job_info,
        "interval_hours": settings.scan_interval_hours,
    }
