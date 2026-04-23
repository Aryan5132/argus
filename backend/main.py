"""
Sentinel – FastAPI Application Entry Point
"""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pathlib import Path

from backend.database import init_db, SessionLocal
from backend.scheduler.jobs import start_scheduler, stop_scheduler
from backend.api.findings import router as findings_router
from backend.api.scans import router as scans_router
from backend.api.stats import router as stats_router
from backend.api.alerts import router as alerts_router
from backend.ml.trainer import load_or_train

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)

FRONTEND_DIR = Path(__file__).parent.parent / "frontend"


def reset_scan_data():
    """Wipe all scan runs and findings on startup so the dashboard opens clean.
    Alert configurations are preserved (they are user settings).
    """
    from backend.models import Finding, ScanRun
    db = SessionLocal()
    try:
        deleted_findings = db.query(Finding).delete(synchronize_session=False)
        deleted_scans    = db.query(ScanRun).delete(synchronize_session=False)
        db.commit()
        logger.info(
            "🗑️  Startup reset: deleted %d finding(s) and %d scan run(s).",
            deleted_findings, deleted_scans,
        )
    except Exception as exc:
        db.rollback()
        logger.warning("Startup reset failed (non-fatal): %s", exc)
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup and shutdown lifecycle."""
    logger.info("🛡️  Sentinel starting up...")

    # Initialize database tables
    init_db()
    logger.info("✅ Database initialised")

    # ── Fresh start: clear previous scan data ──────────────────────────
    reset_scan_data()
    logger.info("✅ Scan data reset — dashboard starts at zero")

    # Pre-load / train ML model
    load_or_train()
    logger.info("✅ ML model ready")

    # Start background scheduler
    start_scheduler()

    yield

    logger.info("🔴 Sentinel shutting down...")
    stop_scheduler()


app = FastAPI(
    title="Sentinel – Cloud Misconfiguration Detection",
    description="Real-time AWS security scanning with ML-powered risk scoring",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routers
app.include_router(findings_router)
app.include_router(scans_router)
app.include_router(stats_router)
app.include_router(alerts_router)


# Health check
@app.get("/health")
def health():
    from backend.scanner.aws_client import aws_client
    return {
        "status": "ok",
        "aws_connected": aws_client.connected,
        "aws_account": getattr(aws_client, "account_id", "N/A"),
    }


# Serve frontend
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/", include_in_schema=False)
    def serve_frontend():
        return FileResponse(str(FRONTEND_DIR / "index.html"))

    @app.get("/{path:path}", include_in_schema=False)
    def serve_frontend_catch(path: str):
        file_path = FRONTEND_DIR / path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(FRONTEND_DIR / "index.html"))
