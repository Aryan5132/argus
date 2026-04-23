"""
Sentinel – Startup Script
Run with: python run.py
"""
import uvicorn
from backend.config import settings

if __name__ == "__main__":
    print("=" * 60)
    print("  SENTINEL - Cloud Misconfiguration Detection System")
    print("=" * 60)
    uvicorn.run(
        "backend.main:app",
        host=settings.app_host,
        port=settings.app_port,
        reload=settings.debug,
        log_level="info",
    )
