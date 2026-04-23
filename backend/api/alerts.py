"""
Sentinel – Alerts Config API
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models import AlertConfig
from backend.schemas import AlertConfigIn, AlertConfigOut, TestAlertIn
from backend.alerts.email_alert import send_email_alert
from backend.alerts.slack_alert import send_slack_alert

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])

TEST_FINDING = [{
    "title": "TEST: S3 Bucket Public Access Enabled",
    "severity": "HIGH",
    "resource_type": "S3",
    "resource_id": "arn:aws:s3:::test-bucket",
    "suggested_fix": "Enable S3 Block Public Access settings.",
}]


@router.get("", response_model=list[AlertConfigOut])
def list_alert_configs(db: Session = Depends(get_db)):
    return db.query(AlertConfig).all()


@router.post("", response_model=AlertConfigOut)
def create_alert_config(body: AlertConfigIn, db: Session = Depends(get_db)):
    config = AlertConfig(**body.model_dump())
    db.add(config)
    db.commit()
    db.refresh(config)
    return AlertConfigOut.model_validate(config)


@router.delete("/{config_id}")
def delete_alert_config(config_id: int, db: Session = Depends(get_db)):
    config = db.query(AlertConfig).filter(AlertConfig.id == config_id).first()
    if config:
        db.delete(config)
        db.commit()
    return {"message": "Deleted"}


@router.post("/test")
def test_alert(body: TestAlertIn):
    """Send a test alert to verify configuration."""
    if body.alert_type == "email":
        success = send_email_alert(TEST_FINDING, scan_run_id=0)
    elif body.alert_type == "slack":
        success = send_slack_alert(TEST_FINDING, scan_run_id=0)
    else:
        return {"success": False, "message": "Unknown alert type"}
    return {"success": success, "message": "Test alert sent" if success else "Alert failed – check logs"}
