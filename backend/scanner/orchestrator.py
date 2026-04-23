"""
Sentinel – Core Scanner Orchestrator
Runs all scanners → applies all rules → saves findings → triggers alerts
"""
import json
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from backend.models import ScanRun, Finding, SeverityLevel, FindingStatus, ResourceType
from backend.scanner.s3_scanner import scan_s3_buckets
from backend.scanner.iam_scanner import scan_iam
from backend.scanner.sg_scanner import scan_security_groups
from backend.scanner.ec2_scanner import scan_ec2_instances
from backend.rules.s3_rules import S3_RULES
from backend.rules.iam_rules import IAM_RULES
from backend.rules.sg_rules import SG_RULES
from backend.rules.ec2_rules import EC2_RULES
from backend.ml.predictor import predict_risk_score
from backend.alerts.email_alert import send_email_alert
from backend.alerts.slack_alert import send_slack_alert
from backend.config import settings
from backend.scanner.aws_client import aws_client
from backend.scanner.demo_data import get_demo_findings
from backend.scanner.realtime_generator import get_realtime_generated_findings

logger = logging.getLogger(__name__)


def run_full_scan(db: Session, triggered_by: str = "scheduler") -> ScanRun:
    """
    Execute full AWS scan, apply rules, persist findings, trigger alerts.
    Returns the completed ScanRun ORM object.
    """
    # Create scan run record
    scan_run = ScanRun(triggered_by=triggered_by, status="RUNNING")
    db.add(scan_run)
    db.commit()
    db.refresh(scan_run)
    logger.info(f"🚀 Scan #{scan_run.id} started (triggered by {triggered_by})")

    all_findings = []

    try:
        scanned_resource_count = 0
        if aws_client.connected:
            # ── S3 ─────────────────────────────────────────────────────
            logger.info("Scanning S3 buckets...")
            s3_resources = scan_s3_buckets()
            scanned_resource_count += len(s3_resources)
            for resource in s3_resources:
                for rule in S3_RULES:
                    finding = rule.evaluate(resource)
                    if finding:
                        all_findings.append(finding)

            # ── IAM ─────────────────────────────────────────────────────
            logger.info("Scanning IAM users...")
            iam_resources = scan_iam()
            scanned_resource_count += len(iam_resources)
            for resource in iam_resources:
                for rule in IAM_RULES:
                    finding = rule.evaluate(resource)
                    if finding:
                        all_findings.append(finding)

            # ── Security Groups ──────────────────────────────────────────
            logger.info("Scanning Security Groups...")
            sg_resources = scan_security_groups()
            scanned_resource_count += len(sg_resources)
            for resource in sg_resources:
                for rule in SG_RULES:
                    finding = rule.evaluate(resource)
                    if finding:
                        all_findings.append(finding)

            # ── EC2 (optional) ───────────────────────────────────────────
            if settings.ec2_scan_enabled:
                logger.info("Scanning EC2 instances...")
                ec2_resources = scan_ec2_instances()
                scanned_resource_count += len(ec2_resources)
                for resource in ec2_resources:
                    for rule in EC2_RULES:
                        finding = rule.evaluate(resource)
                        if finding:
                            all_findings.append(finding)

            if scanned_resource_count == 0:
                logger.warning(
                    "AWS connected but returned no resources (likely permission limits); "
                    "using full demo scan data (S3 + IAM + SG + EC2)."
                )
                all_findings = get_demo_findings()
        else:
            logger.warning("AWS not connected; using full demo scan data (S3 + IAM + SG + EC2).")
            all_findings = get_demo_findings()

        # ── Persist findings ─────────────────────────────────────────
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        alert_findings = []

        for rf in all_findings:
            ml_score = predict_risk_score(rf.ml_features)
            db_finding = Finding(
                scan_run_id=scan_run.id,
                resource_type=ResourceType(rf.resource_type),
                resource_id=rf.resource_id,
                resource_name=rf.resource_name,
                rule_id=rf.rule_id,
                severity=SeverityLevel(rf.severity),
                title=rf.title,
                description=rf.description,
                suggested_fix=rf.suggested_fix,
                ml_risk_score=ml_score,
                region=rf.region,
                extra_data=json.dumps(rf.extra_data),
                status=FindingStatus.OPEN,
            )
            db.add(db_finding)
            severity_counts[rf.severity] = severity_counts.get(rf.severity, 0) + 1

            if rf.severity in ("CRITICAL", "HIGH"):
                alert_findings.append({
                    "title": rf.title,
                    "severity": rf.severity,
                    "resource_type": rf.resource_type,
                    "resource_id": rf.resource_id,
                    "suggested_fix": rf.suggested_fix,
                })

        # ── Update scan run ───────────────────────────────────────────
        scan_run.status = "COMPLETED"
        scan_run.completed_at = datetime.now(timezone.utc)
        scan_run.total_findings = len(all_findings)
        scan_run.critical_count = severity_counts["CRITICAL"]
        scan_run.high_count = severity_counts["HIGH"]
        scan_run.medium_count = severity_counts["MEDIUM"]
        scan_run.low_count = severity_counts["LOW"]
        db.commit()

        logger.info(
            f"✅ Scan #{scan_run.id} completed: "
            f"{len(all_findings)} findings "
            f"(CRITICAL:{severity_counts['CRITICAL']} HIGH:{severity_counts['HIGH']} "
            f"MEDIUM:{severity_counts['MEDIUM']} LOW:{severity_counts['LOW']})"
        )

        # ── Alerts ────────────────────────────────────────────────────
        if alert_findings and settings.alerts_enabled:
            send_email_alert(alert_findings, scan_run.id)
            send_slack_alert(alert_findings, scan_run.id)

    except Exception as e:
        logger.error(f"Scan #{scan_run.id} failed: {e}", exc_info=True)
        scan_run.status = "FAILED"
        scan_run.error_message = str(e)
        scan_run.completed_at = datetime.now(timezone.utc)
        db.commit()

    db.refresh(scan_run)
    return scan_run
