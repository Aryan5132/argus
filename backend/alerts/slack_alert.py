"""
Sentinel – Slack Alert Module
Posts formatted findings to a Slack webhook.
"""
import json
import logging
import requests
from datetime import datetime
from backend.config import settings

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
}

SEVERITY_COLOR = {
    "CRITICAL": "#FF0033",
    "HIGH": "#FF6B35",
    "MEDIUM": "#FFB800",
    "LOW": "#00BB77",
}


def send_slack_alert(findings: list[dict], scan_run_id: int) -> bool:
    """Post finding summary to Slack webhook."""
    if not settings.slack_webhook_url:
        logger.warning("Slack alert skipped – SLACK_WEBHOOK_URL not configured")
        return False

    try:
        payload = _build_slack_payload(findings, scan_run_id)
        resp = requests.post(
            settings.slack_webhook_url,
            data=json.dumps(payload),
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        resp.raise_for_status()
        logger.info("📣 Slack alert sent successfully")
        return True
    except Exception as e:
        logger.error(f"Slack alert failed: {e}")
        return False


def _build_slack_payload(findings: list[dict], scan_run_id: int) -> dict:
    severity_counts = {}
    for f in findings:
        sev = f.get("severity", "LOW")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    summary_parts = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if severity_counts.get(sev):
            summary_parts.append(f"{SEVERITY_EMOJI[sev]} {severity_counts[sev]} {sev}")

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "🛡️ Sentinel Security Alert", "emoji": True},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{len(findings)} new finding(s)* detected in Scan Run #{scan_run_id}\n"
                        f"{datetime.now().strftime('%Y-%m-%d %H:%M UTC')}\n\n"
                        + " · ".join(summary_parts),
            },
        },
        {"type": "divider"},
    ]

    # Add top 5 findings as attachment blocks
    for f in findings[:5]:
        sev = f.get("severity", "LOW")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{SEVERITY_EMOJI.get(sev,'')} *{f.get('title','')}*\n"
                    f"Resource: `{f.get('resource_id','')}`\n"
                    f"Fix: _{f.get('suggested_fix','')[:150]}..._"
                ),
            },
        })

    if len(findings) > 5:
        blocks.append({
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": f"_...and {len(findings)-5} more findings. Check your Sentinel dashboard._"}],
        })

    return {
        "text": f"🚨 Sentinel: {len(findings)} new security finding(s) detected!",
        "blocks": blocks,
        "attachments": [{"color": SEVERITY_COLOR.get(findings[0].get("severity", "LOW"), "#888")}] if findings else [],
    }
