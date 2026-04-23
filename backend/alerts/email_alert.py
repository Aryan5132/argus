"""
Sentinel – Email Alert Module
Sends HTML email alerts via SMTP for critical/high findings.
"""
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from backend.config import settings

logger = logging.getLogger(__name__)

SEVERITY_COLORS = {
    "CRITICAL": "#FF0033",
    "HIGH": "#FF6B35",
    "MEDIUM": "#FFB800",
    "LOW": "#00BB77",
}


def send_email_alert(findings: list[dict], scan_run_id: int) -> bool:
    """Send HTML email with finding summary."""
    if not settings.smtp_user or not settings.alert_email_to:
        logger.warning("Email alert skipped – SMTP credentials not configured")
        return False

    try:
        subject = f"🚨 Sentinel Alert – {len(findings)} New Finding(s) Detected"
        html_body = _build_html_body(findings, scan_run_id)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"Sentinel Security <{settings.smtp_user}>"
        msg["To"] = settings.alert_email_to

        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(settings.smtp_host, settings.smtp_port) as server:
            server.ehlo()
            server.starttls()
            server.login(settings.smtp_user, settings.smtp_password)
            server.sendmail(settings.smtp_user, settings.alert_email_to, msg.as_string())

        logger.info(f"📧 Email alert sent to {settings.alert_email_to}")
        return True

    except Exception as e:
        logger.error(f"Email alert failed: {e}")
        return False


def _build_html_body(findings: list[dict], scan_run_id: int) -> str:
    rows = ""
    for f in findings[:20]:  # limit table to 20
        color = SEVERITY_COLORS.get(f.get("severity", "LOW"), "#888")
        rows += f"""
        <tr>
          <td style="padding:8px;border-bottom:1px solid #2a2a3e;">
            <span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;">
              {f.get('severity','?')}
            </span>
          </td>
          <td style="padding:8px;border-bottom:1px solid #2a2a3e;color:#e0e0ff;">{f.get('resource_type','')}</td>
          <td style="padding:8px;border-bottom:1px solid #2a2a3e;color:#e0e0ff;">{f.get('title','')}</td>
          <td style="padding:8px;border-bottom:1px solid #2a2a3e;color:#9898bb;">{f.get('resource_id','')[:40]}...</td>
        </tr>"""

    return f"""
    <!DOCTYPE html>
    <html>
    <body style="background:#0a0e1a;font-family:Arial,sans-serif;margin:0;padding:20px;">
      <div style="max-width:700px;margin:0 auto;background:#12172b;border-radius:12px;overflow:hidden;border:1px solid #1e2a4a;">
        <div style="background:linear-gradient(135deg,#0a0e1a,#1a2a5e);padding:24px;">
          <h1 style="color:#00d4ff;margin:0;font-size:22px;">🛡️ Sentinel Security Alert</h1>
          <p style="color:#7a8cbb;margin:8px 0 0;">Scan Run #{scan_run_id} · {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}</p>
        </div>
        <div style="padding:24px;">
          <p style="color:#e0e0ff;font-size:15px;">
            <strong style="color:#ff3366;">{len(findings)}</strong> new finding(s) detected in your AWS environment.
          </p>
          <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
            <thead>
              <tr style="background:#1e2a4a;">
                <th style="padding:10px;text-align:left;color:#7a8cbb;font-size:12px;">SEVERITY</th>
                <th style="padding:10px;text-align:left;color:#7a8cbb;font-size:12px;">RESOURCE</th>
                <th style="padding:10px;text-align:left;color:#7a8cbb;font-size:12px;">FINDING</th>
                <th style="padding:10px;text-align:left;color:#7a8cbb;font-size:12px;">RESOURCE ID</th>
              </tr>
            </thead>
            <tbody>{rows}</tbody>
          </table>
          <div style="margin-top:24px;padding:16px;background:#0a0e1a;border-radius:8px;border-left:3px solid #00d4ff;">
            <p style="color:#9898bb;margin:0;font-size:13px;">
              Log in to your Sentinel dashboard to review findings and mark them as resolved.
            </p>
          </div>
        </div>
        <div style="padding:16px 24px;background:#0d1224;text-align:center;">
          <p style="color:#4a5a7a;font-size:12px;margin:0;">Sentinel – Cloud Misconfiguration Detection System</p>
        </div>
      </div>
    </body>
    </html>"""
