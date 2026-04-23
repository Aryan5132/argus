"""
Sentinel – Configuration & Settings
Loads all environment variables from .env
"""
from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional
import os


class Settings(BaseSettings):
    # AWS
    aws_access_key_id: Optional[str] = Field(default=None, alias="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[str] = Field(default=None, alias="AWS_SECRET_ACCESS_KEY")
    aws_default_region: str = Field(default="us-east-1", alias="AWS_DEFAULT_REGION")

    # Database
    database_url: str = Field(default="sqlite:///./sentinel.db", alias="DATABASE_URL")

    # Scheduler
    scan_interval_hours: int = Field(default=6, alias="SCAN_INTERVAL_HOURS")
    ec2_scan_enabled: bool = Field(default=True, alias="EC2_SCAN_ENABLED")

    # Email Alerts
    smtp_host: str = Field(default="smtp.gmail.com", alias="SMTP_HOST")
    smtp_port: int = Field(default=587, alias="SMTP_PORT")
    smtp_user: Optional[str] = Field(default=None, alias="SMTP_USER")
    smtp_password: Optional[str] = Field(default=None, alias="SMTP_PASSWORD")
    alert_email_to: Optional[str] = Field(default=None, alias="ALERT_EMAIL_TO")
    alerts_enabled: bool = Field(default=True, alias="ALERTS_ENABLED")

    # Slack
    slack_webhook_url: Optional[str] = Field(default=None, alias="SLACK_WEBHOOK_URL")

    # App
    app_host: str = Field(default="0.0.0.0", alias="APP_HOST")
    app_port: int = Field(default=8000, alias="APP_PORT")
    debug: bool = Field(default=True, alias="DEBUG")

    model_config = {"env_file": ".env", "populate_by_name": True, "extra": "ignore"}


settings = Settings()
