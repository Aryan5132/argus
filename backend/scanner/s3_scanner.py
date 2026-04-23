"""
Sentinel – S3 Bucket Scanner
Checks: public access, encryption, versioning, logging
"""
import json
import logging
from botocore.exceptions import ClientError
from backend.scanner.aws_client import aws_client

logger = logging.getLogger(__name__)


def scan_s3_buckets() -> list[dict]:
    """
    Fetches all S3 buckets and returns their configuration details.
    Returns a list of bucket config dicts ready for the rules engine.
    """
    results = []
    try:
        s3 = aws_client.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])
        logger.info(f"Found {len(buckets)} S3 buckets")

        for bucket in buckets:
            name = bucket["Name"]
            config = {
                "name": name,
                "resource_id": f"arn:aws:s3:::{name}",
                "resource_type": "S3",
                "public_access_block": _get_public_access_block(s3, name),
                "acl_public": _check_acl_public(s3, name),
                "encryption_enabled": _check_encryption(s3, name),
                "versioning_enabled": _check_versioning(s3, name),
                "logging_enabled": _check_logging(s3, name),
                "region": _get_bucket_region(s3, name),
                "policy_public": _check_bucket_policy_public(s3, name),
            }
            results.append(config)

    except ClientError as e:
        logger.error(f"S3 scan error: {e}")
    return results


def _get_public_access_block(s3, bucket_name: str) -> dict:
    try:
        resp = s3.get_public_access_block(Bucket=bucket_name)
        cfg = resp.get("PublicAccessBlockConfiguration", {})
        return cfg
    except ClientError:
        # No block policy set = potentially public
        return {}


def _check_acl_public(s3, bucket_name: str) -> bool:
    try:
        acl = s3.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            if grantee.get("URI") in [
                "http://acs.amazonaws.com/groups/global/AllUsers",
                "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
            ]:
                return True
        return False
    except ClientError:
        return False


def _check_encryption(s3, bucket_name: str) -> bool:
    try:
        s3.get_bucket_encryption(Bucket=bucket_name)
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return False
        return False


def _check_versioning(s3, bucket_name: str) -> bool:
    try:
        resp = s3.get_bucket_versioning(Bucket=bucket_name)
        return resp.get("Status") == "Enabled"
    except ClientError:
        return False


def _check_logging(s3, bucket_name: str) -> bool:
    try:
        resp = s3.get_bucket_logging(Bucket=bucket_name)
        return "LoggingEnabled" in resp
    except ClientError:
        return False


def _get_bucket_region(s3, bucket_name: str) -> str:
    try:
        resp = s3.get_bucket_location(Bucket=bucket_name)
        return resp.get("LocationConstraint") or "us-east-1"
    except ClientError:
        return "unknown"


def _check_bucket_policy_public(s3, bucket_name: str) -> bool:
    try:
        resp = s3.get_bucket_policy_status(Bucket=bucket_name)
        return resp.get("PolicyStatus", {}).get("IsPublic", False)
    except ClientError:
        return False
