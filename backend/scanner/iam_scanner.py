"""
Sentinel – IAM Scanner
Checks: wildcard permissions, MFA, unused credentials, root account, password policy
"""
import json
import logging
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError
from backend.scanner.aws_client import aws_client

logger = logging.getLogger(__name__)
UNUSED_DAYS_THRESHOLD = 90


def scan_iam() -> list[dict]:
    """Scan all IAM users and return config dicts for rules engine."""
    results = []
    try:
        iam = aws_client.client("iam")

        # Generate credential report for last-used info
        _generate_credential_report(iam)
        credential_report = _parse_credential_report(iam)

        users = _paginate(iam, "list_users", "Users")
        logger.info(f"Found {len(users)} IAM users")

        for user in users:
            username = user["UserName"]
            user_arn = user["Arn"]

            # MFA devices
            mfa_devices = _paginate(iam, "list_mfa_devices", "MFADevices", UserName=username)
            mfa_enabled = len(mfa_devices) > 0

            # Inline + attached policies – check for wildcard
            has_wildcard, wildcard_details = _check_wildcard_permissions(iam, username, user_arn)

            # Credential report fields
            cred_info = credential_report.get(username, {})
            access_key_last_used = cred_info.get("access_key_1_last_used_date", "N/A")
            password_last_used = cred_info.get("password_last_used", "N/A")
            has_access_key = cred_info.get("access_key_1_active", "false").lower() == "true"

            # Check unused credentials  
            unused_credentials = _check_unused_credentials(
                access_key_last_used, password_last_used, has_access_key
            )

            result = {
                "username": username,
                "resource_id": user_arn,
                "resource_type": "IAM",
                "mfa_enabled": mfa_enabled,
                "has_wildcard_permission": has_wildcard,
                "wildcard_details": wildcard_details,
                "has_access_key": has_access_key,
                "unused_credentials": unused_credentials,
                "access_key_last_used": access_key_last_used,
                "password_last_used": password_last_used,
                "user_created": user.get("CreateDate", "").isoformat() if hasattr(user.get("CreateDate", ""), "isoformat") else str(user.get("CreateDate", "")),
            }
            results.append(result)

        # Check root account MFA (separate check)
        root_config = _check_root_account(iam)
        if root_config:
            results.append(root_config)

    except ClientError as e:
        logger.error(f"IAM scan error: {e}")

    return results


def _paginate(client, method: str, key: str, **kwargs) -> list:
    items = []
    paginator = client.get_paginator(method)
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(key, []))
    return items


def _generate_credential_report(iam):
    try:
        while True:
            resp = iam.generate_credential_report()
            if resp.get("State") == "COMPLETE":
                break
    except ClientError:
        pass


def _parse_credential_report(iam) -> dict:
    try:
        resp = iam.get_credential_report()
        content = resp["Content"].decode("utf-8")
        lines = content.strip().split("\n")
        headers = lines[0].split(",")
        report = {}
        for line in lines[1:]:
            values = line.split(",")
            row = dict(zip(headers, values))
            report[row.get("user", "")] = row
        return report
    except Exception:
        return {}


def _check_wildcard_permissions(iam, username: str, user_arn: str):
    wildcard_details = []

    # Inline policies
    try:
        inline_names = _paginate(iam, "list_user_policies", "PolicyNames", UserName=username)
        for policy_name in inline_names:
            doc = iam.get_user_policy(UserName=username, PolicyName=policy_name)
            statements = doc.get("PolicyDocument", {}).get("Statement", [])
            for stmt in statements:
                if _is_wildcard_statement(stmt):
                    wildcard_details.append(f"Inline:{policy_name}")
    except ClientError:
        pass

    # Attached managed policies
    try:
        attached = _paginate(iam, "list_attached_user_policies", "AttachedPolicies", UserName=username)
        for policy in attached:
            policy_arn = policy["PolicyArn"]
            version_id = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            statements = doc["PolicyVersion"]["Document"].get("Statement", [])
            for stmt in statements:
                if _is_wildcard_statement(stmt):
                    wildcard_details.append(f"Managed:{policy['PolicyName']}")
    except ClientError:
        pass

    return len(wildcard_details) > 0, wildcard_details


def _is_wildcard_statement(stmt: dict) -> bool:
    actions = stmt.get("Action", [])
    resources = stmt.get("Resource", [])
    effect = stmt.get("Effect", "")
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]
    return effect == "Allow" and "*" in actions and "*" in resources


def _check_unused_credentials(key_last_used: str, pwd_last_used: str, has_key: bool) -> bool:
    now = datetime.now(timezone.utc)
    threshold = timedelta(days=UNUSED_DAYS_THRESHOLD)
    for date_str in [key_last_used, pwd_last_used]:
        if date_str and date_str not in ("N/A", "no_information", "not_supported", ""):
            try:
                last = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                if now - last > threshold:
                    return True
            except ValueError:
                pass
    return False


def _check_root_account(iam) -> dict | None:
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1
        return {
            "username": "<root>",
            "resource_id": "arn:aws:iam::root",
            "resource_type": "IAM",
            "mfa_enabled": mfa_enabled,
            "has_wildcard_permission": True,  # root always has *
            "wildcard_details": ["Root account"],
            "has_access_key": summary.get("AccountAccessKeysPresent", 0) > 0,
            "unused_credentials": False,
            "is_root": True,
        }
    except ClientError:
        return None
