"""
Sentinel – IAM Security Rules
Rules: wildcard permissions, MFA, unused credentials, root account
"""
from typing import Optional
from backend.rules.base_rule import BaseRule, RuleFinding


class IAMWildcardPermissionRule(BaseRule):
    rule_id = "IAM-001"
    severity = "CRITICAL"
    title = "IAM User Has Wildcard (Action:* Resource:*) Permission"
    description = (
        "An IAM policy attached to this user grants Action='*' and Resource='*', "
        "giving full administrative access to the entire AWS account."
    )
    suggested_fix = (
        "Replace wildcard policies with least-privilege policies. Use AWS IAM Access Analyzer "
        "to generate minimal permission sets. Remove AdministratorAccess managed policy if attached."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        if resource.get("is_root"):
            return None  # Root handled separately
        if resource.get("has_wildcard_permission"):
            details = ", ".join(resource.get("wildcard_details", []))
            return self._make_finding(
                resource,
                resource_name=resource.get("username"),
                description=f"{self.description} Policies: {details}",
                ml_features={
                    "public_access": 0, "encryption_enabled": 1, "ip_open": 0,
                    "sensitive_port": 0, "wildcard_permission": 1,
                    "mfa_enabled": int(resource.get("mfa_enabled", False)),
                    "public_ip": 0,
                },
            )
        return None


class IAMMFARule(BaseRule):
    rule_id = "IAM-002"
    severity = "HIGH"
    title = "IAM User MFA Not Enabled"
    description = "Multi-Factor Authentication (MFA) is not enabled for this IAM user, increasing account takeover risk."
    suggested_fix = (
        "Enable MFA: IAM Console → Users → Security Credentials → Assign MFA device. "
        "Enforce MFA via IAM policy condition: aws:MultiFactorAuthPresent = true."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        if not resource.get("mfa_enabled", True) and resource.get("has_access_key"):
            return self._make_finding(
                resource,
                resource_name=resource.get("username"),
                ml_features={
                    "public_access": 0, "encryption_enabled": 1, "ip_open": 0,
                    "sensitive_port": 0,
                    "wildcard_permission": int(resource.get("has_wildcard_permission", False)),
                    "mfa_enabled": 0, "public_ip": 0,
                },
            )
        return None


class IAMUnusedCredentialsRule(BaseRule):
    rule_id = "IAM-003"
    severity = "MEDIUM"
    title = "IAM User Has Unused Credentials (>90 days)"
    description = "Access keys or passwords that have not been used in over 90 days pose a dormant security risk."
    suggested_fix = (
        "Deactivate or delete unused access keys: IAM Console → Users → Security Credentials. "
        "Implement automated key rotation policy using AWS Config rule: iam-user-unused-credentials-check."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        if resource.get("unused_credentials") and not resource.get("is_root"):
            return self._make_finding(
                resource,
                resource_name=resource.get("username"),
                description=f"{self.description} Last key use: {resource.get('access_key_last_used', 'N/A')}",
                ml_features={
                    "public_access": 0, "encryption_enabled": 1, "ip_open": 0,
                    "sensitive_port": 0,
                    "wildcard_permission": int(resource.get("has_wildcard_permission", False)),
                    "mfa_enabled": int(resource.get("mfa_enabled", False)),
                    "public_ip": 0,
                },
            )
        return None


class IAMRootMFARule(BaseRule):
    rule_id = "IAM-004"
    severity = "CRITICAL"
    title = "Root Account MFA Not Enabled"
    description = "The AWS root account does not have MFA enabled. Root compromise can lead to total account takeover."
    suggested_fix = (
        "Enable MFA on root account immediately: AWS Console → top-right username → Security Credentials → "
        "Activate MFA. Use a hardware MFA device for root accounts."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        if resource.get("is_root") and not resource.get("mfa_enabled"):
            return self._make_finding(
                resource,
                resource_name="<root>",
                ml_features={
                    "public_access": 0, "encryption_enabled": 1, "ip_open": 0,
                    "sensitive_port": 0, "wildcard_permission": 1, "mfa_enabled": 0, "public_ip": 0,
                },
            )
        return None


IAM_RULES = [IAMWildcardPermissionRule(), IAMMFARule(), IAMUnusedCredentialsRule(), IAMRootMFARule()]
