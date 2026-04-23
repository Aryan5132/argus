"""
Sentinel – S3 Security Rules
Rules: public access, encryption, versioning, logging, policy public
"""
from typing import Optional
from backend.rules.base_rule import BaseRule, RuleFinding


class S3PublicAccessRule(BaseRule):
    rule_id = "S3-001"
    severity = "HIGH"
    title = "S3 Bucket Public Access Enabled"
    description = "The S3 bucket allows public access via ACL or bucket policy, exposing potentially sensitive data."
    suggested_fix = (
        "Enable S3 Block Public Access settings: go to S3 console → Bucket → Permissions → "
        "Block Public Access → enable all four options. Review and remove public ACL grants."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        block = resource.get("public_access_block", {})
        acl_public = resource.get("acl_public", False)
        policy_public = resource.get("policy_public", False)

        # Block public access fully enabled = safe
        fully_blocked = (
            block.get("BlockPublicAcls") and
            block.get("IgnorePublicAcls") and
            block.get("BlockPublicPolicy") and
            block.get("RestrictPublicBuckets")
        )
        if fully_blocked:
            return None

        if acl_public or policy_public or not fully_blocked:
            return self._make_finding(
                resource,
                resource_name=resource.get("name"),
                description=f"{self.description} (ACL public: {acl_public}, Policy public: {policy_public})",
                ml_features={
                    "public_access": 1,
                    "encryption_enabled": int(resource.get("encryption_enabled", False)),
                    "ip_open": 0, "sensitive_port": 0,
                    "wildcard_permission": 0, "mfa_enabled": 1, "public_ip": 0,
                },
            )
        return None


class S3EncryptionRule(BaseRule):
    rule_id = "S3-002"
    severity = "MEDIUM"
    title = "S3 Bucket Encryption Disabled"
    description = "The S3 bucket does not have server-side encryption enabled, exposing data at rest."
    suggested_fix = (
        "Enable default encryption: S3 console → Bucket → Properties → Default Encryption → "
        "Enable with AES-256 or AWS KMS key."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        if not resource.get("encryption_enabled", True):
            return self._make_finding(
                resource,
                resource_name=resource.get("name"),
                ml_features={
                    "public_access": int(resource.get("acl_public", False)),
                    "encryption_enabled": 0,
                    "ip_open": 0, "sensitive_port": 0,
                    "wildcard_permission": 0, "mfa_enabled": 1, "public_ip": 0,
                },
            )
        return None


class S3VersioningRule(BaseRule):
    rule_id = "S3-003"
    severity = "LOW"
    title = "S3 Bucket Versioning Disabled"
    description = "Versioning is disabled, which means accidental deletions or overwrites cannot be recovered."
    suggested_fix = (
        "Enable versioning: S3 console → Bucket → Properties → Bucket Versioning → Enable."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        if not resource.get("versioning_enabled", True):
            return self._make_finding(
                resource,
                resource_name=resource.get("name"),
                ml_features={
                    "public_access": int(resource.get("acl_public", False)),
                    "encryption_enabled": int(resource.get("encryption_enabled", False)),
                    "ip_open": 0, "sensitive_port": 0,
                    "wildcard_permission": 0, "mfa_enabled": 1, "public_ip": 0,
                },
            )
        return None


class S3LoggingRule(BaseRule):
    rule_id = "S3-004"
    severity = "LOW"
    title = "S3 Bucket Access Logging Disabled"
    description = "Server access logging is disabled. Without logs, it is difficult to audit access patterns."
    suggested_fix = (
        "Enable access logging: S3 console → Bucket → Properties → Server Access Logging → Enable. "
        "Specify a target bucket to store logs."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        if not resource.get("logging_enabled", True):
            return self._make_finding(resource, resource_name=resource.get("name"))
        return None


S3_RULES = [S3PublicAccessRule(), S3EncryptionRule(), S3VersioningRule(), S3LoggingRule()]
