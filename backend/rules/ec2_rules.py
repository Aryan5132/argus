"""
Sentinel – EC2 Security Rules
Rules: public IP with open ports, no SG, IMDSv1, unencrypted EBS
"""
from typing import Optional
from backend.rules.base_rule import BaseRule, RuleFinding


class EC2PublicIPRule(BaseRule):
    rule_id = "EC2-001"
    severity = "HIGH"
    title = "EC2 Instance Has Public IP Address"
    description = "The instance has a public IP, making it directly reachable from the internet."
    suggested_fix = (
        "Move instances to private subnets and access via ALB/NAT gateway. "
        "If public access is required, ensure security groups are tightly restricted."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        if resource.get("has_public_ip"):
            return self._make_finding(
                resource,
                resource_name=resource.get("instance_name"),
                description=f"{self.description} Public IP: {resource.get('public_ip')}",
                ml_features={
                    "public_access": 0, "encryption_enabled": 1, "ip_open": 1,
                    "sensitive_port": 0, "wildcard_permission": 0, "mfa_enabled": 1, "public_ip": 1,
                },
            )
        return None


class EC2NoSecurityGroupRule(BaseRule):
    rule_id = "EC2-002"
    severity = "HIGH"
    title = "EC2 Instance Has No Security Group"
    description = "The instance has no security groups attached, potentially inheriting a default permissive policy."
    suggested_fix = (
        "Assign at least one security group with a deny-all default and explicit allow rules. "
        "Never rely on EC2-Classic networking."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        if resource.get("no_security_groups"):
            return self._make_finding(
                resource,
                resource_name=resource.get("instance_name"),
                ml_features={
                    "public_access": 0, "encryption_enabled": 1, "ip_open": 0,
                    "sensitive_port": 0, "wildcard_permission": 0, "mfa_enabled": 1,
                    "public_ip": int(resource.get("has_public_ip", False)),
                },
            )
        return None


class EC2IMDSv1Rule(BaseRule):
    rule_id = "EC2-003"
    severity = "MEDIUM"
    title = "EC2 Instance Allows IMDSv1 (Metadata Service v1)"
    description = (
        "Instance Metadata Service v1 is vulnerable to SSRF attacks that can expose "
        "IAM credentials via the metadata endpoint."
    )
    suggested_fix = (
        "Enforce IMDSv2: EC2 Console → Instance → Actions → Modify Instance Metadata Options → "
        "Set HttpTokens=required. Or use AWS CLI: "
        "aws ec2 modify-instance-metadata-options --instance-id <ID> --http-tokens required"
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        if not resource.get("imdsv2_required", True):
            return self._make_finding(
                resource,
                resource_name=resource.get("instance_name"),
                ml_features={
                    "public_access": 0, "encryption_enabled": 1, "ip_open": 0,
                    "sensitive_port": 0, "wildcard_permission": 0, "mfa_enabled": 1,
                    "public_ip": int(resource.get("has_public_ip", False)),
                },
            )
        return None


class EC2UnencryptedEBSRule(BaseRule):
    rule_id = "EC2-004"
    severity = "MEDIUM"
    title = "EC2 Instance Has Unencrypted EBS Volumes"
    description = "One or more EBS volumes attached to this instance are not encrypted at rest."
    suggested_fix = (
        "Enable EBS encryption by default: EC2 Console → Settings → Enable EBS Encryption. "
        "For existing volumes: create encrypted snapshot and launch new encrypted volume."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        unencrypted = resource.get("unencrypted_volumes", [])
        if unencrypted:
            return self._make_finding(
                resource,
                resource_name=resource.get("instance_name"),
                description=f"{self.description} Volumes: {', '.join(unencrypted)}",
                ml_features={
                    "public_access": 0, "encryption_enabled": 0, "ip_open": 0,
                    "sensitive_port": 0, "wildcard_permission": 0, "mfa_enabled": 1,
                    "public_ip": int(resource.get("has_public_ip", False)),
                },
            )
        return None


EC2_RULES = [EC2PublicIPRule(), EC2NoSecurityGroupRule(), EC2IMDSv1Rule(), EC2UnencryptedEBSRule()]
