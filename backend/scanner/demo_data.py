"""
Sentinel – Demo Data Generator
Produces realistic mock findings when AWS credentials are not configured.
These findings mirror what a typical misconfigured AWS account looks like,
and pass through the same rules engine + ML scorer as real data.
"""
from backend.rules.base_rule import RuleFinding

DEMO_RESOURCES = {
    # ── S3 Buckets ────────────────────────────────────────────────────────────
    "s3": [
        {
            "name": "prod-customer-data-backup",
            "resource_id": "arn:aws:s3:::prod-customer-data-backup",
            "resource_type": "S3",
            "public_access_block": {},          # no block policy set
            "acl_public": True,                 # public ACL!
            "policy_public": True,
            "encryption_enabled": False,
            "versioning_enabled": False,
            "logging_enabled": False,
            "region": "us-east-1",
        },
        {
            "name": "dev-ml-datasets",
            "resource_id": "arn:aws:s3:::dev-ml-datasets",
            "resource_type": "S3",
            "public_access_block": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                     "BlockPublicPolicy": False, "RestrictPublicBuckets": False},
            "acl_public": False,
            "policy_public": False,
            "encryption_enabled": False,        # encryption off
            "versioning_enabled": False,
            "logging_enabled": False,
            "region": "us-west-2",
        },
        {
            "name": "staging-app-assets",
            "resource_id": "arn:aws:s3:::staging-app-assets",
            "resource_type": "S3",
            "public_access_block": {"BlockPublicAcls": True, "IgnorePublicAcls": True,
                                     "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
            "acl_public": False,
            "policy_public": False,
            "encryption_enabled": True,
            "versioning_enabled": False,        # versioning off
            "logging_enabled": False,
            "region": "eu-west-1",
        },
        {
            "name": "finance-reports-2024",
            "resource_id": "arn:aws:s3:::finance-reports-2024",
            "resource_type": "S3",
            "public_access_block": {},
            "acl_public": False,
            "policy_public": False,
            "encryption_enabled": True,
            "versioning_enabled": True,
            "logging_enabled": False,           # logging off
            "region": "us-east-1",
        },
    ],

    # ── IAM Users ─────────────────────────────────────────────────────────────
    "iam": [
        {
            "username": "ci-deploy-bot",
            "resource_id": "arn:aws:iam::123456789012:user/ci-deploy-bot",
            "resource_type": "IAM",
            "mfa_enabled": False,               # no MFA
            "has_wildcard_permission": True,    # AdministratorAccess!
            "wildcard_details": ["Managed:AdministratorAccess"],
            "has_access_key": True,
            "unused_credentials": False,
            "access_key_last_used": "2026-04-17T10:00:00+00:00",
            "password_last_used": "N/A",
            "is_root": False,
        },
        {
            "username": "legacy-analytics",
            "resource_id": "arn:aws:iam::123456789012:user/legacy-analytics",
            "resource_type": "IAM",
            "mfa_enabled": False,               # no MFA
            "has_wildcard_permission": False,
            "wildcard_details": [],
            "has_access_key": True,
            "unused_credentials": True,         # not used in 90+ days
            "access_key_last_used": "2025-12-01T00:00:00+00:00",
            "password_last_used": "N/A",
            "is_root": False,
        },
        {
            "username": "data-science-team",
            "resource_id": "arn:aws:iam::123456789012:user/data-science-team",
            "resource_type": "IAM",
            "mfa_enabled": False,               # no MFA
            "has_wildcard_permission": True,    # wildcard inline policy
            "wildcard_details": ["Inline:InlineAdminPolicy"],
            "has_access_key": True,
            "unused_credentials": False,
            "access_key_last_used": "2026-04-10T08:00:00+00:00",
            "password_last_used": "N/A",
            "is_root": False,
        },
        # Root account
        {
            "username": "<root>",
            "resource_id": "arn:aws:iam::root",
            "resource_type": "IAM",
            "mfa_enabled": False,               # root MFA disabled!
            "has_wildcard_permission": True,
            "wildcard_details": ["Root account"],
            "has_access_key": True,
            "unused_credentials": False,
            "is_root": True,
        },
    ],

    # ── Security Groups ───────────────────────────────────────────────────────
    "sg": [
        {
            "sg_id": "sg-0a1b2c3d4e",
            "sg_name": "web-servers-prod",
            "resource_id": "sg-0a1b2c3d4e",
            "resource_type": "SECURITY_GROUP",
            "vpc_id": "vpc-0abc1234",
            "region": "us-east-1",
            "open_to_public": [
                {"port_range": "22", "protocol": "tcp", "cidrs": ["0.0.0.0/0"]},
                {"port_range": "80", "protocol": "tcp", "cidrs": ["0.0.0.0/0"]},
                {"port_range": "443", "protocol": "tcp", "cidrs": ["0.0.0.0/0"]},
            ],
            "sensitive_ports_exposed": [{"port": 22, "service": "SSH"}],
            "all_traffic_open": False,
            "inbound_rule_count": 3,
        },
        {
            "sg_id": "sg-0b2c3d4e5f",
            "sg_name": "database-servers",
            "resource_id": "sg-0b2c3d4e5f",
            "resource_type": "SECURITY_GROUP",
            "vpc_id": "vpc-0abc1234",
            "region": "us-east-1",
            "open_to_public": [
                {"port_range": "3306", "protocol": "tcp", "cidrs": ["0.0.0.0/0"]},
                {"port_range": "5432", "protocol": "tcp", "cidrs": ["0.0.0.0/0"]},
            ],
            "sensitive_ports_exposed": [
                {"port": 3306, "service": "MySQL"},
                {"port": 5432, "service": "PostgreSQL"},
            ],
            "all_traffic_open": False,
            "inbound_rule_count": 2,
        },
        {
            "sg_id": "sg-0c3d4e5f6g",
            "sg_name": "bastion-host-legacy",
            "resource_id": "sg-0c3d4e5f6g",
            "resource_type": "SECURITY_GROUP",
            "vpc_id": "vpc-0def5678",
            "region": "us-west-2",
            "open_to_public": [
                {"port_range": "0-65535", "protocol": "-1", "cidrs": ["0.0.0.0/0", "::/0"]},
            ],
            "sensitive_ports_exposed": [
                {"port": 22, "service": "SSH"},
                {"port": 3389, "service": "RDP"},
            ],
            "all_traffic_open": True,
            "inbound_rule_count": 1,
        },
        {
            "sg_id": "sg-0d4e5f6g7h",
            "sg_name": "dev-jump-box",
            "resource_id": "sg-0d4e5f6g7h",
            "resource_type": "SECURITY_GROUP",
            "vpc_id": "vpc-0def5678",
            "region": "eu-west-1",
            "open_to_public": [
                {"port_range": "3389", "protocol": "tcp", "cidrs": ["0.0.0.0/0"]},
            ],
            "sensitive_ports_exposed": [{"port": 3389, "service": "RDP"}],
            "all_traffic_open": False,
            "inbound_rule_count": 1,
        },
    ],

    # ── EC2 Instances ─────────────────────────────────────────────────────────
    "ec2": [
        {
            "instance_id": "i-0abc123def456789a",
            "instance_name": "prod-api-server-01",
            "resource_id": "arn:aws:ec2:us-east-1:i-0abc123def456789a",
            "resource_type": "EC2",
            "instance_type": "t3.medium",
            "state": "running",
            "public_ip": "54.172.88.19",
            "public_dns": "ec2-54-172-88-19.compute-1.amazonaws.com",
            "has_public_ip": True,              # public IP exposed
            "security_group_ids": ["sg-0a1b2c3d4e"],
            "no_security_groups": False,
            "imdsv2_required": False,           # IMDSv1 allowed (SSRF risk)
            "unencrypted_volumes": ["/dev/xvda"],
            "region": "us-east-1",
        },
        {
            "instance_id": "i-0def456abc789012b",
            "instance_name": "analytics-worker-03",
            "resource_id": "arn:aws:ec2:us-west-2:i-0def456abc789012b",
            "resource_type": "EC2",
            "instance_type": "c5.xlarge",
            "state": "running",
            "public_ip": "34.218.45.102",
            "public_dns": "ec2-34-218-45-102.us-west-2.compute.amazonaws.com",
            "has_public_ip": True,
            "security_group_ids": [],
            "no_security_groups": True,         # no SG attached!
            "imdsv2_required": False,
            "unencrypted_volumes": ["/dev/xvda", "/dev/xvdb"],
            "region": "us-west-2",
        },
    ],
}


def get_demo_findings() -> list[RuleFinding]:
    """
    Run all demo resources through the real rules engine.
    Returns a list of RuleFinding objects identical to what a real scan would produce.
    """
    from backend.rules.s3_rules import S3_RULES
    from backend.rules.iam_rules import IAM_RULES
    from backend.rules.sg_rules import SG_RULES
    from backend.rules.ec2_rules import EC2_RULES

    all_findings = []

    for resource in DEMO_RESOURCES["s3"]:
        for rule in S3_RULES:
            f = rule.evaluate(resource)
            if f:
                all_findings.append(f)

    for resource in DEMO_RESOURCES["iam"]:
        for rule in IAM_RULES:
            f = rule.evaluate(resource)
            if f:
                all_findings.append(f)

    for resource in DEMO_RESOURCES["sg"]:
        for rule in SG_RULES:
            f = rule.evaluate(resource)
            if f:
                all_findings.append(f)

    for resource in DEMO_RESOURCES["ec2"]:
        for rule in EC2_RULES:
            f = rule.evaluate(resource)
            if f:
                all_findings.append(f)

    return all_findings
