"""
Sentinel – Security Group Rules
Rules: SSH/RDP/any public port, all-traffic open
"""
from typing import Optional
from backend.rules.base_rule import BaseRule, RuleFinding


class SGSSHOpenRule(BaseRule):
    rule_id = "SG-001"
    severity = "HIGH"
    title = "Security Group Allows SSH (Port 22) from 0.0.0.0/0"
    description = "Port 22 (SSH) is open to the entire internet, exposing instances to brute-force and unauthorized access."
    suggested_fix = (
        "Restrict SSH access to known IP ranges: EC2 Console → Security Groups → Edit Inbound Rules → "
        "Change source from 0.0.0.0/0 to your organization's IP CIDR. "
        "Better: use AWS Systems Manager Session Manager to eliminate SSH entirely."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        for exposed in resource.get("sensitive_ports_exposed", []):
            if exposed.get("port") == 22:
                return self._make_finding(
                    resource,
                    resource_name=resource.get("sg_name"),
                    ml_features={
                        "public_access": 0, "encryption_enabled": 1, "ip_open": 1,
                        "sensitive_port": 1, "wildcard_permission": 0, "mfa_enabled": 1, "public_ip": 0,
                    },
                )
        return None


class SGRDPOpenRule(BaseRule):
    rule_id = "SG-002"
    severity = "HIGH"
    title = "Security Group Allows RDP (Port 3389) from 0.0.0.0/0"
    description = "Port 3389 (RDP) is open to the internet, enabling remote desktop attacks from anywhere."
    suggested_fix = (
        "Restrict RDP to known IPs. Use AWS Systems Manager Fleet Manager for Windows remote access "
        "without opening RDP ports."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        for exposed in resource.get("sensitive_ports_exposed", []):
            if exposed.get("port") == 3389:
                return self._make_finding(
                    resource,
                    resource_name=resource.get("sg_name"),
                    ml_features={
                        "public_access": 0, "encryption_enabled": 1, "ip_open": 1,
                        "sensitive_port": 1, "wildcard_permission": 0, "mfa_enabled": 1, "public_ip": 0,
                    },
                )
        return None


class SGSensitivePortRule(BaseRule):
    rule_id = "SG-003"
    severity = "HIGH"
    title = "Security Group Exposes Sensitive Service Port to Internet"
    description = "A database or cache service port is publicly accessible (MySQL/PostgreSQL/Redis/MongoDB/Elasticsearch)."
    suggested_fix = (
        "Database ports must NEVER be publicly accessible. Move databases to private subnets. "
        "Use VPC security groups to allow access only from application servers."
    )

    SENSITIVE_DB_PORTS = {3306, 5432, 6379, 27017, 9200}

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        for exposed in resource.get("sensitive_ports_exposed", []):
            if exposed.get("port") in self.SENSITIVE_DB_PORTS:
                return self._make_finding(
                    resource,
                    rule_id="SG-003",
                    resource_name=resource.get("sg_name"),
                    severity="HIGH",
                    title=f"Security Group Exposes {exposed.get('service')} Port {exposed.get('port')} to Internet",
                    description=f"Port {exposed.get('port')} ({exposed.get('service')}) is publicly accessible.",
                    suggested_fix=self.suggested_fix,
                    ml_features={
                        "public_access": 0, "encryption_enabled": 1, "ip_open": 1,
                        "sensitive_port": 1, "wildcard_permission": 0, "mfa_enabled": 1, "public_ip": 0,
                    },
                )
        return None


class SGPublicPortRule(BaseRule):
    rule_id = "SG-004"
    severity = "MEDIUM"
    title = "Security Group Has Port Open to Internet"
    description = "One or more ports are accessible from any IP address (0.0.0.0/0 or ::/0)."
    suggested_fix = (
        "Review all inbound rules with source 0.0.0.0/0 or ::/0. Restrict to minimum necessary CIDRs. "
        "Use AWS WAF for public web endpoints instead of direct SG exposure."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        open_rules = resource.get("open_to_public", [])
        if open_rules:
            port_summary = ", ".join([r.get("port_range", "?") for r in open_rules[:5]])
            return self._make_finding(
                resource,
                resource_name=resource.get("sg_name"),
                description=f"{self.description} Open ports: {port_summary}",
                ml_features={
                    "public_access": 0, "encryption_enabled": 1, "ip_open": 1,
                    "sensitive_port": 0, "wildcard_permission": 0, "mfa_enabled": 1, "public_ip": 0,
                },
            )
        return None


class SGAllTrafficRule(BaseRule):
    rule_id = "SG-005"
    severity = "CRITICAL"
    title = "Security Group Allows All Traffic from Internet"
    description = "The security group allows all protocols and all ports from 0.0.0.0/0 — complete exposure."
    suggested_fix = (
        "Immediately remove the 'All traffic' inbound rule. Define specific port/protocol rules "
        "for only the services that need to be accessible."
    )

    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        if resource.get("all_traffic_open") and resource.get("open_to_public"):
            return self._make_finding(
                resource,
                resource_name=resource.get("sg_name"),
                ml_features={
                    "public_access": 1, "encryption_enabled": 1, "ip_open": 1,
                    "sensitive_port": 1, "wildcard_permission": 0, "mfa_enabled": 1, "public_ip": 0,
                },
            )
        return None


SG_RULES = [SGAllTrafficRule(), SGSSHOpenRule(), SGRDPOpenRule(), SGSensitivePortRule(), SGPublicPortRule()]
