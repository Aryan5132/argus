"""
Sentinel – Security Group Scanner
Checks: SSH/RDP/any port open to 0.0.0.0/0 or ::/0 across all regions
"""
import logging
from botocore.exceptions import ClientError
from backend.scanner.aws_client import aws_client

logger = logging.getLogger(__name__)

SENSITIVE_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL",
                   6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch", 8080: "HTTP-Alt"}
PUBLIC_CIDRS = {"0.0.0.0/0", "::/0"}


def scan_security_groups() -> list[dict]:
    """Scan SGs across all regions."""
    all_results = []
    regions = aws_client.get_all_regions()
    logger.info(f"Scanning security groups in {len(regions)} regions")

    for region in regions:
        try:
            ec2 = aws_client.client("ec2", region=region)
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page.get("SecurityGroups", []):
                    config = _parse_sg(sg, region)
                    all_results.append(config)
        except ClientError as e:
            logger.warning(f"SG scan failed in {region}: {e}")

    logger.info(f"Found {len(all_results)} security groups total")
    return all_results


def _parse_sg(sg: dict, region: str) -> dict:
    sg_id = sg["GroupId"]
    sg_name = sg.get("GroupName", sg_id)
    inbound_rules = sg.get("IpPermissions", [])

    open_to_public = []
    sensitive_ports_exposed = []
    all_traffic_open = False

    for rule in inbound_rules:
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)
        protocol = rule.get("IpProtocol", "-1")

        if protocol == "-1":
            all_traffic_open = True

        public_cidrs_in_rule = []
        for ip_range in rule.get("IpRanges", []):
            if ip_range.get("CidrIp") in PUBLIC_CIDRS:
                public_cidrs_in_rule.append(ip_range["CidrIp"])
        for ip_range in rule.get("Ipv6Ranges", []):
            if ip_range.get("CidrIpv6") in PUBLIC_CIDRS:
                public_cidrs_in_rule.append(ip_range["CidrIpv6"])

        if public_cidrs_in_rule:
            port_range = f"{from_port}-{to_port}" if from_port != to_port else str(from_port)
            open_to_public.append({
                "port_range": port_range,
                "protocol": protocol,
                "cidrs": public_cidrs_in_rule,
            })
            # Check if any sensitive port in range
            for port, service in SENSITIVE_PORTS.items():
                if from_port <= port <= to_port:
                    sensitive_ports_exposed.append({"port": port, "service": service})

    return {
        "sg_id": sg_id,
        "sg_name": sg_name,
        "resource_id": sg_id,
        "resource_type": "SECURITY_GROUP",
        "vpc_id": sg.get("VpcId", ""),
        "description": sg.get("Description", ""),
        "region": region,
        "open_to_public": open_to_public,
        "sensitive_ports_exposed": sensitive_ports_exposed,
        "all_traffic_open": all_traffic_open,
        "inbound_rule_count": len(inbound_rules),
    }
