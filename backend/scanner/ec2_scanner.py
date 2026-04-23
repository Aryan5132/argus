"""
Sentinel – EC2 Instance Scanner
Checks: public IPs, open security groups, IMDSv2, EBS encryption
"""
import logging
from botocore.exceptions import ClientError
from backend.scanner.aws_client import aws_client

logger = logging.getLogger(__name__)


def scan_ec2_instances() -> list[dict]:
    """Scan EC2 instances across all regions."""
    all_results = []
    regions = aws_client.get_all_regions()
    logger.info(f"Scanning EC2 in {len(regions)} regions")

    for region in regions:
        try:
            ec2 = aws_client.client("ec2", region=region)
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate(
                Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
            ):
                for reservation in page.get("Reservations", []):
                    for instance in reservation.get("Instances", []):
                        config = _parse_instance(instance, region)
                        all_results.append(config)
        except ClientError as e:
            logger.warning(f"EC2 scan failed in {region}: {e}")

    logger.info(f"Found {len(all_results)} EC2 instances total")
    return all_results


def _parse_instance(instance: dict, region: str) -> dict:
    instance_id = instance["InstanceId"]
    instance_type = instance.get("InstanceType", "")
    state = instance.get("State", {}).get("Name", "unknown")
    public_ip = instance.get("PublicIpAddress")
    public_dns = instance.get("PublicDnsName")
    has_public_ip = bool(public_ip)

    sg_ids = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]

    # IMDSv2 check
    metadata_options = instance.get("MetadataOptions", {})
    imdsv2_required = metadata_options.get("HttpTokens") == "required"

    # EBS encryption check
    block_devices = instance.get("BlockDeviceMappings", [])
    unencrypted_volumes = []
    for bd in block_devices:
        ebs = bd.get("Ebs", {})
        if not ebs.get("Encrypted", False):
            unencrypted_volumes.append(bd.get("DeviceName", "unknown"))

    # Tags
    tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
    name = tags.get("Name", instance_id)

    return {
        "instance_id": instance_id,
        "instance_name": name,
        "resource_id": f"arn:aws:ec2:{region}:{instance_id}",
        "resource_type": "EC2",
        "instance_type": instance_type,
        "state": state,
        "public_ip": public_ip,
        "public_dns": public_dns,
        "has_public_ip": has_public_ip,
        "security_group_ids": sg_ids,
        "no_security_groups": len(sg_ids) == 0,
        "imdsv2_required": imdsv2_required,
        "unencrypted_volumes": unencrypted_volumes,
        "region": region,
    }
