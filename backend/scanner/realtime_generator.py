"""
Sentinel – Real-time Fallback Data Generator
Uses the user-provided stream generator and maps it to RuleFinding entries.
"""
from __future__ import annotations

import importlib.util
from itertools import islice
from pathlib import Path

from backend.rules.base_rule import RuleFinding

GENERATOR_PATH = Path(__file__).resolve().parents[2] / "dataset" / "dataset" / "realtime_data_generator.py"


def _load_external_generator():
    spec = importlib.util.spec_from_file_location("user_realtime_generator", str(GENERATOR_PATH))
    if not spec or not spec.loader:
        raise RuntimeError(f"Unable to load generator at {GENERATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    if not hasattr(module, "generate_realtime_data"):
        raise RuntimeError("Expected function generate_realtime_data() not found in user generator.")
    return module.generate_realtime_data


def _finding_from_point(data: dict) -> RuleFinding | None:
    instance_id = data.get("instance_id", "unknown-instance")
    status = str(data.get("status", "unknown"))
    cpu = float(data.get("cpu_utilization", 0.0))
    memory = float(data.get("memory_utilization", 0.0))
    net_out = int(data.get("network_out", 0))
    net_in = int(data.get("network_in", 0))

    if status in {"terminated", "stopped"}:
        return RuleFinding(
            rule_id="GEN-EC2-001",
            resource_type="EC2",
            resource_id=instance_id,
            resource_name=instance_id,
            severity="HIGH",
            title=f"Instance {status.upper()} in Real-time Feed",
            description=f"Generator reported instance state '{status}' at {data.get('timestamp')}.",
            suggested_fix="Validate instance lifecycle events and recover required services.",
            region="ap-south-1",
            ml_features={
                "public_access": 0,
                "encryption_enabled": 1,
                "ip_open": 0,
                "sensitive_port": 0,
                "wildcard_permission": 0,
                "mfa_enabled": 1,
                "public_ip": 0,
            },
        )

    if cpu >= 85 or memory >= 90:
        return RuleFinding(
            rule_id="GEN-EC2-002",
            resource_type="EC2",
            resource_id=instance_id,
            resource_name=instance_id,
            severity="MEDIUM",
            title="High EC2 Runtime Utilization Detected",
            description=(
                f"cpu={cpu:.2f}% memory={memory:.2f}% network_out={net_out} network_in={net_in} "
                f"at {data.get('timestamp')}."
            ),
            suggested_fix="Scale out/increase instance capacity and inspect running workloads.",
            region="ap-south-1",
            ml_features={
                "public_access": 0,
                "encryption_enabled": 1,
                "ip_open": int(net_out > 90000),
                "sensitive_port": 0,
                "wildcard_permission": 0,
                "mfa_enabled": 1,
                "public_ip": 0,
            },
        )

    if net_out >= 95000:
        return RuleFinding(
            rule_id="GEN-EC2-003",
            resource_type="EC2",
            resource_id=instance_id,
            resource_name=instance_id,
            severity="LOW",
            title="Unusually High Outbound Network Activity",
            description=f"Outbound traffic spike detected: network_out={net_out} at {data.get('timestamp')}.",
            suggested_fix="Verify expected traffic destination and investigate suspicious egress.",
            region="ap-south-1",
            ml_features={
                "public_access": 0,
                "encryption_enabled": 1,
                "ip_open": 1,
                "sensitive_port": 0,
                "wildcard_permission": 0,
                "mfa_enabled": 1,
                "public_ip": 1,
            },
        )

    return None


def get_realtime_generated_findings() -> list[RuleFinding]:
    generate_realtime_data = _load_external_generator()
    stream = generate_realtime_data()
    findings: list[RuleFinding] = []

    # Consume a small window from the live stream to build each scan payload.
    for point in islice(stream, 9):
        finding = _finding_from_point(point)
        if finding:
            findings.append(finding)

    return findings
