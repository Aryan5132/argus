"""
Sentinel – Base Rule Class
All rules inherit from this and return a standardised Finding dict.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class RuleFinding:
    rule_id: str
    resource_type: str
    resource_id: str
    resource_name: str
    severity: str  # CRITICAL / HIGH / MEDIUM / LOW
    title: str
    description: str
    suggested_fix: str
    region: Optional[str] = None
    extra_data: dict = field(default_factory=dict)

    # ML feature vector
    ml_features: dict = field(default_factory=dict)


class BaseRule(ABC):
    rule_id: str = ""
    severity: str = "MEDIUM"
    title: str = ""
    description: str = ""
    suggested_fix: str = ""

    @abstractmethod
    def evaluate(self, resource: dict) -> Optional[RuleFinding]:
        """Return a RuleFinding if the rule triggers, else None."""
        ...

    def _make_finding(self, resource: dict, **overrides) -> RuleFinding:
        return RuleFinding(
            rule_id=overrides.get("rule_id", self.rule_id),
            resource_type=resource.get("resource_type", "UNKNOWN"),
            resource_id=resource.get("resource_id", ""),
            resource_name=overrides.get("resource_name",
                          resource.get("resource_name", resource.get("resource_id", ""))),
            severity=overrides.get("severity", self.severity),
            title=overrides.get("title", self.title),
            description=overrides.get("description", self.description),
            suggested_fix=overrides.get("suggested_fix", self.suggested_fix),
            region=resource.get("region"),
            extra_data=overrides.get("extra_data", {}),
            ml_features=overrides.get("ml_features", {}),
        )
