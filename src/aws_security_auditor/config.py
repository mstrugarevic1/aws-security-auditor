from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from botocore.config import Config

DEFAULT_REQUIRED_TAGS = ("Owner", "Environment", "CostCenter")
DEFAULT_CRITICAL_RESOURCE_TAGS = {
    "Environment": ("prod", "production", "prd"),
    "Criticality": ("high", "critical", "tier1"),
}
BASELINE_SERVICES = ("cloudtrail", "config", "guardduty", "securityhub")
DEFAULT_SERVICES = (
    "ec2",
    "ecr",
    "elbv2",
    "iam",
    "kms",
    "rds",
    "s3",
    "tags",
)
ALL_SERVICES = (
    "cloudtrail",
    "config",
    "ec2",
    "ecr",
    "elbv2",
    "guardduty",
    "iam",
    "kms",
    "rds",
    "s3",
    "securityhub",
    "tags",
)


@dataclass(frozen=True)
class ScanConfig:
    profile: str | None = None
    role_arn: str | None = None
    external_id: str | None = None
    regions: tuple[str, ...] | None = None
    exclude_regions: tuple[str, ...] = ()
    services: tuple[str, ...] | None = None
    output: str = "table"
    output_file: str | None = None
    severity: str | None = None
    fail_on: str | None = None
    no_color: bool = False
    verbose: bool = False
    snapshot_age_days: int = 90
    access_key_age_days: int = 90
    required_tags: tuple[str, ...] = DEFAULT_REQUIRED_TAGS
    critical_resource_tags: dict[str, tuple[str, ...]] = field(
        default_factory=lambda: {
            key: tuple(values) for key, values in DEFAULT_CRITICAL_RESOURCE_TAGS.items()
        }
    )
    max_workers: int = 5


AWS_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 5})


def load_config_file(path: Path) -> tuple[tuple[str, ...] | None, dict[str, tuple[str, ...]]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    required_tags = data.get("required_tags")
    critical_tags = data.get("critical_resource_tags", {})
    if required_tags is not None and not _strings(required_tags):
        raise ValueError("required_tags must be a list of strings")
    if not isinstance(critical_tags, dict):
        raise ValueError("critical_resource_tags must be a table")
    parsed_critical: dict[str, tuple[str, ...]] = {}
    for key, values in critical_tags.items():
        if not isinstance(key, str) or not _strings(values):
            raise ValueError("critical_resource_tags values must be lists of strings")
        parsed_critical[key] = tuple(values)
    return tuple(required_tags) if required_tags is not None else None, parsed_critical


def _strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)
