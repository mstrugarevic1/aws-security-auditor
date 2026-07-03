from __future__ import annotations

import tomllib
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from botocore.config import Config

DEFAULT_REQUIRED_TAGS = ("Owner", "Environment", "CostCenter")
DEFAULT_CRITICAL_RESOURCE_TAGS = {
    "Environment": ("prod", "production", "prd"),
    "Criticality": ("high", "critical", "tier1"),
}
BASELINE_SERVICES = ("accessanalyzer", "cloudtrail", "config", "guardduty", "securityhub")
DEFAULT_SERVICES = (
    "ec2",
    "ecs",
    "ecr",
    "elbv2",
    "iam",
    "kms",
    "lambda",
    "rds",
    "s3",
    "secretsmanager",
    "tags",
    "vpc",
)
ALL_SERVICES = (
    "accessanalyzer",
    "cloudtrail",
    "config",
    "ec2",
    "ecs",
    "ecr",
    "elbv2",
    "guardduty",
    "iam",
    "kms",
    "lambda",
    "rds",
    "s3",
    "securityhub",
    "secretsmanager",
    "tags",
    "vpc",
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
    suppressions: tuple[Suppression, ...] = ()
    max_workers: int = 5


@dataclass(frozen=True)
class Suppression:
    check_id: str
    resource_id: str
    reason: str
    expires: date
    region: str | None = None
    account_id: str | None = None


@dataclass(frozen=True)
class FileConfig:
    required_tags: tuple[str, ...] | None
    critical_resource_tags: dict[str, tuple[str, ...]]
    suppressions: tuple[Suppression, ...]

    def __iter__(self) -> Iterator[object]:
        yield self.required_tags
        yield self.critical_resource_tags


AWS_CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 5})


def load_config_file(path: Path) -> FileConfig:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    required_tags = data.get("required_tags")
    critical_tags = data.get("critical_resource_tags", {})
    suppressions = data.get("suppressions", [])
    if required_tags is not None and not _strings(required_tags):
        raise ValueError("required_tags must be a list of strings")
    if not isinstance(critical_tags, dict):
        raise ValueError("critical_resource_tags must be a table")
    if not isinstance(suppressions, list):
        raise ValueError("suppressions must be a list of tables")
    parsed_critical: dict[str, tuple[str, ...]] = {}
    for key, values in critical_tags.items():
        if not isinstance(key, str) or not _strings(values):
            raise ValueError("critical_resource_tags values must be lists of strings")
        parsed_critical[key] = tuple(values)
    return FileConfig(
        tuple(required_tags) if required_tags is not None else None,
        parsed_critical,
        tuple(_parse_suppression(item) for item in suppressions),
    )


def _strings(value: object) -> bool:
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def _parse_suppression(value: object) -> Suppression:
    if not isinstance(value, dict):
        raise ValueError("each suppression must be a table")
    required = ("check_id", "resource_id", "reason", "expires")
    missing = [field_name for field_name in required if field_name not in value]
    if missing:
        raise ValueError(f"suppression missing required fields: {', '.join(missing)}")
    for field_name in (*required, "region", "account_id"):
        if field_name in value and not isinstance(value[field_name], str):
            raise ValueError(f"suppression {field_name} must be a string")
    reason = str(value["reason"]).strip()
    if not reason:
        raise ValueError("suppression reason must not be empty")
    try:
        expires = date.fromisoformat(str(value["expires"]))
    except ValueError as exc:
        raise ValueError("suppression expires must be an ISO date") from exc
    return Suppression(
        check_id=str(value["check_id"]),
        resource_id=str(value["resource_id"]),
        reason=reason,
        expires=expires,
        region=str(value["region"]) if value.get("region") is not None else None,
        account_id=str(value["account_id"]) if value.get("account_id") is not None else None,
    )
