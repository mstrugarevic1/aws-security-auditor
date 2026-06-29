from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from aws_security_auditor.checks.base import CheckResult
from aws_security_auditor.models import Finding, ScanError, Severity
from aws_security_auditor.readonly_client import ReadOnlyAwsClient


def scan_rds(
    rds: ReadOnlyAwsClient,
    region: str,
    critical_resource_tags: dict[str, tuple[str, ...]] | None = None,
) -> CheckResult:
    result = CheckResult(checks=5)
    try:
        for page in rds.paginate("describe_db_instances"):
            instances = page.get("DBInstances", [])
            result.resources += len(instances)
            for db in instances:
                dbid = db.get("DBInstanceIdentifier", "unknown")
                critical = _is_critical(rds, db, critical_resource_tags or {})
                if db.get("PubliclyAccessible"):
                    result.findings.append(
                        Finding(
                            Severity.HIGH,
                            "RDS_PUBLIC_INSTANCE",
                            "RDS",
                            region,
                            dbid,
                            "Publicly accessible RDS instance",
                            "RDS instance is reachable from public networks.",
                            "Disable public accessibility unless explicitly required.",
                        )
                    )
                if db.get("StorageEncrypted") is False:
                    result.findings.append(
                        Finding(
                            Severity.HIGH,
                            "RDS_UNENCRYPTED_INSTANCE",
                            "RDS",
                            region,
                            dbid,
                            "Unencrypted RDS instance",
                            "Storage encryption is disabled.",
                            "Use encrypted RDS storage.",
                        )
                    )
                retention = int(db.get("BackupRetentionPeriod", 0))
                if retention == 0:
                    result.findings.append(
                        Finding(
                            Severity.HIGH if critical else Severity.MEDIUM,
                            "RDS_BACKUPS_DISABLED",
                            "RDS",
                            region,
                            dbid,
                            "Automated backups disabled",
                            "Backup retention period is 0 days.",
                            "Enable automated backups.",
                        )
                    )
                elif retention < 7:
                    result.findings.append(
                        Finding(
                            Severity.LOW,
                            "RDS_BACKUP_RETENTION_LOW",
                            "RDS",
                            region,
                            dbid,
                            "Backup retention shorter than seven days",
                            f"Backup retention is {retention} days.",
                            "Set backup retention to at least seven days where practical.",
                        )
                    )
                if db.get("DeletionProtection") is False:
                    result.findings.append(
                        Finding(
                            Severity.HIGH if critical else Severity.MEDIUM,
                            "RDS_DELETION_PROTECTION_DISABLED",
                            "RDS",
                            region,
                            dbid,
                            "RDS deletion protection disabled",
                            "RDS instance can be deleted without deletion protection.",
                            "Enable deletion protection where accidental deletion would be risky.",
                        )
                    )
    except (ClientError, BotoCoreError, KeyError, TypeError, ValueError) as exc:
        return CheckResult(errors=[ScanError("RDS", region, f"RDS scan skipped: {exc}")])
    return result


def _is_critical(
    rds: ReadOnlyAwsClient,
    db: dict[str, object],
    critical_resource_tags: dict[str, tuple[str, ...]],
) -> bool:
    arn = db.get("DBInstanceArn")
    if not arn or not critical_resource_tags:
        return False
    try:
        tags = rds.call("list_tags_for_resource", ResourceName=arn).get("TagList", [])
    except (ClientError, BotoCoreError, KeyError, TypeError):
        return False
    configured = {
        key.lower(): {value.lower() for value in values}
        for key, values in critical_resource_tags.items()
    }
    for tag in tags:
        if not isinstance(tag, dict):
            continue
        key = str(tag.get("Key", "")).lower()
        value = str(tag.get("Value", "")).lower()
        if value in configured.get(key, set()):
            return True
    return False
