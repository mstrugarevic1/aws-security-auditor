from __future__ import annotations

from aws_security_auditor.checks.rds import scan_rds


class FakeRds:
    def call(self, operation: str, **kwargs: object):
        if operation == "list_tags_for_resource":
            return {"TagList": [{"Key": "Criticality", "Value": "tier1"}]}
        raise AssertionError(operation)

    def paginate(self, operation: str, **kwargs: object):
        return iter(
            [
                {
                    "DBInstances": [
                        {
                            "DBInstanceIdentifier": "db-1",
                            "PubliclyAccessible": True,
                            "StorageEncrypted": False,
                            "BackupRetentionPeriod": 0,
                            "DeletionProtection": False,
                            "DBInstanceArn": "arn:aws:rds:us-east-1:123:db:db-1",
                        }
                    ]
                }
            ]
        )


def test_rds_findings() -> None:
    result = scan_rds(FakeRds(), "us-east-1")  # type: ignore[arg-type]
    assert {f.check_id for f in result.findings} == {
        "RDS_PUBLIC_INSTANCE",
        "RDS_UNENCRYPTED_INSTANCE",
        "RDS_BACKUPS_DISABLED",
        "RDS_DELETION_PROTECTION_DISABLED",
    }


def test_rds_critical_tags_raise_resilience_severity() -> None:
    result = scan_rds(  # type: ignore[arg-type]
        FakeRds(),
        "us-east-1",
        {"Criticality": ("tier1",)},
    )
    severities = {f.check_id: f.severity for f in result.findings}
    assert severities["RDS_BACKUPS_DISABLED"].value == "HIGH"
    assert severities["RDS_DELETION_PROTECTION_DISABLED"].value == "HIGH"
