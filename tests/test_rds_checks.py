from __future__ import annotations

from botocore.exceptions import ClientError

from aws_security_auditor.checks.rds import scan_rds


class FakeRds:
    def __init__(
        self,
        db: dict[str, object] | None = None,
        tags: list[dict[str, str]] | None = None,
        fail_tags: bool = False,
    ):
        self.db = db
        self.tags = tags or [{"Key": "Criticality", "Value": "tier1"}]
        self.fail_tags = fail_tags

    def call(self, operation: str, **kwargs: object):
        if operation == "list_tags_for_resource":
            if self.fail_tags:
                raise ClientError({"Error": {"Code": "Denied"}}, operation)
            return {"TagList": self.tags}
        raise AssertionError(operation)

    def paginate(self, operation: str, **kwargs: object):
        return iter(
            [
                {
                    "DBInstances": [
                        self.db
                        or {
                            "DBInstanceIdentifier": "db-1",
                            "PubliclyAccessible": True,
                            "StorageEncrypted": False,
                            "BackupRetentionPeriod": 0,
                            "DeletionProtection": False,
                            "MultiAZ": True,
                            "Engine": "postgres",
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


def test_rds_production_multiaz() -> None:
    base = {
        "DBInstanceIdentifier": "prod",
        "BackupRetentionPeriod": 7,
        "DeletionProtection": True,
        "StorageEncrypted": True,
        "PubliclyAccessible": False,
        "MultiAZ": False,
        "Engine": "postgres",
        "DBInstanceArn": "arn:aws:rds:us-east-1:123:db:prod",
    }

    prod = scan_rds(  # type: ignore[arg-type]
        FakeRds(base, [{"Key": "Environment", "Value": "PrOd"}]),
        "us-east-1",
        {"Environment": ("prod",)},
    )
    compliant = scan_rds(  # type: ignore[arg-type]
        FakeRds({**base, "MultiAZ": True}),
        "us-east-1",
        {"Criticality": ("tier1",)},
    )
    non_prod = scan_rds(  # type: ignore[arg-type]
        FakeRds(base, [{"Key": "Environment", "Value": "dev"}]),
        "us-east-1",
        {"Environment": ("prod",)},
    )

    assert {f.check_id for f in prod.findings} == {"RDS_PRODUCTION_NOT_MULTI_AZ"}
    assert compliant.findings == []
    assert non_prod.findings == []


def test_rds_multiaz_skips_aurora_custom_missing_tags_and_tag_failure() -> None:
    base = {
        "DBInstanceIdentifier": "db",
        "BackupRetentionPeriod": 7,
        "DeletionProtection": True,
        "StorageEncrypted": True,
        "PubliclyAccessible": False,
        "MultiAZ": False,
        "DBInstanceArn": "arn:aws:rds:us-east-1:123:db:db",
    }

    for engine in ("aurora-postgresql", "custom-oracle-ee"):
        result = scan_rds(  # type: ignore[arg-type]
            FakeRds({**base, "Engine": engine}),
            "us-east-1",
            {"Criticality": ("tier1",)},
        )
        assert result.findings == []

    assert (
        scan_rds(  # type: ignore[arg-type]
            FakeRds({**base, "Engine": "postgres", "DBInstanceArn": None}),
            "us-east-1",
            {"Criticality": ("tier1",)},
        ).findings
        == []
    )
    assert (
        scan_rds(  # type: ignore[arg-type]
            FakeRds({**base, "Engine": "postgres"}, fail_tags=True),
            "us-east-1",
            {"Criticality": ("tier1",)},
        ).findings
        == []
    )
