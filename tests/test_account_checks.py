from __future__ import annotations

from botocore.exceptions import ClientError

from aws_security_auditor.checks.account import (
    scan_cloudtrail,
    scan_config,
    scan_guardduty,
    scan_securityhub,
)


class NoCloudTrail:
    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        if operation == "describe_trails":
            return {"trailList": []}
        raise AssertionError(operation)


class NoConfig:
    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        if operation == "describe_configuration_recorders":
            return {"ConfigurationRecorders": []}
        raise AssertionError(operation)


class NoGuardDuty:
    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        if operation == "list_detectors":
            return {"DetectorIds": []}
        raise AssertionError(operation)


class NoSecurityHub:
    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        raise ClientError({"Error": {"Code": "ResourceNotFoundException"}}, operation)


def test_account_security_service_findings() -> None:
    findings = (
        scan_cloudtrail(NoCloudTrail(), "us-east-1").findings
        + scan_config(NoConfig(), "us-east-1").findings
        + scan_guardduty(NoGuardDuty(), "us-east-1").findings
        + scan_securityhub(NoSecurityHub(), "us-east-1").findings
    )
    assert {
        "CLOUDTRAIL_NO_TRAILS",
        "CONFIG_NO_RECORDER",
        "GUARDDUTY_DISABLED",
        "SECURITYHUB_DISABLED",
    } <= {finding.check_id for finding in findings}
