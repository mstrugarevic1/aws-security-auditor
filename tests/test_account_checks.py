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


class CloudTrail:
    def __init__(self, trails: list[dict[str, object]], logging: bool = True, fail: bool = False):
        self.trails = trails
        self.logging = logging
        self.fail = fail

    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        if self.fail:
            raise ClientError({"Error": {"Code": "Denied"}}, operation)
        if operation == "describe_trails":
            return {"trailList": self.trails}
        if operation == "get_trail_status":
            return {"IsLogging": self.logging}
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


def test_cloudtrail_validation_and_kms_checks() -> None:
    result = scan_cloudtrail(
        CloudTrail(
            [
                {
                    "Name": "trail",
                    "TrailARN": "arn:trail",
                    "HomeRegion": "us-east-1",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": False,
                }
            ]
        ),
        "us-east-1",
    )

    assert {
        "CLOUDTRAIL_LOG_VALIDATION_DISABLED",
        "CLOUDTRAIL_LOGS_NOT_KMS_ENCRYPTED",
    } == {f.check_id for f in result.findings}
    assert result.checks == 3


def test_cloudtrail_enabled_controls_and_shadow_trails() -> None:
    result = scan_cloudtrail(
        CloudTrail(
            [
                {
                    "Name": "home",
                    "TrailARN": "arn:home",
                    "HomeRegion": "us-east-1",
                    "IsMultiRegionTrail": True,
                    "LogFileValidationEnabled": True,
                    "KmsKeyId": "key",
                },
                {
                    "Name": "shadow",
                    "TrailARN": "arn:shadow",
                    "HomeRegion": "eu-west-1",
                    "IsMultiRegionTrail": True,
                },
            ]
        ),
        "us-east-1",
    )

    assert result.findings == []


def test_cloudtrail_not_logging_and_api_failure() -> None:
    stopped = scan_cloudtrail(
        CloudTrail([{"Name": "trail", "TrailARN": "arn:trail", "IsMultiRegionTrail": True}], False),
        "us-east-1",
    )
    failed = scan_cloudtrail(CloudTrail([], fail=True), "us-east-1")

    assert {f.check_id for f in stopped.findings} == {"CLOUDTRAIL_TRAIL_NOT_LOGGING"}
    assert failed.errors
