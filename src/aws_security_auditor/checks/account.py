from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from aws_security_auditor.checks.base import CheckResult
from aws_security_auditor.models import Finding, ScanError, Severity
from aws_security_auditor.readonly_client import ReadOnlyAwsClient


def scan_cloudtrail(cloudtrail: ReadOnlyAwsClient, region: str) -> CheckResult:
    result = CheckResult(checks=3)
    try:
        trails = cloudtrail.call("describe_trails", includeShadowTrails=True).get("trailList", [])
        result.resources += len(trails)
        if not trails:
            result.findings.append(
                _finding(
                    Severity.HIGH,
                    "CLOUDTRAIL_NO_TRAILS",
                    "CloudTrail",
                    region,
                    "account",
                    "No CloudTrail trails found",
                    "Create an organization or multi-region trail for API activity auditing.",
                )
            )
            return result
        if not any(trail.get("IsMultiRegionTrail") for trail in trails):
            result.findings.append(
                _finding(
                    Severity.MEDIUM,
                    "CLOUDTRAIL_NO_MULTI_REGION_TRAIL",
                    "CloudTrail",
                    region,
                    "account",
                    "No multi-region CloudTrail trail found",
                    "Use a multi-region trail unless there is a deliberate scoped design.",
                )
            )
        for trail in trails:
            home_region = trail.get("HomeRegion")
            if home_region and home_region != region:
                continue
            name = trail.get("Name")
            if not name:
                continue
            resource_id = str(trail.get("TrailARN") or name)
            status = cloudtrail.call("get_trail_status", Name=name)
            if status.get("IsLogging") is not True:
                result.findings.append(
                    _finding(
                        Severity.HIGH,
                        "CLOUDTRAIL_TRAIL_NOT_LOGGING",
                        "CloudTrail",
                        region,
                        resource_id,
                        "CloudTrail trail is not logging",
                        "Enable logging for the trail.",
                    )
                )
                continue
            if trail.get("LogFileValidationEnabled") is not True:
                result.findings.append(
                    _finding(
                        Severity.MEDIUM,
                        "CLOUDTRAIL_LOG_VALIDATION_DISABLED",
                        "CloudTrail",
                        region,
                        resource_id,
                        "CloudTrail log-file validation is disabled",
                        "Enable CloudTrail log-file validation to detect modified "
                        "or deleted log files.",
                    )
                )
            if not trail.get("KmsKeyId"):
                result.findings.append(
                    _finding(
                        Severity.MEDIUM,
                        "CLOUDTRAIL_LOGS_NOT_KMS_ENCRYPTED",
                        "CloudTrail",
                        region,
                        resource_id,
                        "CloudTrail logs are not encrypted with a customer-managed KMS key",
                        "Configure the trail to encrypt log and digest files with "
                        "an approved KMS key.",
                    )
                )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(
            errors=[ScanError("CloudTrail", region, f"CloudTrail scan skipped: {exc}")]
        )
    return result


def scan_config(config: ReadOnlyAwsClient, region: str) -> CheckResult:
    result = CheckResult(checks=1)
    try:
        recorders = config.call("describe_configuration_recorders").get(
            "ConfigurationRecorders", []
        )
        result.resources += len(recorders)
        if not recorders:
            result.findings.append(
                _finding(
                    Severity.MEDIUM,
                    "CONFIG_NO_RECORDER",
                    "Config",
                    region,
                    "account",
                    "AWS Config recorder is not configured",
                    "Enable AWS Config for continuous configuration history and compliance checks.",
                )
            )
            return result
        statuses = config.call("describe_configuration_recorder_status").get(
            "ConfigurationRecordersStatus", []
        )
        if not any(status.get("recording") is True for status in statuses):
            result.findings.append(
                _finding(
                    Severity.MEDIUM,
                    "CONFIG_RECORDER_NOT_RECORDING",
                    "Config",
                    region,
                    "account",
                    "AWS Config recorder is not recording",
                    "Start the AWS Config recorder.",
                )
            )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(errors=[ScanError("Config", region, f"Config scan skipped: {exc}")])
    return result


def scan_guardduty(guardduty: ReadOnlyAwsClient, region: str) -> CheckResult:
    result = CheckResult(checks=1)
    try:
        detectors = guardduty.call("list_detectors").get("DetectorIds", [])
        result.resources += len(detectors)
        if not detectors:
            result.findings.append(
                _finding(
                    Severity.MEDIUM,
                    "GUARDDUTY_DISABLED",
                    "GuardDuty",
                    region,
                    "account",
                    "GuardDuty is not enabled",
                    "Enable GuardDuty for threat detection where supported.",
                )
            )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(
            errors=[ScanError("GuardDuty", region, f"GuardDuty scan skipped: {exc}")]
        )
    return result


def scan_securityhub(securityhub: ReadOnlyAwsClient, region: str) -> CheckResult:
    result = CheckResult(checks=1)
    try:
        securityhub.call("describe_hub")
        result.resources += 1
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code in {"InvalidAccessException", "ResourceNotFoundException"}:
            result.findings.append(
                _finding(
                    Severity.MEDIUM,
                    "SECURITYHUB_DISABLED",
                    "SecurityHub",
                    region,
                    "account",
                    "Security Hub is not enabled",
                    "Enable Security Hub for centralized security posture management.",
                )
            )
            return result
        return CheckResult(
            errors=[ScanError("SecurityHub", region, f"Security Hub scan skipped: {exc}")]
        )
    except (BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(
            errors=[ScanError("SecurityHub", region, f"Security Hub scan skipped: {exc}")]
        )
    return result


def _finding(
    severity: Severity,
    check_id: str,
    service: str,
    region: str,
    resource_id: str,
    title: str,
    recommendation: str,
) -> Finding:
    return Finding(severity, check_id, service, region, resource_id, title, title, recommendation)
