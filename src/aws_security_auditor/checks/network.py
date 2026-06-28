from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from aws_security_auditor.checks.base import CheckResult
from aws_security_auditor.models import Finding, ScanError, Severity
from aws_security_auditor.readonly_client import ReadOnlyAwsClient


def scan_elbv2(elbv2: ReadOnlyAwsClient, region: str) -> CheckResult:
    result = CheckResult(checks=1)
    try:
        for page in elbv2.paginate("describe_load_balancers"):
            load_balancers = page.get("LoadBalancers", [])
            result.resources += len(load_balancers)
            for lb in load_balancers:
                if lb.get("Scheme") == "internet-facing":
                    result.findings.append(
                        _finding(
                            Severity.MEDIUM,
                            "ELBV2_INTERNET_FACING",
                            "ELBv2",
                            region,
                            lb.get("LoadBalancerArn", lb.get("LoadBalancerName", "unknown")),
                            "Internet-facing load balancer",
                            "Review whether this load balancer should be public.",
                        )
                    )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(errors=[ScanError("ELBv2", region, f"ELBv2 scan skipped: {exc}")])
    return result


def scan_ecr(ecr: ReadOnlyAwsClient, region: str) -> CheckResult:
    result = CheckResult(checks=1)
    try:
        for page in ecr.paginate("describe_repositories"):
            repos = page.get("repositories", [])
            result.resources += len(repos)
            for repo in repos:
                scan_on_push = repo.get("imageScanningConfiguration", {}).get("scanOnPush")
                if scan_on_push is not True:
                    result.findings.append(
                        _finding(
                            Severity.LOW,
                            "ECR_SCAN_ON_PUSH_DISABLED",
                            "ECR",
                            region,
                            repo.get("repositoryName", "unknown"),
                            "ECR scan on push is disabled",
                            "Enable image scanning or confirm enhanced scanning is "
                            "handled elsewhere.",
                        )
                    )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(errors=[ScanError("ECR", region, f"ECR scan skipped: {exc}")])
    return result


def scan_kms(kms: ReadOnlyAwsClient, region: str) -> CheckResult:
    result = CheckResult(checks=1)
    try:
        for page in kms.paginate("list_keys"):
            keys = page.get("Keys", [])
            result.resources += len(keys)
            for key in keys:
                key_id = key.get("KeyId", "unknown")
                try:
                    rotation = kms.call("get_key_rotation_status", KeyId=key_id)
                    if rotation.get("KeyRotationEnabled") is not True:
                        result.findings.append(
                            _finding(
                                Severity.LOW,
                                "KMS_KEY_ROTATION_DISABLED",
                                "KMS",
                                region,
                                key_id,
                                "KMS key rotation is disabled",
                                "Enable automatic rotation for eligible customer-managed KMS keys.",
                            )
                        )
                except ClientError as exc:
                    code = exc.response.get("Error", {}).get("Code")
                    if code not in {"UnsupportedOperationException", "NotFoundException"}:
                        raise
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(errors=[ScanError("KMS", region, f"KMS scan skipped: {exc}")])
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
