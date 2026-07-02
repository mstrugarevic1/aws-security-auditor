from __future__ import annotations

from collections.abc import Iterator
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_security_auditor.checks.base import CheckResult
from aws_security_auditor.models import Finding, ScanError, Severity
from aws_security_auditor.readonly_client import ReadOnlyAwsClient


def scan_lambda(lambda_client: ReadOnlyAwsClient, region: str) -> CheckResult:
    result = CheckResult(checks=1)
    try:
        for page in lambda_client.paginate("list_functions"):
            functions = page.get("Functions", [])
            result.resources += len(functions)
            for function in functions:
                try:
                    result.findings.extend(
                        _function_url_findings(lambda_client, region, function)
                    )
                except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
                    name = str(function.get("FunctionName") or "unknown")
                    result.errors.append(
                        ScanError(
                            "Lambda",
                            region,
                            f"Function URL scan skipped for {name}: {exc}",
                        )
                    )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(errors=[ScanError("Lambda", region, f"Lambda scan skipped: {exc}")])
    return result


def _function_url_findings(
    lambda_client: ReadOnlyAwsClient, region: str, function: dict[str, Any]
) -> list[Finding]:
    name = str(function.get("FunctionName") or "unknown")
    resource_id = str(function.get("FunctionArn") or name)
    findings: list[Finding] = []
    for config in _function_url_configs(lambda_client, name):
        if config.get("AuthType") == "NONE":
            findings.append(
                Finding(
                    Severity.HIGH,
                    "LAMBDA_PUBLIC_FUNCTION_URL",
                    "Lambda",
                    region,
                    resource_id,
                    "Lambda Function URL allows unauthenticated public access",
                    f"Function URL {config.get('FunctionUrl', 'unknown')} uses AuthType=NONE.",
                    "Use AWS_IAM authentication or remove the Function URL when "
                    "public access is not required.",
                )
            )
    return findings


def _function_url_configs(
    lambda_client: ReadOnlyAwsClient, function_name: str
) -> Iterator[dict[str, Any]]:
    marker: str | None = None
    for _ in range(100):
        kwargs = {"FunctionName": function_name}
        if marker:
            kwargs["Marker"] = marker
        page = lambda_client.call("list_function_url_configs", **kwargs)
        yield from page.get("FunctionUrlConfigs", [])
        marker = page.get("NextMarker")
        if not marker:
            return
