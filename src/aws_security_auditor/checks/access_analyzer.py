from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from aws_security_auditor.checks.base import CheckResult
from aws_security_auditor.models import Finding, ScanError, Severity
from aws_security_auditor.readonly_client import ReadOnlyAwsClient

EXTERNAL_ANALYZER_TYPES = {"ACCOUNT", "ORGANIZATION"}


def scan_access_analyzer(access_analyzer: ReadOnlyAwsClient, region: str) -> CheckResult:
    result = CheckResult(checks=1)
    try:
        analyzers: list[dict[str, object]] = []
        for page in access_analyzer.paginate("list_analyzers"):
            page_analyzers = page.get("analyzers", [])
            result.resources += len(page_analyzers)
            analyzers.extend(page_analyzers)
        external = [a for a in analyzers if a.get("type") in EXTERNAL_ANALYZER_TYPES]
        if any(a.get("status") == "ACTIVE" for a in external):
            return result
        statuses = ", ".join(
            f"{a.get('name', 'unknown')}={a.get('status', 'unknown')}" for a in external
        )
        description = "No active external-access analyzer exists."
        if statuses:
            description = f"No active external-access analyzer exists. Found: {statuses}."
        result.findings.append(
            Finding(
                Severity.MEDIUM,
                "ACCESS_ANALYZER_EXTERNAL_ACCESS_DISABLED",
                "AccessAnalyzer",
                region,
                "account",
                "IAM Access Analyzer external-access analysis is not enabled",
                description,
                "Enable an account-level or organization-level external-access analyzer.",
            )
        )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(
            errors=[ScanError("AccessAnalyzer", region, f"Access Analyzer scan skipped: {exc}")]
        )
    return result
