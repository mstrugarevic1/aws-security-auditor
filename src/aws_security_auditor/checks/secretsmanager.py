from __future__ import annotations

from botocore.exceptions import BotoCoreError, ClientError

from aws_security_auditor.checks.base import CheckResult
from aws_security_auditor.models import Finding, ScanError, Severity
from aws_security_auditor.readonly_client import ReadOnlyAwsClient


def scan_secretsmanager(secretsmanager: ReadOnlyAwsClient, region: str) -> CheckResult:
    result = CheckResult(checks=1)
    try:
        for page in secretsmanager.paginate("list_secrets", IncludePlannedDeletion=False):
            secrets = page.get("SecretList", [])
            result.resources += len(secrets)
            for secret in secrets:
                if secret.get("OwningService"):
                    continue
                if secret.get("RotationEnabled") is True:
                    continue
                name = str(secret.get("Name") or "unknown")
                resource_id = str(secret.get("ARN") or name)
                result.findings.append(
                    Finding(
                        Severity.MEDIUM,
                        "SECRETSMANAGER_ROTATION_DISABLED",
                        "SecretsManager",
                        region,
                        resource_id,
                        "Secrets Manager secret does not use automatic rotation",
                        f"Secret {name} ({resource_id}) does not use automatic rotation.",
                        "Configure automatic rotation or create a documented "
                        "time-limited suppression when the secret is intentionally static.",
                    )
                )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(
            errors=[ScanError("SecretsManager", region, f"Secrets Manager scan skipped: {exc}")]
        )
    return result
