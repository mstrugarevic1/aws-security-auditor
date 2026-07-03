from __future__ import annotations

from botocore.exceptions import ClientError

from aws_security_auditor.checks.secretsmanager import scan_secretsmanager


class FakeSecretsManager:
    def __init__(self, fail: bool = False):
        self.fail = fail
        self.operations: list[str] = []

    def paginate(self, operation: str, **kwargs: object):
        self.operations.append(operation)
        assert kwargs == {"IncludePlannedDeletion": False}
        if self.fail:
            raise ClientError({"Error": {"Code": "Denied"}}, operation)
        return iter(
            [
                {
                    "SecretList": [
                        {"Name": "rotated", "ARN": "arn:rotated", "RotationEnabled": True},
                        {"Name": "static", "ARN": "arn:static", "RotationEnabled": False},
                    ]
                },
                {
                    "SecretList": [
                        {"Name": "missing", "ARN": "arn:missing"},
                        {"Name": "owned", "ARN": "arn:owned", "OwningService": "rds"},
                    ]
                },
            ]
        )


def test_secretsmanager_rotation() -> None:
    fake = FakeSecretsManager()
    result = scan_secretsmanager(fake, "us-east-1")  # type: ignore[arg-type]

    assert result.resources == 4
    assert {f.resource_id for f in result.findings} == {"arn:static", "arn:missing"}
    assert {f.check_id for f in result.findings} == {"SECRETSMANAGER_ROTATION_DISABLED"}
    assert fake.operations == ["list_secrets"]


def test_secretsmanager_api_failure() -> None:
    result = scan_secretsmanager(FakeSecretsManager(fail=True), "us-east-1")  # type: ignore[arg-type]

    assert result.findings == []
    assert result.errors
