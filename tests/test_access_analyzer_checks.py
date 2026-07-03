from __future__ import annotations

from botocore.exceptions import ClientError

from aws_security_auditor.checks.access_analyzer import scan_access_analyzer


class FakeAccessAnalyzer:
    def __init__(self, analyzers: list[dict[str, object]], fail: bool = False):
        self.analyzers = analyzers
        self.fail = fail

    def paginate(self, operation: str, **kwargs: object):
        assert operation == "list_analyzers"
        if self.fail:
            raise ClientError({"Error": {"Code": "Denied"}}, operation)
        midpoint = len(self.analyzers) // 2
        return iter(
            [
                {"analyzers": self.analyzers[:midpoint]},
                {"analyzers": self.analyzers[midpoint:]},
            ]
        )


def test_access_analyzer_active_external_analyzers() -> None:
    assert (
        scan_access_analyzer(  # type: ignore[arg-type]
            FakeAccessAnalyzer([{"name": "account", "type": "ACCOUNT", "status": "ACTIVE"}]),
            "us-east-1",
        ).findings
        == []
    )
    assert (
        scan_access_analyzer(  # type: ignore[arg-type]
            FakeAccessAnalyzer([{"name": "org", "type": "ORGANIZATION", "status": "ACTIVE"}]),
            "us-east-1",
        ).findings
        == []
    )


def test_access_analyzer_missing_external_access() -> None:
    result = scan_access_analyzer(  # type: ignore[arg-type]
        FakeAccessAnalyzer(
            [
                {"name": "unused", "type": "ACCOUNT_UNUSED_ACCESS", "status": "ACTIVE"},
                {"name": "disabled", "type": "ACCOUNT", "status": "DISABLED"},
                {"name": "failed", "type": "ORGANIZATION", "status": "FAILED"},
            ]
        ),
        "us-east-1",
    )

    assert [(f.check_id, f.service, f.resource_id) for f in result.findings] == [
        ("ACCESS_ANALYZER_EXTERNAL_ACCESS_DISABLED", "AccessAnalyzer", "account")
    ]
    assert "disabled=DISABLED" in result.findings[0].description
    assert "failed=FAILED" in result.findings[0].description


def test_access_analyzer_empty_and_api_failure() -> None:
    empty = scan_access_analyzer(FakeAccessAnalyzer([]), "us-east-1")  # type: ignore[arg-type]
    failed = scan_access_analyzer(FakeAccessAnalyzer([], fail=True), "us-east-1")  # type: ignore[arg-type]

    assert empty.findings
    assert failed.errors
