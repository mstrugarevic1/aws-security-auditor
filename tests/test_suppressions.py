from __future__ import annotations

from datetime import UTC, datetime, timedelta

from aws_security_auditor.config import Suppression
from aws_security_auditor.models import Finding, Severity
from aws_security_auditor.suppressions import apply_suppressions


def _finding(check_id: str = "H", resource_id: str = "r", region: str = "us-east-1") -> Finding:
    return Finding(Severity.HIGH, check_id, "EC2", region, resource_id, "High", "", "")


def _suppression(
    check_id: str = "H",
    resource_id: str = "r",
    *,
    days: int = 1,
    region: str | None = None,
    account_id: str | None = None,
) -> Suppression:
    return Suppression(
        check_id,
        resource_id,
        "accepted",
        datetime.now(UTC).date() + timedelta(days=days),
        region,
        account_id,
    )


def test_suppression_matching_rules(caplog) -> None:
    finding = _finding()

    active, suppressed = apply_suppressions([finding], (_suppression(days=0),), "123")
    assert active == []
    assert suppressed[0].finding == finding

    assert apply_suppressions([finding], (_suppression("X"),), "123")[0] == [finding]
    assert apply_suppressions([finding], (_suppression(resource_id="x"),), "123")[0] == [finding]
    assert apply_suppressions([finding], (_suppression(region="us-east-1"),), "123")[0] == []
    assert apply_suppressions([finding], (_suppression(region="eu-west-1"),), "123")[0] == [
        finding
    ]
    assert apply_suppressions([finding], (_suppression(account_id="123"),), "123")[0] == []
    assert apply_suppressions([finding], (_suppression(account_id="999"),), "123")[0] == [
        finding
    ]

    expired = _suppression(days=-1)
    active, suppressed = apply_suppressions([finding], (expired,), "123")
    assert active == [finding]
    assert suppressed == []
    assert "expired suppression ignored" in caplog.text


def test_one_suppression_matches_duplicate_findings() -> None:
    findings = [_finding(), _finding()]

    active, suppressed = apply_suppressions(findings, (_suppression(),), "123")

    assert active == []
    assert len(suppressed) == 2
