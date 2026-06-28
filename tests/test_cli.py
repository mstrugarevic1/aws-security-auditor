from __future__ import annotations

from typer.testing import CliRunner

from aws_security_auditor.cli import app
from aws_security_auditor.models import Finding, ScanReport, ScanSummary, Severity


def test_fail_on_exits_nonzero(monkeypatch) -> None:
    report = ScanReport(
        "123",
        "arn",
        None,
        None,
        ["us-east-1"],
        [Finding(Severity.HIGH, "H", "EC2", "us-east-1", "sg-1", "High", "", "")],
        [],
        ScanSummary(1, 1, 1, 0, 0.1),
    )
    monkeypatch.setattr("aws_security_auditor.cli.run_scan", lambda _config: report)

    result = CliRunner().invoke(app, ["scan", "--fail-on", "HIGH", "--no-color"])

    assert result.exit_code == 1
