from __future__ import annotations

from datetime import date

from aws_security_auditor.models import (
    Finding,
    ScanReport,
    ScanSummary,
    Severity,
    SuppressedFinding,
    sort_findings,
)
from aws_security_auditor.reporting.console import render_console
from aws_security_auditor.reporting.csv_report import render_csv
from aws_security_auditor.reporting.json_report import render_json
from aws_security_auditor.reporting.markdown import render_markdown


def _report() -> ScanReport:
    return ScanReport(
        "123",
        "arn",
        None,
        None,
        ["us-east-1"],
        [
            Finding(Severity.LOW, "L", "EC2", "us-east-1", "i-1", "Low", "", ""),
            Finding(Severity.HIGH, "H", "EC2", "us-east-1", "i-2", "High", "", ""),
        ],
        [],
        ScanSummary(1, 1, 2, 0, 0.1),
    )


def test_severity_sorting() -> None:
    assert [f.severity for f in sort_findings(_report().findings)] == [Severity.HIGH, Severity.LOW]


def test_json_output_has_no_ansi() -> None:
    assert "\x1b[" not in render_json(_report())


def test_markdown_output() -> None:
    text = render_markdown(_report())
    assert "| Severity | Region | Service | Resource | Finding |" in text
    assert "us-east-1 (US East (N. Virginia))" in text
    assert "## Summary" in text


def test_csv_output() -> None:
    text = render_csv(_report())
    assert "severity,region,service,resource_id,check_id,title,description,recommendation" in text
    assert "HIGH,us-east-1,EC2,i-2,H,High,," in text


def test_suppressed_findings_in_json_and_markdown_but_not_csv() -> None:
    finding = Finding(Severity.HIGH, "H", "EC2", "us-east-1", "i-2", "High", "", "")
    report = ScanReport(
        "123",
        "arn",
        None,
        None,
        ["us-east-1"],
        [],
        [],
        ScanSummary(1, 1, 2, 0, 0.1, suppressed=1),
        [SuppressedFinding(finding, "accepted", date(2099, 1, 1))],
    )

    assert "suppressed_findings" in render_json(report)
    assert "## Suppressed findings" in render_markdown(report)
    assert "accepted" not in render_csv(report)


def test_console_output_shortens_noisy_identifiers(capsys) -> None:
    report = ScanReport(
        "123",
        "arn",
        None,
        None,
        ["us-east-1"],
        [
            Finding(
                Severity.HIGH,
                "LAMBDA_PUBLIC_FUNCTION_URL",
                "Lambda",
                "us-east-1",
                "arn:aws:lambda:us-east-1:123:function:hello",
                "Public URL",
                "",
                "",
            ),
            Finding(
                Severity.MEDIUM,
                "SECRETSMANAGER_ROTATION_DISABLED",
                "SecretsManager",
                "us-east-1",
                "arn:aws:secretsmanager:us-east-1:123:secret:test-o0bXO6",
                "Rotation disabled",
                "",
                "",
            ),
            Finding(
                Severity.MEDIUM,
                "ELBV2_INTERNET_FACING",
                "ELBv2",
                "us-east-1",
                "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/test/abc",
                "Internet-facing load balancer",
                "",
                "",
            ),
        ],
        [],
        ScanSummary(1, 1, 3, 0, 0.1),
    )

    render_console(report, no_color=True)
    text = capsys.readouterr().out

    assert "function:hello" in text
    assert "secret:test-o0bXO6" in text
    assert "㊙" not in text
    assert "app/test/abc" in text
    assert "us-east-1 (US East" not in text
    assert "SecretsMa" not in text
