from __future__ import annotations

from datetime import date

from botocore.exceptions import ClientError, ProfileNotFound
from typer.testing import CliRunner

from aws_security_auditor.cli import app
from aws_security_auditor.config import ScanConfig
from aws_security_auditor.models import (
    Finding,
    ScanReport,
    ScanSummary,
    Severity,
    SuppressedFinding,
)


def _report(findings: list[Finding]) -> ScanReport:
    return ScanReport(
        "123",
        "arn",
        None,
        None,
        ["us-east-1"],
        findings,
        [],
        ScanSummary(1, 1, 1, 0, 0.1),
    )


def test_fail_on_exits_nonzero(monkeypatch) -> None:
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda _config: _report(
            [Finding(Severity.HIGH, "H", "EC2", "us-east-1", "sg-1", "High", "", "")]
        ),
    )

    result = CliRunner().invoke(app, ["scan", "--fail-on", "HIGH", "--no-color"])

    assert result.exit_code == 1


def test_notify_on_sends_slack_when_threshold_matches(monkeypatch) -> None:
    calls: list[tuple[str, Severity]] = []
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda _config: _report(
            [Finding(Severity.HIGH, "H", "EC2", "us-east-1", "sg-1", "High", "", "")]
        ),
    )
    monkeypatch.setattr(
        "aws_security_auditor.cli.notify_slack",
        lambda report, webhook_url, threshold: calls.append((webhook_url, threshold)),
    )

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--notify-on",
            "HIGH",
            "--slack-webhook-url",
            "https://hooks.slack.test/example",
            "--no-color",
        ],
    )

    assert result.exit_code == 0
    assert calls == [("https://hooks.slack.test/example", Severity.HIGH)]


def test_notify_on_uses_env_webhook(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setenv("AWS_SECURITY_AUDITOR_SLACK_WEBHOOK_URL", "https://hooks.slack.test/env")
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda _config: _report(
            [Finding(Severity.MEDIUM, "M", "S3", "global", "bucket", "Medium", "", "")]
        ),
    )
    monkeypatch.setattr(
        "aws_security_auditor.cli.notify_slack",
        lambda report, webhook_url, threshold: calls.append(webhook_url),
    )

    result = CliRunner().invoke(app, ["scan", "--notify-on", "MEDIUM", "--no-color"])

    assert result.exit_code == 0
    assert calls == ["https://hooks.slack.test/env"]


def test_notify_on_skips_when_threshold_does_not_match(monkeypatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda _config: _report(
            [Finding(Severity.LOW, "L", "Tags", "us-east-1", "i-1", "Low", "", "")]
        ),
    )
    monkeypatch.setattr(
        "aws_security_auditor.cli.notify_slack",
        lambda report, webhook_url, threshold: calls.append(webhook_url),
    )

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--notify-on",
            "HIGH",
            "--slack-webhook-url",
            "https://hooks.slack.test/example",
            "--no-color",
        ],
    )

    assert result.exit_code == 0
    assert calls == []


def test_slack_failure_does_not_fail_scan(monkeypatch) -> None:
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda _config: _report(
            [Finding(Severity.HIGH, "H", "EC2", "us-east-1", "sg-1", "High", "", "")]
        ),
    )

    def fail_notify(*_args: object) -> None:
        raise RuntimeError("boom")

    monkeypatch.setattr("aws_security_auditor.cli.notify_slack", fail_notify)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--notify-on",
            "HIGH",
            "--slack-webhook-url",
            "https://hooks.slack.test/example",
            "--no-color",
        ],
    )

    assert result.exit_code == 0
    assert "Slack notification failed" in result.stderr


def test_suppressed_high_does_not_fail_or_notify(monkeypatch) -> None:
    calls: list[str] = []
    finding = Finding(Severity.HIGH, "H", "EC2", "us-east-1", "sg-1", "High", "", "")
    report = ScanReport(
        "123",
        "arn",
        None,
        None,
        ["us-east-1"],
        [],
        [],
        ScanSummary(1, 1, 1, 0, 0.1, suppressed=1),
        [SuppressedFinding(finding, "accepted", date(2099, 1, 1))],
    )
    monkeypatch.setattr("aws_security_auditor.cli.run_scan", lambda _config: report)
    monkeypatch.setattr(
        "aws_security_auditor.cli.notify_slack",
        lambda report, webhook_url, threshold: calls.append(webhook_url),
    )

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--fail-on",
            "HIGH",
            "--notify-on",
            "HIGH",
            "--slack-webhook-url",
            "https://hooks.slack.test/example",
            "--no-color",
        ],
    )

    assert result.exit_code == 0
    assert calls == []


def test_table_output_file_gets_table_text(monkeypatch, tmp_path) -> None:
    output_file = tmp_path / "report.txt"
    monkeypatch.setattr("aws_security_auditor.cli.run_scan", lambda _config: _report([]))

    result = CliRunner().invoke(
        app,
        ["scan", "--output", "table", "--output-file", str(output_file), "--no-color"],
    )

    assert result.exit_code == 0
    assert "Account: 123" in output_file.read_text(encoding="utf-8")
    assert "# AWS Security Auditor Report" not in output_file.read_text(encoding="utf-8")


def test_output_formats(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("aws_security_auditor.cli.run_scan", lambda _config: _report([]))

    json_result = CliRunner().invoke(app, ["scan", "--output", "json", "--no-color"])
    markdown_result = CliRunner().invoke(app, ["scan", "--output", "markdown", "--no-color"])
    csv_result = CliRunner().invoke(app, ["scan", "--output", "csv", "--no-color"])

    assert json_result.exit_code == 0
    assert '"account_id": "123"' in json_result.stdout
    assert markdown_result.exit_code == 0
    assert "# AWS Security Auditor Report" in markdown_result.stdout
    assert csv_result.exit_code == 0
    assert "severity,region,service,resource_id,check_id" in csv_result.stdout


def test_config_file_precedence(monkeypatch, tmp_path) -> None:
    seen: list[ScanConfig] = []
    config_file = tmp_path / "auditor.toml"
    config_file.write_text(
        """
regions = ["eu-west-1"]
services = ["s3"]
output = "json"
severity = "LOW"
snapshot_age_days = 30
access_key_age_days = 45
max_workers = 2
required_tags = ["Owner"]
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda config: seen.append(config) or _report([]),
    )

    result = CliRunner().invoke(app, ["scan", "--config", str(config_file), "--no-color"])

    assert result.exit_code == 0
    assert seen[0].regions == ("eu-west-1",)
    assert seen[0].services == ("s3",)
    assert seen[0].output == "json"
    assert seen[0].severity == "LOW"
    assert seen[0].snapshot_age_days == 30
    assert seen[0].access_key_age_days == 45
    assert seen[0].max_workers == 2
    assert seen[0].required_tags == ("Owner",)


def test_cli_overrides_config_file(monkeypatch, tmp_path) -> None:
    seen: list[ScanConfig] = []
    config_file = tmp_path / "auditor.toml"
    config_file.write_text(
        """
regions = ["eu-west-1"]
services = ["s3"]
output = "json"
required_tags = ["Owner"]
""".strip(),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda config: seen.append(config) or _report([]),
    )

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--config",
            str(config_file),
            "--regions",
            "us-east-1",
            "--services",
            "ec2",
            "--output",
            "csv",
            "--required-tags",
            "Service",
            "--no-color",
        ],
    )

    assert result.exit_code == 0
    assert seen[0].regions == ("us-east-1",)
    assert seen[0].services == ("ec2",)
    assert seen[0].output == "csv"
    assert seen[0].required_tags == ("Service",)


def test_version_and_list_commands() -> None:
    runner = CliRunner()

    assert runner.invoke(app, ["--version"]).exit_code == 0
    checks = runner.invoke(app, ["list-checks"])
    services = runner.invoke(app, ["list-services"])

    assert checks.exit_code == 0
    assert "EC2_SG_OPEN_SSH" in checks.stdout
    assert services.exit_code == 0
    assert "ec2" in services.stdout


def test_operational_errors_exit_2(monkeypatch) -> None:
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda _config: (_ for _ in ()).throw(ProfileNotFound(profile="missing")),
    )

    profile_result = CliRunner().invoke(app, ["scan", "--profile", "missing", "--no-color"])

    assert profile_result.exit_code == 2
    assert "missing" in profile_result.stderr


def test_invalid_region_exits_2(monkeypatch) -> None:
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda _config: (_ for _ in ()).throw(ValueError("Invalid region selection")),
    )

    result = CliRunner().invoke(app, ["scan", "--regions", "antarctica-1", "--no-color"])

    assert result.exit_code == 2
    assert "Invalid region selection" in result.stderr


def test_aws_api_errors_exit_2(monkeypatch) -> None:
    monkeypatch.setattr(
        "aws_security_auditor.cli.run_scan",
        lambda _config: (_ for _ in ()).throw(
            ClientError({"Error": {"Code": "Denied", "Message": "nope"}}, "DescribeRegions")
        ),
    )

    result = CliRunner().invoke(app, ["scan", "--no-color"])

    assert result.exit_code == 2
    assert "Denied" in result.stderr
