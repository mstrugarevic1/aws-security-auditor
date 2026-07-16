from __future__ import annotations

import logging
import os
from dataclasses import replace
from importlib.metadata import version
from pathlib import Path
from typing import Annotated

import typer
from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound

from aws_security_auditor.config import (
    ALL_SERVICES,
    FileConfig,
    ScanConfig,
    load_config_file,
)
from aws_security_auditor.models import SEVERITY_ORDER, ScanReport, Severity
from aws_security_auditor.notifiers.slack import notify_slack
from aws_security_auditor.reporting.console import render_console
from aws_security_auditor.reporting.csv_report import render_csv
from aws_security_auditor.reporting.json_report import render_json
from aws_security_auditor.reporting.markdown import render_markdown
from aws_security_auditor.scanner import run_scan

app = typer.Typer(help="Read-only AWS security auditor.")
CHECK_IDS = (
    "ACCESS_ANALYZER_EXTERNAL_ACCESS_DISABLED",
    "CLOUDTRAIL_LOG_VALIDATION_DISABLED",
    "CLOUDTRAIL_LOGS_NOT_KMS_ENCRYPTED",
    "CLOUDTRAIL_NO_MULTI_REGION_TRAIL",
    "CLOUDTRAIL_NO_TRAILS",
    "CLOUDTRAIL_TRAIL_NOT_LOGGING",
    "CONFIG_NO_RECORDER",
    "CONFIG_RECORDER_NOT_RECORDING",
    "EBS_DEFAULT_ENCRYPTION_DISABLED",
    "EBS_OLD_SNAPSHOT",
    "EBS_PUBLIC_SNAPSHOT",
    "EBS_UNATTACHED_VOLUME",
    "EBS_UNENCRYPTED_VOLUME",
    "EC2_DEFAULT_SG_PUBLIC_INGRESS",
    "EC2_IMDSV2_NOT_REQUIRED",
    "EC2_PUBLIC_AMI",
    "EC2_PUBLIC_INSTANCE_EXPOSURE",
    "EC2_SG_OPEN_ALL",
    "EC2_SG_OPEN_DB",
    "EC2_SG_OPEN_HTTP",
    "EC2_SG_OPEN_HTTPS",
    "EC2_SG_OPEN_RDP",
    "EC2_SG_OPEN_SSH",
    "EC2_SG_PUBLIC_INGRESS",
    "EC2_UNUSED_EIP",
    "EC2_UNUSED_SECURITY_GROUP",
    "ECR_SCAN_ON_PUSH_DISABLED",
    "ECS_PRIVILEGED_CONTAINER",
    "ECS_SERVICE_PUBLIC_IP_ENABLED",
    "ELBV2_INTERNET_FACING",
    "GUARDDUTY_DISABLED",
    "IAM_DIRECT_INLINE_USER_POLICY",
    "IAM_GROUP_ADMINISTRATOR_ACCESS",
    "IAM_OLD_ACCESS_KEY",
    "IAM_PASSWORD_POLICY_MISSING",
    "IAM_ROLE_ADMINISTRATOR_ACCESS",
    "IAM_ROOT_ACCESS_KEYS_PRESENT",
    "IAM_ROOT_MFA_DISABLED",
    "IAM_UNUSED_ACCESS_KEY",
    "IAM_USER_ADMINISTRATOR_ACCESS",
    "IAM_USER_NO_MFA",
    "IAM_WEAK_PASSWORD_POLICY",
    "KMS_KEY_ROTATION_DISABLED",
    "LAMBDA_PUBLIC_FUNCTION_URL",
    "RDS_BACKUP_RETENTION_LOW",
    "RDS_BACKUPS_DISABLED",
    "RDS_DELETION_PROTECTION_DISABLED",
    "RDS_PRODUCTION_NOT_MULTI_AZ",
    "RDS_PUBLIC_INSTANCE",
    "RDS_UNENCRYPTED_INSTANCE",
    "RESOURCE_MISSING_REQUIRED_TAGS",
    "S3_ACCESS_LOGGING_DISABLED",
    "S3_DEFAULT_ENCRYPTION_MISSING",
    "S3_PUBLIC_ACCESS_BLOCK_DISABLED",
    "S3_PUBLIC_ACL",
    "S3_PUBLIC_POLICY",
    "S3_VERSIONING_DISABLED",
    "SECRETSMANAGER_ROTATION_DISABLED",
    "SECURITYHUB_DISABLED",
    "VPC_FLOW_LOGS_DISABLED",
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(version("aws-security-auditor"))
        raise typer.Exit()


@app.callback()
def main(
    version_: Annotated[
        bool | None,
        typer.Option("--version", callback=_version_callback, help="Show version and exit."),
    ] = None,
) -> None:
    """Read-only AWS security auditor."""


@app.command()
def scan(
    profile: Annotated[str | None, typer.Option(help="AWS profile name.")] = None,
    config_file: Annotated[
        Path | None,
        typer.Option("--config", help="TOML config file for tags and scan tuning."),
    ] = None,
    role_arn: Annotated[str | None, typer.Option(help="Optional role ARN to assume.")] = None,
    external_id: Annotated[str | None, typer.Option(help="External ID for AssumeRole.")] = None,
    regions: Annotated[str | None, typer.Option(help="Comma-separated AWS regions.")] = None,
    exclude_regions: Annotated[
        str | None, typer.Option(help="Comma-separated AWS regions to skip.")
    ] = None,
    services: Annotated[
        str | None, typer.Option(help="Comma-separated services to scan.")
    ] = None,
    output: Annotated[str | None, typer.Option(help="table, json, markdown, or csv.")] = None,
    output_file: Annotated[Path | None, typer.Option(help="Write report to this path.")] = None,
    severity: Annotated[
        str | None, typer.Option(help="Only include findings at this severity or higher.")
    ] = None,
    fail_on: Annotated[
        str | None,
        typer.Option(help="Exit with status 1 when findings include this severity or higher."),
    ] = None,
    no_color: Annotated[bool, typer.Option(help="Disable terminal color.")] = False,
    verbose: Annotated[bool, typer.Option(help="Show skipped regions and warnings.")] = False,
    snapshot_age_days: Annotated[int | None, typer.Option(help="Old snapshot threshold.")] = None,
    access_key_age_days: Annotated[
        int | None, typer.Option(help="Old access key threshold.")
    ] = None,
    required_tags: Annotated[
        str | None, typer.Option(help="Comma-separated required tags.")
    ] = None,
    max_workers: Annotated[
        int | None, typer.Option(help="Maximum regional scan worker threads.")
    ] = None,
    notify_on: Annotated[
        str | None,
        typer.Option(help="Send Slack notification when findings include this severity or higher."),
    ] = None,
    slack_webhook_url: Annotated[
        str | None,
        typer.Option(
            help="Slack webhook URL. Defaults to AWS_SECURITY_AUDITOR_SLACK_WEBHOOK_URL."
        ),
    ] = None,
) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
    )
    file_config = None
    if config_file:
        try:
            file_config = load_config_file(config_file)
        except ValueError as exc:
            raise typer.BadParameter(str(exc), param_hint="--config") from exc
    config = _build_scan_config(
        file_config=file_config,
        profile=profile,
        role_arn=role_arn,
        external_id=external_id,
        regions=regions,
        exclude_regions=exclude_regions,
        services=services,
        output=output,
        output_file=output_file,
        severity=severity,
        fail_on=fail_on,
        no_color=no_color,
        verbose=verbose,
        snapshot_age_days=snapshot_age_days,
        access_key_age_days=access_key_age_days,
        required_tags=required_tags,
        max_workers=max_workers,
    )
    try:
        report = run_scan(config)
    except (BotoCoreError, ClientError, ProfileNotFound, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc
    if config.output == "table":
        text = render_console(report, no_color=config.no_color, verbose=config.verbose)
    elif config.output == "json":
        text = render_json(report)
        typer.echo(text)
    elif config.output == "markdown":
        text = render_markdown(report)
        typer.echo(text)
    elif config.output == "csv":
        text = render_csv(report)
        typer.echo(text)
    else:
        raise typer.BadParameter("output must be table, json, markdown, or csv")

    if output_file:
        output_file.write_text(text, encoding="utf-8")

    if notify_on:
        threshold = Severity(notify_on.upper())
        webhook_url = slack_webhook_url or os.environ.get("AWS_SECURITY_AUDITOR_SLACK_WEBHOOK_URL")
        if webhook_url and _has_findings_at_or_above(report, threshold):
            try:
                notify_slack(report, webhook_url, threshold)
            except Exception as exc:  # noqa: BLE001
                typer.echo(f"warning: Slack notification failed: {exc}", err=True)
        elif not webhook_url:
            typer.echo(
                "warning: Slack notification skipped: webhook URL is not configured",
                err=True,
            )

    if config.fail_on:
        threshold = Severity(config.fail_on.upper())
        if _has_findings_at_or_above(report, threshold):
            raise typer.Exit(1)


@app.command("list-checks")
def list_checks() -> None:
    for check_id in CHECK_IDS:
        typer.echo(check_id)


@app.command("list-services")
def list_services() -> None:
    for service in ALL_SERVICES:
        typer.echo(service)


def _build_scan_config(
    *,
    file_config: FileConfig | None,
    profile: str | None,
    role_arn: str | None,
    external_id: str | None,
    regions: str | None,
    exclude_regions: str | None,
    services: str | None,
    output: str | None,
    output_file: Path | None,
    severity: str | None,
    fail_on: str | None,
    no_color: bool,
    verbose: bool,
    snapshot_age_days: int | None,
    access_key_age_days: int | None,
    required_tags: str | None,
    max_workers: int | None,
) -> ScanConfig:
    config = ScanConfig()
    if file_config is not None:
        config = replace(
            config,
            regions=file_config.regions or config.regions,
            exclude_regions=file_config.exclude_regions or config.exclude_regions,
            services=file_config.services or config.services,
            output=file_config.output or config.output,
            severity=file_config.severity or config.severity,
            fail_on=file_config.fail_on or config.fail_on,
            snapshot_age_days=file_config.snapshot_age_days or config.snapshot_age_days,
            access_key_age_days=file_config.access_key_age_days or config.access_key_age_days,
            required_tags=file_config.required_tags or config.required_tags,
            critical_resource_tags=file_config.critical_resource_tags
            or config.critical_resource_tags,
            suppressions=file_config.suppressions,
            max_workers=file_config.max_workers or config.max_workers,
        )
    return replace(
        config,
        profile=profile or config.profile,
        role_arn=role_arn or config.role_arn,
        external_id=external_id or config.external_id,
        regions=_csv(regions) or config.regions,
        exclude_regions=_csv(exclude_regions) or config.exclude_regions,
        services=_services(services) or config.services,
        output=output or config.output,
        output_file=str(output_file) if output_file else config.output_file,
        severity=severity or config.severity,
        fail_on=fail_on or config.fail_on,
        no_color=no_color,
        verbose=verbose,
        snapshot_age_days=snapshot_age_days or config.snapshot_age_days,
        access_key_age_days=access_key_age_days or config.access_key_age_days,
        required_tags=_csv(required_tags) or config.required_tags,
        max_workers=max_workers or config.max_workers,
    )


def _csv(value: str | None) -> tuple[str, ...]:
    return tuple(item.strip() for item in value.split(",") if item.strip()) if value else ()


def _services(value: str | None) -> tuple[str, ...] | None:
    services = tuple(item.lower() for item in _csv(value))
    unknown = sorted(set(services) - set(ALL_SERVICES))
    if unknown:
        raise typer.BadParameter(f"unknown services: {', '.join(unknown)}")
    return services or None


def _has_findings_at_or_above(report: ScanReport, threshold: Severity) -> bool:
    return any(SEVERITY_ORDER[f.severity] <= SEVERITY_ORDER[threshold] for f in report.findings)
