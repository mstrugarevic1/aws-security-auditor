from __future__ import annotations

from aws_security_auditor.models import ScanReport, Severity
from aws_security_auditor.reporting.regions import region_label


def render_markdown(report: ScanReport) -> str:
    lines = [
        "# AWS Security Auditor Report",
        "",
        f"- Account: `{report.account_id}`",
        f"- ARN: `{report.arn}`",
        f"- Regions scanned: {len(report.regions)}",
        "",
        "| Severity | Region | Service | Resource | Finding |",
        "| --- | --- | --- | --- | --- |",
    ]
    for f in report.findings:
        lines.append(
            f"| {f.severity.value} | {region_label(f.region)} | {f.service} | "
            f"{f.resource_id} | {f.title} |"
        )
    counts = {s: sum(1 for f in report.findings if f.severity == s) for s in Severity}
    lines.extend(
        [
            "",
            "## Summary",
            "",
            f"- Scanned regions: {report.summary.scanned_regions}",
            f"- Checks executed: {report.summary.checks_executed}",
            f"- Resources inspected: {report.summary.resources_inspected}",
            f"- HIGH: {counts[Severity.HIGH]}",
            f"- MEDIUM: {counts[Severity.MEDIUM]}",
            f"- LOW: {counts[Severity.LOW]}",
            f"- Suppressed: {report.summary.suppressed}",
            f"- Errors: {report.summary.errors}",
            f"- Duration: {report.summary.duration_seconds}s",
        ]
    )
    if report.suppressed_findings:
        lines.extend(
            [
                "",
                "## Suppressed findings",
                "",
                "| Check ID | Region | Resource | Reason | Expires |",
                "| --- | --- | --- | --- | --- |",
            ]
        )
        for suppressed in report.suppressed_findings:
            finding = suppressed.finding
            lines.append(
                f"| {finding.check_id} | {region_label(finding.region)} | "
                f"{finding.resource_id} | {suppressed.reason} | "
                f"{suppressed.expires.isoformat()} |"
            )
    return "\n".join(lines) + "\n"
