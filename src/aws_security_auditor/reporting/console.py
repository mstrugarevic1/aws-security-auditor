from __future__ import annotations

from tabulate import tabulate

from aws_security_auditor.models import ScanReport, Severity
from aws_security_auditor.reporting.regions import region_label


def render_console(report: ScanReport, no_color: bool = False) -> None:
    del no_color
    print(f"Account: {report.account_id}")
    print(f"ARN: {report.arn}")
    if report.profile:
        print(f"Profile: {report.profile}")
    if report.assumed_role:
        print(f"Assumed role: {report.assumed_role}")
    print(f"Regions scanned: {len(report.regions)}")

    print(
        tabulate(
            [
                [f.severity.value, region_label(f.region), f.service, f.resource_id, f.title]
                for f in report.findings
            ],
            headers=["Severity", "Region", "Service", "Resource", "Finding"],
            tablefmt="github",
        )
    )

    counts = {s: sum(1 for f in report.findings if f.severity == s) for s in Severity}
    print(f"Scanned regions: {report.summary.scanned_regions}")
    print(f"Checks executed: {report.summary.checks_executed}")
    print(f"Resources inspected: {report.summary.resources_inspected}")
    print(f"HIGH: {counts[Severity.HIGH]}")
    print(f"MEDIUM: {counts[Severity.MEDIUM]}")
    print(f"LOW: {counts[Severity.LOW]}")
    print(f"Errors: {report.summary.errors}")
    print(f"Duration: {report.summary.duration_seconds}s")
    if report.errors:
        print("Warnings:")
        for error in report.errors:
            print(f"{error.service} {region_label(error.region)}: {error.message}")
