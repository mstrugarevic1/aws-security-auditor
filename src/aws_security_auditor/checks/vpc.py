from __future__ import annotations

from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_security_auditor.checks.base import CheckResult
from aws_security_auditor.models import Finding, ScanError, Severity
from aws_security_auditor.readonly_client import ReadOnlyAwsClient


def scan_vpc(ec2: ReadOnlyAwsClient, region: str) -> CheckResult:
    result = CheckResult(checks=1)
    try:
        vpcs: list[dict[str, Any]] = []
        for page in ec2.paginate("describe_vpcs"):
            page_vpcs = page.get("Vpcs", [])
            result.resources += len(page_vpcs)
            vpcs.extend(page_vpcs)

        active_flow_log_vpcs: set[str] = set()
        for page in ec2.paginate("describe_flow_logs"):
            for flow_log in page.get("FlowLogs", []):
                resource_id = flow_log.get("ResourceId")
                if flow_log.get("FlowLogStatus") == "ACTIVE" and isinstance(
                    resource_id, str
                ) and resource_id.startswith("vpc-"):
                    active_flow_log_vpcs.add(resource_id)

        for vpc in vpcs:
            vpc_id = str(vpc.get("VpcId", "unknown"))
            if vpc_id in active_flow_log_vpcs:
                continue
            name = _name_tag(vpc)
            detail = f"VPC {vpc_id} has no active VPC-level Flow Log."
            if name:
                detail = f"VPC {vpc_id} ({name}) has no active VPC-level Flow Log."
            result.findings.append(
                Finding(
                    Severity.MEDIUM,
                    "VPC_FLOW_LOGS_DISABLED",
                    "VPC",
                    region,
                    vpc_id,
                    "VPC Flow Logs are not enabled",
                    detail,
                    "Enable VPC-level Flow Logs and deliver them to an approved "
                    "logging destination.",
                )
            )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(errors=[ScanError("VPC", region, f"VPC scan skipped: {exc}")])
    return result


def _name_tag(vpc: dict[str, Any]) -> str | None:
    for tag in vpc.get("Tags", []):
        if isinstance(tag, dict) and tag.get("Key") == "Name":
            value = tag.get("Value")
            return str(value) if value else None
    return None
