from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_security_auditor.checks.base import CheckResult
from aws_security_auditor.models import Finding, ScanError, Severity
from aws_security_auditor.readonly_client import ReadOnlyAwsClient

DB_PORTS = {1433, 1521, 27017, 3306, 5432, 6379, 9200}


def _port_range(rule: dict[str, Any]) -> tuple[int, int] | None:
    if rule.get("IpProtocol") == "-1":
        return (0, 65535)
    if "FromPort" not in rule or "ToPort" not in rule:
        return None
    return int(rule["FromPort"]), int(rule["ToPort"])


def _contains(start: int, end: int, port: int) -> bool:
    return start <= port <= end


def _public(rule: dict[str, Any]) -> bool:
    return any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", [])) or any(
        r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", [])
    )


def scan_ec2(
    ec2: ReadOnlyAwsClient, region: str, account_id: str, snapshot_age_days: int
) -> CheckResult:
    result = CheckResult(checks=11)
    security_groups: dict[str, dict[str, Any]] = {}
    try:
        if ec2.call("get_ebs_encryption_by_default").get("EbsEncryptionByDefault") is not True:
            result.findings.append(
                Finding(
                    Severity.MEDIUM,
                    "EBS_DEFAULT_ENCRYPTION_DISABLED",
                    "EBS",
                    region,
                    "account",
                    "EBS encryption by default is disabled",
                    "New EBS volumes are not encrypted by default in this region.",
                    "Enable EBS encryption by default.",
                )
            )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        result.errors.append(
            ScanError("EC2", region, f"EBS default encryption check skipped: {exc}")
        )

    try:
        for page in ec2.paginate("describe_security_groups"):
            groups = page.get("SecurityGroups", [])
            result.resources += len(groups)
            for group in groups:
                security_groups[group.get("GroupId", "unknown")] = group
                result.findings.extend(_security_group_findings(group, region))
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        result.errors.append(ScanError("EC2", region, f"Security group scan skipped: {exc}"))

    try:
        attached_groups = _attached_security_groups(ec2)
        for group_id, group in security_groups.items():
            if group_id not in attached_groups and group.get("GroupName") != "default":
                result.findings.append(
                    Finding(
                        Severity.LOW,
                        "EC2_UNUSED_SECURITY_GROUP",
                        "EC2",
                        region,
                        group_id,
                        "Unused security group",
                        "Security group is not attached to any network interface.",
                        "Delete unused security groups after confirming they are not needed.",
                    )
                )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        result.errors.append(ScanError("EC2", region, f"Unused security group scan skipped: {exc}"))

    try:
        for page in ec2.paginate("describe_instances"):
            for reservation in page.get("Reservations", []):
                instances = reservation.get("Instances", [])
                result.resources += len(instances)
                for instance in instances:
                    result.findings.extend(_imds_findings(instance, region))
                    result.findings.extend(
                        _public_instance_findings(instance, security_groups, region)
                    )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        result.errors.append(ScanError("EC2", region, f"Public instance scan skipped: {exc}"))

    try:
        addresses = ec2.call("describe_addresses").get("Addresses", [])
        result.resources += len(addresses)
        for address in addresses:
            if "AssociationId" not in address:
                alloc = address.get("AllocationId") or address.get("PublicIp", "unknown")
                result.findings.append(
                    Finding(
                        Severity.MEDIUM,
                        "EC2_UNUSED_EIP",
                        "EC2",
                        region,
                        alloc,
                        "Unused Elastic IP address",
                        "Elastic IP address is not associated with a resource.",
                        "Release unused Elastic IP addresses after confirming they "
                        "are not needed.",
                    )
                )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        result.errors.append(ScanError("EC2", region, f"Elastic IP scan skipped: {exc}"))

    try:
        for page in ec2.paginate("describe_volumes"):
            volumes = page.get("Volumes", [])
            result.resources += len(volumes)
            for volume in volumes:
                result.findings.extend(_volume_findings(volume, region))
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        result.errors.append(ScanError("EC2", region, f"EBS volume scan skipped: {exc}"))

    cutoff = datetime.now(UTC) - timedelta(days=snapshot_age_days)
    try:
        for page in ec2.paginate("describe_snapshots", OwnerIds=[account_id]):
            snapshots = page.get("Snapshots", [])
            result.resources += len(snapshots)
            for snapshot in snapshots:
                snapshot_id = snapshot.get("SnapshotId", "unknown")
                started = snapshot.get("StartTime")
                if isinstance(started, datetime) and started < cutoff:
                    result.findings.append(
                        Finding(
                            Severity.LOW,
                            "EBS_OLD_SNAPSHOT",
                            "EBS",
                            region,
                            snapshot_id,
                            "Old EBS snapshot",
                            f"Snapshot is older than {snapshot_age_days} days.",
                            "Review old snapshots and retain only those required by backup policy.",
                        )
                    )
                if _snapshot_public(ec2, snapshot_id):
                    result.findings.append(
                        Finding(
                            Severity.HIGH,
                            "EBS_PUBLIC_SNAPSHOT",
                            "EBS",
                            region,
                            snapshot_id,
                            "Public EBS snapshot",
                            "Snapshot restore permissions include all AWS accounts.",
                            "Remove public restore permissions unless explicitly required.",
                        )
                    )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        result.errors.append(ScanError("EC2", region, f"EBS snapshot scan skipped: {exc}"))

    try:
        for page in ec2.paginate("describe_images", Owners=[account_id]):
            images = page.get("Images", [])
            result.resources += len(images)
            for image in images:
                if image.get("Public") is True:
                    result.findings.append(
                        Finding(
                            Severity.HIGH,
                            "EC2_PUBLIC_AMI",
                            "EC2",
                            region,
                            image.get("ImageId", "unknown"),
                            "Public account-owned AMI",
                            "AMI is publicly launchable.",
                            "Make the AMI private unless public distribution is intentional.",
                        )
                    )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        result.errors.append(ScanError("EC2", region, f"AMI scan skipped: {exc}"))
    return result


def _security_group_findings(group: dict[str, Any], region: str) -> list[Finding]:
    findings: list[Finding] = []
    group_id = group.get("GroupId", "unknown")
    group_name = group.get("GroupName", "unknown")
    for rule in group.get("IpPermissions", []):
        if not _public(rule):
            continue
        ports = _port_range(rule)
        if not ports:
            continue
        start, end = ports
        if start == 0 and end == 65535:
            title, severity, check = "All ports open to the world", Severity.HIGH, "EC2_SG_OPEN_ALL"
        elif _contains(start, end, 22):
            title, severity, check = "SSH open to the world", Severity.HIGH, "EC2_SG_OPEN_SSH"
        elif _contains(start, end, 3389):
            title, severity, check = "RDP open to the world", Severity.HIGH, "EC2_SG_OPEN_RDP"
        elif any(_contains(start, end, p) for p in DB_PORTS):
            title, severity, check = (
                "Database port open to the world",
                Severity.HIGH,
                "EC2_SG_OPEN_DB",
            )
        elif start == 80 and end == 80:
            title, severity, check = "HTTP open to the world", Severity.LOW, "EC2_SG_OPEN_HTTP"
        elif start == 443 and end == 443:
            title, severity, check = "HTTPS open to the world", Severity.LOW, "EC2_SG_OPEN_HTTPS"
        else:
            title, severity, check = "Public ingress port", Severity.MEDIUM, "EC2_SG_PUBLIC_INGRESS"
        findings.append(
            Finding(
                severity,
                check,
                "EC2",
                region,
                group_id,
                title,
                f"Security group {group_name} ({group_id}) allows ingress "
                f"from the internet on ports {start}-{end}.",
                "Restrict ingress to trusted CIDR ranges or remove the rule.",
            )
        )
        if group_name == "default":
            findings.append(
                Finding(
                    Severity.HIGH,
                    "EC2_DEFAULT_SG_PUBLIC_INGRESS",
                    "EC2",
                    region,
                    group_id,
                    "Default security group allows public ingress",
                    f"Default security group ({group_id}) allows ingress "
                    f"from the internet on ports {start}-{end}.",
                    "Remove public ingress from the default security group.",
                )
            )
    return findings


def _attached_security_groups(ec2: ReadOnlyAwsClient) -> set[str]:
    group_ids: set[str] = set()
    for page in ec2.paginate("describe_network_interfaces"):
        for interface in page.get("NetworkInterfaces", []):
            for group in interface.get("Groups", []):
                if group_id := group.get("GroupId"):
                    group_ids.add(group_id)
    return group_ids


def _public_instance_findings(
    instance: dict[str, Any], security_groups: dict[str, dict[str, Any]], region: str
) -> list[Finding]:
    if not _instance_has_public_ip(instance):
        return []
    instance_id = instance.get("InstanceId", "unknown")
    findings: list[Finding] = []
    for group_ref in instance.get("SecurityGroups", []):
        group = security_groups.get(group_ref.get("GroupId", ""))
        if not group:
            continue
        for rule in group.get("IpPermissions", []):
            if not _public(rule):
                continue
            ports = _port_range(rule)
            if not ports:
                continue
            title, severity = _public_instance_title(*ports)
            if not title:
                continue
            findings.append(
                Finding(
                    severity,
                    "EC2_PUBLIC_INSTANCE_EXPOSURE",
                    "EC2",
                    region,
                    instance_id,
                    title,
                    f"Public instance {instance_id} uses security group "
                    f"{group.get('GroupId', 'unknown')} with internet ingress "
                    f"on ports {ports[0]}-{ports[1]}.",
                    "Restrict ingress, remove the public IP, or place the workload "
                    "behind a load balancer.",
                )
            )
    return findings


def _imds_findings(instance: dict[str, Any], region: str) -> list[Finding]:
    if instance.get("State", {}).get("Name") == "terminated":
        return []
    metadata_options = instance.get("MetadataOptions", {})
    if not isinstance(metadata_options, dict):
        metadata_options = {}
    http_endpoint = metadata_options.get("HttpEndpoint")
    http_tokens = metadata_options.get("HttpTokens")
    if http_endpoint == "disabled" or http_tokens == "required":
        return []
    instance_id = instance.get("InstanceId", "unknown")
    return [
        Finding(
            Severity.MEDIUM,
            "EC2_IMDSV2_NOT_REQUIRED",
            "EC2",
            region,
            instance_id,
            "EC2 instance does not require IMDSv2",
            f"Instance metadata options: HttpEndpoint={http_endpoint} "
            f"HttpTokens={http_tokens}.",
            "Require IMDSv2 by setting HttpTokens to required.",
        )
    ]


def _instance_has_public_ip(instance: dict[str, Any]) -> bool:
    if instance.get("PublicIpAddress"):
        return True
    return any(
        interface.get("Association", {}).get("PublicIp")
        for interface in instance.get("NetworkInterfaces", [])
    )


def _public_instance_title(start: int, end: int) -> tuple[str | None, Severity]:
    if start == 0 and end == 65535:
        return "Public EC2 instance exposes all ports", Severity.HIGH
    if _contains(start, end, 22):
        return "Public EC2 instance exposes SSH", Severity.HIGH
    if _contains(start, end, 3389):
        return "Public EC2 instance exposes RDP", Severity.HIGH
    if any(_contains(start, end, p) for p in DB_PORTS):
        return "Public EC2 instance exposes a database port", Severity.HIGH
    if start in {80, 443} and end == start:
        return "Public EC2 instance exposes web traffic", Severity.MEDIUM
    return "Public EC2 instance exposes internet ingress", Severity.MEDIUM


def _snapshot_public(ec2: ReadOnlyAwsClient, snapshot_id: str) -> bool:
    try:
        response = ec2.call(
            "describe_snapshot_attribute",
            SnapshotId=snapshot_id,
            Attribute="createVolumePermission",
        )
    except ClientError:
        return False
    return any(
        permission.get("Group") == "all"
        for permission in response.get("CreateVolumePermissions", [])
    )


def _volume_findings(volume: dict[str, Any], region: str) -> list[Finding]:
    volume_id = volume.get("VolumeId", "unknown")
    findings: list[Finding] = []
    if volume.get("State") == "available":
        findings.append(
            Finding(
                Severity.MEDIUM,
                "EBS_UNATTACHED_VOLUME",
                "EBS",
                region,
                volume_id,
                "Unattached EBS volume",
                "Volume is available and unattached. "
                f"Size={volume.get('Size')}GiB Created={volume.get('CreateTime')} "
                f"Encrypted={volume.get('Encrypted')}",
                "Delete unused volumes after confirming no data retention requirement.",
            )
        )
    if volume.get("Encrypted") is False:
        findings.append(
            Finding(
                Severity.HIGH,
                "EBS_UNENCRYPTED_VOLUME",
                "EBS",
                region,
                volume_id,
                "Unencrypted EBS volume",
                "Volume encryption is disabled.",
                "Migrate data to encrypted storage.",
            )
        )
    return findings
