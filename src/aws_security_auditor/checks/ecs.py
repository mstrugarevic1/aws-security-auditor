from __future__ import annotations

from collections.abc import Iterator
from itertools import islice
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_security_auditor.checks.base import CheckResult
from aws_security_auditor.models import Finding, ScanError, Severity
from aws_security_auditor.readonly_client import ReadOnlyAwsClient


def scan_ecs(ecs: ReadOnlyAwsClient, region: str) -> CheckResult:
    result = CheckResult(checks=2)
    task_definitions: dict[str, dict[str, Any]] = {}
    privileged_seen: set[tuple[str, str]] = set()
    try:
        for cluster_page in ecs.paginate("list_clusters"):
            for cluster_arn in cluster_page.get("clusterArns", []):
                _scan_cluster(
                    ecs,
                    region,
                    str(cluster_arn),
                    result,
                    task_definitions,
                    privileged_seen,
                )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        return CheckResult(errors=[ScanError("ECS", region, f"ECS scan skipped: {exc}")])
    return result


def _scan_cluster(
    ecs: ReadOnlyAwsClient,
    region: str,
    cluster_arn: str,
    result: CheckResult,
    task_definitions: dict[str, dict[str, Any]],
    privileged_seen: set[tuple[str, str]],
) -> None:
    try:
        for service_arns in _service_batches(ecs, cluster_arn):
            if not service_arns:
                continue
            try:
                services = ecs.call(
                    "describe_services",
                    cluster=cluster_arn,
                    services=service_arns,
                ).get("services", [])
            except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
                result.errors.append(
                    ScanError("ECS", region, f"ECS service batch skipped: {exc}")
                )
                continue
            result.resources += len(services)
            for service in services:
                _scan_service(
                    ecs,
                    region,
                    cluster_arn,
                    service,
                    result,
                    task_definitions,
                    privileged_seen,
                )
    except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
        result.errors.append(ScanError("ECS", region, f"ECS cluster skipped: {exc}"))
        return


def _scan_service(
    ecs: ReadOnlyAwsClient,
    region: str,
    cluster_arn: str,
    service: dict[str, Any],
    result: CheckResult,
    task_definitions: dict[str, dict[str, Any]],
    privileged_seen: set[tuple[str, str]],
) -> None:
    result.findings.extend(_public_ip_findings(service, cluster_arn, region))
    task_definition_arn = service.get("taskDefinition")
    if not isinstance(task_definition_arn, str):
        return
    task_definition = task_definitions.get(task_definition_arn)
    if task_definition is None:
        try:
            task_definition = ecs.call(
                "describe_task_definition",
                taskDefinition=task_definition_arn,
            ).get("taskDefinition", {})
        except (ClientError, BotoCoreError, KeyError, TypeError) as exc:
            result.errors.append(
                ScanError(
                    "ECS",
                    region,
                    f"ECS task definition skipped for {task_definition_arn}: {exc}",
                )
            )
            return
        task_definitions[task_definition_arn] = task_definition
    result.findings.extend(
        _privileged_findings(
            task_definition,
            service,
            cluster_arn,
            region,
            privileged_seen,
        )
    )


def _service_batches(ecs: ReadOnlyAwsClient, cluster_arn: str) -> Iterator[list[str]]:
    for page in ecs.paginate("list_services", cluster=cluster_arn):
        services = iter(page.get("serviceArns", []))
        while batch := list(islice(services, 10)):
            yield batch


def _public_ip_findings(
    service: dict[str, Any], cluster_arn: str, region: str
) -> list[Finding]:
    awsvpc = service.get("networkConfiguration", {}).get("awsvpcConfiguration", {})
    if awsvpc.get("assignPublicIp") != "ENABLED":
        return []
    service_id = str(service.get("serviceArn") or service.get("serviceName") or "unknown")
    task_definition = str(service.get("taskDefinition") or "unknown")
    return [
        Finding(
            Severity.MEDIUM,
            "ECS_SERVICE_PUBLIC_IP_ENABLED",
            "ECS",
            region,
            service_id,
            "ECS service assigns public IP addresses",
            f"Cluster {cluster_arn} service {service.get('serviceName', service_id)} "
            f"uses task definition {task_definition} with assignPublicIp=ENABLED.",
            "Run tasks in private subnets and expose them through an approved "
            "load balancer or ingress layer.",
        )
    ]


def _privileged_findings(
    task_definition: dict[str, Any],
    service: dict[str, Any],
    cluster_arn: str,
    region: str,
    seen: set[tuple[str, str]],
) -> list[Finding]:
    task_definition_arn = str(
        task_definition.get("taskDefinitionArn") or service.get("taskDefinition")
    )
    findings: list[Finding] = []
    for container in task_definition.get("containerDefinitions", []):
        if container.get("privileged") is not True:
            continue
        container_name = str(container.get("name") or "unknown")
        key = (task_definition_arn, container_name)
        if key in seen:
            continue
        seen.add(key)
        findings.append(
            Finding(
                Severity.HIGH,
                "ECS_PRIVILEGED_CONTAINER",
                "ECS",
                region,
                task_definition_arn,
                "ECS task definition contains a privileged container",
                f"Container {container_name} in task definition {task_definition_arn} "
                f"is privileged. Service={service.get('serviceName', 'unknown')} "
                f"Cluster={cluster_arn}.",
                "Remove privileged mode and grant only the minimum required Linux capabilities.",
            )
        )
    return findings
