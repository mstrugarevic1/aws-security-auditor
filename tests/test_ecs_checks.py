from __future__ import annotations

from botocore.exceptions import ClientError

from aws_security_auditor.checks.ecs import scan_ecs


class FakeEcs:
    def __init__(self, fail: bool = False):
        self.fail = fail
        self.describe_services_batches: list[list[str]] = []
        self.task_definition_calls = 0

    def paginate(self, operation: str, **kwargs: object):
        if self.fail:
            raise ClientError({"Error": {"Code": "Denied"}}, operation)
        if operation == "list_clusters":
            return iter([{"clusterArns": ["cluster-a"]}, {"clusterArns": ["cluster-b"]}])
        if operation == "list_services":
            cluster = kwargs["cluster"]
            services = [f"{cluster}/svc-{i}" for i in range(11)] if cluster == "cluster-a" else []
            return iter([{"serviceArns": services}])
        raise AssertionError(operation)

    def call(self, operation: str, **kwargs: object):
        if operation == "describe_services":
            services = list(kwargs["services"])
            self.describe_services_batches.append(services)
            return {
                "services": [
                    {
                        "serviceArn": arn,
                        "serviceName": arn.rsplit("/", 1)[-1],
                        "taskDefinition": "td-shared" if arn.endswith(("0", "1")) else "td-safe",
                        "networkConfiguration": {
                            "awsvpcConfiguration": {
                                "assignPublicIp": "ENABLED" if arn.endswith("0") else "DISABLED"
                            }
                        },
                    }
                    for arn in services
                ]
            }
        if operation == "describe_task_definition":
            self.task_definition_calls += 1
            arn = str(kwargs["taskDefinition"])
            containers = [{"name": "app", "privileged": arn == "td-shared"}, {"name": "sidecar"}]
            return {
                "taskDefinition": {
                    "taskDefinitionArn": arn,
                    "containerDefinitions": containers,
                }
            }
        raise AssertionError(operation)


def test_ecs_service_checks_batching_and_cache() -> None:
    fake = FakeEcs()
    result = scan_ecs(fake, "us-east-1")  # type: ignore[arg-type]

    assert result.resources == 11
    assert len(fake.describe_services_batches) == 2
    assert all(len(batch) <= 10 for batch in fake.describe_services_batches)
    assert fake.task_definition_calls == 2
    assert {f.check_id for f in result.findings} == {
        "ECS_SERVICE_PUBLIC_IP_ENABLED",
        "ECS_PRIVILEGED_CONTAINER",
    }
    privileged = [f for f in result.findings if f.check_id == "ECS_PRIVILEGED_CONTAINER"]
    assert len(privileged) == 1


def test_ecs_api_failure() -> None:
    result = scan_ecs(FakeEcs(fail=True), "us-east-1")  # type: ignore[arg-type]

    assert result.findings == []
    assert result.errors
