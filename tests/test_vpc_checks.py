from __future__ import annotations

from botocore.exceptions import ClientError

from aws_security_auditor.checks.vpc import scan_vpc


class FakeVpc:
    def __init__(self, fail: bool = False):
        self.fail = fail

    def paginate(self, operation: str, **kwargs: object):
        if self.fail:
            raise ClientError({"Error": {"Code": "Denied"}}, operation)
        pages = {
            "describe_vpcs": [
                {
                    "Vpcs": [
                        {"VpcId": "vpc-ok"},
                        {
                            "VpcId": "vpc-missing",
                            "Tags": [{"Key": "Name", "Value": "prod"}],
                        },
                    ]
                },
                {"Vpcs": [{"VpcId": "vpc-inactive"}, {"VpcId": "vpc-subnet-only"}]},
            ],
            "describe_flow_logs": [
                {
                    "FlowLogs": [
                        {"ResourceId": "vpc-ok", "FlowLogStatus": "ACTIVE"},
                        {"ResourceId": "vpc-inactive", "FlowLogStatus": "FAILED"},
                        {"ResourceId": "subnet-1", "FlowLogStatus": "ACTIVE"},
                    ]
                }
            ],
        }
        return iter(pages[operation])


def test_vpc_flow_logs() -> None:
    result = scan_vpc(FakeVpc(), "us-east-1")  # type: ignore[arg-type]

    assert result.checks == 1
    assert result.resources == 4
    assert {f.resource_id for f in result.findings} == {
        "vpc-missing",
        "vpc-inactive",
        "vpc-subnet-only",
    }
    assert {f.check_id for f in result.findings} == {"VPC_FLOW_LOGS_DISABLED"}


def test_vpc_api_error() -> None:
    result = scan_vpc(FakeVpc(fail=True), "us-east-1")  # type: ignore[arg-type]

    assert result.findings == []
    assert result.errors
