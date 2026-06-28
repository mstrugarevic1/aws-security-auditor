from __future__ import annotations

from aws_security_auditor.checks.network import scan_ecr, scan_elbv2, scan_kms


class FakeElbv2:
    def paginate(self, operation: str, **kwargs: object):
        return iter(
            [
                {
                    "LoadBalancers": [
                        {
                            "LoadBalancerArn": "arn:lb",
                            "LoadBalancerName": "public",
                            "Scheme": "internet-facing",
                        }
                    ]
                }
            ]
        )


class FakeEcr:
    def paginate(self, operation: str, **kwargs: object):
        return iter(
            [
                {
                    "repositories": [
                        {
                            "repositoryName": "app",
                            "imageScanningConfiguration": {"scanOnPush": False},
                        }
                    ]
                }
            ]
        )


class FakeKms:
    def paginate(self, operation: str, **kwargs: object):
        return iter([{"Keys": [{"KeyId": "key-1"}]}])

    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        if operation == "get_key_rotation_status":
            return {"KeyRotationEnabled": False}
        raise AssertionError(operation)


def test_network_security_findings() -> None:
    findings = (
        scan_elbv2(FakeElbv2(), "us-east-1").findings
        + scan_ecr(FakeEcr(), "us-east-1").findings
        + scan_kms(FakeKms(), "us-east-1").findings
    )
    assert {
        "ELBV2_INTERNET_FACING",
        "ECR_SCAN_ON_PUSH_DISABLED",
        "KMS_KEY_ROTATION_DISABLED",
    } <= {finding.check_id for finding in findings}
