from __future__ import annotations

from botocore.exceptions import ClientError

from aws_security_auditor.checks.lambda_functions import scan_lambda


class FakeLambda:
    def __init__(self):
        self.url_calls: list[str] = []

    def paginate(self, operation: str, **kwargs: object):
        assert operation == "list_functions"
        return iter(
            [
                {"Functions": [{"FunctionName": "public", "FunctionArn": "arn:public"}]},
                {
                    "Functions": [
                        {"FunctionName": "private", "FunctionArn": "arn:private"},
                        {"FunctionName": "none", "FunctionArn": "arn:none"},
                        {"FunctionName": "fail", "FunctionArn": "arn:fail"},
                    ]
                },
            ]
        )

    def call(self, operation: str, **kwargs: object):
        assert operation == "list_function_url_configs"
        name = str(kwargs["FunctionName"])
        self.url_calls.append(name)
        if name == "fail":
            raise ClientError({"Error": {"Code": "Denied"}}, operation)
        if name == "public" and "Marker" not in kwargs:
            return {
                "FunctionUrlConfigs": [
                    {"AuthType": "AWS_IAM", "FunctionUrl": "https://private.example"},
                ],
                "NextMarker": "next",
            }
        if name == "public":
            return {
                "FunctionUrlConfigs": [
                    {"AuthType": "NONE", "FunctionUrl": "https://public.example"},
                ]
            }
        if name == "private":
            return {"FunctionUrlConfigs": [{"AuthType": "AWS_IAM"}]}
        return {"FunctionUrlConfigs": []}


def test_lambda_public_function_urls() -> None:
    fake = FakeLambda()
    result = scan_lambda(fake, "us-east-1")  # type: ignore[arg-type]

    assert result.resources == 4
    assert [(f.check_id, f.severity.value, f.resource_id) for f in result.findings] == [
        ("LAMBDA_PUBLIC_FUNCTION_URL", "HIGH", "arn:public")
    ]
    assert result.errors
    assert fake.url_calls == ["public", "public", "private", "none", "fail"]
