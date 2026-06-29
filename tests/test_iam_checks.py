from __future__ import annotations

from datetime import UTC, datetime, timedelta

from botocore.exceptions import ClientError

from aws_security_auditor.checks.iam import scan_iam


class FakeIam:
    def paginate(self, operation: str, **kwargs: object):
        old = datetime.now(UTC) - timedelta(days=120)
        if operation == "list_users":
            return iter([[{"Users": [{"UserName": "alice", "CreateDate": old}]}][0]])
        if operation == "list_access_keys":
            return iter(
                [
                    [
                        {
                            "AccessKeyMetadata": [
                                {"AccessKeyId": "AKIAOLD", "Status": "Active", "CreateDate": old}
                            ]
                        }
                    ][0]
                ]
            )
        if operation == "list_mfa_devices":
            return iter([{"MFADevices": []}])
        if operation == "list_user_policies":
            return iter([{"PolicyNames": ["inline"]}])
        if operation == "get_account_authorization_details":
            return iter(
                [
                    {
                        "UserDetailList": [
                            {
                                "UserName": "admin-user",
                                "AttachedManagedPolicies": [
                                    {"PolicyName": "AdministratorAccess"}
                                ],
                            }
                        ],
                        "GroupDetailList": [
                            {
                                "GroupName": "admins",
                                "AttachedManagedPolicies": [
                                    {
                                        "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
                                    }
                                ],
                            }
                        ],
                        "RoleDetailList": [
                            {
                                "RoleName": "admin-role",
                                "AttachedManagedPolicies": [
                                    {"PolicyName": "AdministratorAccess"}
                                ],
                            }
                        ],
                    }
                ]
            )
        raise AssertionError(operation)

    def call(self, operation: str, **kwargs: object) -> dict[str, object]:
        if operation == "get_account_summary":
            return {"SummaryMap": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1}}
        if operation == "get_account_password_policy":
            return {"PasswordPolicy": {"MinimumPasswordLength": 8}}
        if operation == "get_login_profile":
            return {"LoginProfile": {}}
        if operation == "get_access_key_last_used":
            return {"AccessKeyLastUsed": {}}
        raise ClientError({"Error": {"Code": "NoSuchEntity"}}, operation)


def test_old_access_key_and_missing_mfa() -> None:
    result = scan_iam(FakeIam(), 90)  # type: ignore[arg-type]
    assert {"IAM_OLD_ACCESS_KEY", "IAM_UNUSED_ACCESS_KEY", "IAM_USER_NO_MFA"} <= {
        f.check_id for f in result.findings
    }
    assert {
        "IAM_ROOT_MFA_DISABLED",
        "IAM_ROOT_ACCESS_KEYS_PRESENT",
        "IAM_WEAK_PASSWORD_POLICY",
        "IAM_USER_ADMINISTRATOR_ACCESS",
        "IAM_GROUP_ADMINISTRATOR_ACCESS",
        "IAM_ROLE_ADMINISTRATOR_ACCESS",
    } <= {f.check_id for f in result.findings}
