# Authentication

Supported authentication:

- default boto3 credential chain
- named AWS profile with `--profile`
- STS AssumeRole with `--role-arn` and optional `--external-id`

Recommended approach: use a dedicated read-only role.

```bash
aws-security-auditor scan \
  --role-arn arn:aws:iam::123456789012:role/AwsSecurityAuditorReadOnly
```

Example trust policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
      "Action": "sts:AssumeRole"
    }
  ]
}
```

The tool does not require administrator permissions. Some checks may be skipped when the role
lacks access to specific services.

Before scanning it calls `sts:GetCallerIdentity` and displays the account ID, ARN, selected
profile or assumed role, and region count. It never prints credentials, tokens, or secrets.
