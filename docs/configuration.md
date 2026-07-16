# Configuration

Use a TOML config file for repeatable scan defaults:

```bash
aws-security-auditor scan --profile audit --config aws-security-auditor.toml
```

Example:

```toml
required_tags = ["Owner", "Environment", "CostCenter"]
regions = ["eu-central-1", "eu-west-1"]
services = ["ec2", "s3", "iam"]
output = "json"
severity = "MEDIUM"
fail_on = "HIGH"
snapshot_age_days = 90
access_key_age_days = 90
max_workers = 5

[critical_resource_tags]
Environment = ["prod", "production", "prd"]
Criticality = ["high", "critical", "tier1"]

[[suppressions]]
check_id = "EC2_SG_OPEN_SSH"
resource_id = "sg-0123456789abcdef0"
region = "eu-central-1"
account_id = "123456789012"
reason = "Temporary vendor access"
expires = "2026-08-01"
```

See [examples/aws-security-auditor.toml](../examples/aws-security-auditor.toml) for a reusable
starting point.

| Setting | Purpose |
| --- | --- |
| `regions` | Regions to scan. CLI `--regions` overrides this. |
| `exclude_regions` | Regions to skip. CLI `--exclude-regions` overrides this. |
| `services` | Services to scan. CLI `--services` overrides this. |
| `output` | `table`, `json`, `markdown`, or `csv`. CLI `--output` overrides this. |
| `severity` | Minimum reported severity. CLI `--severity` overrides this. |
| `fail_on` | Severity threshold for exit code `1`. CLI `--fail-on` overrides this. |
| `snapshot_age_days` | Old EBS snapshot threshold. |
| `access_key_age_days` | Old IAM access key threshold. |
| `max_workers` | Maximum regional scan worker threads. |
| `required_tags` | Tags required by the tag governance check. |
| `critical_resource_tags` | Tag values that raise severity for resilience-sensitive findings such as disabled RDS backups or deletion protection. |
| `suppressions` | Time-limited exact-match finding suppressions. |

Precedence is: CLI arguments, then config file, then application defaults.

Tags tune severity and context only. Missing tags do not suppress direct security exposure checks.

## Suppressions

Suppressions require `check_id`, `resource_id`, `reason`, and `expires`. `region` and
`account_id` are optional exact-match constraints. Suppressions do not support wildcards,
regular expressions, service-wide rules, severity-only rules, or permanent suppressions.
The expiration date is valid through that UTC date. Expired suppressions are logged as warnings
and stop suppressing findings.

Suppressed findings are removed before severity filtering, Slack notification, and `--fail-on`
evaluation. They remain auditable in console summary counts, verbose console output, JSON, and
Markdown. CSV reports include active findings only.
