# Usage

Full option and service reference. Run `aws-security-auditor --help` or
`aws-security-auditor scan --help` for the authoritative help generated from the code.

## Commands

| Command | Purpose |
| --- | --- |
| `scan` | Run a read-only audit. |
| `list-checks` | Print implemented check IDs. |
| `list-services` | Print service names accepted by `--services`. |
| `--version` | Print the installed package version. |

## Options

| Option | Purpose |
| --- | --- |
| `--profile PROFILE` | Use a named AWS profile. |
| `--config PATH` | Load TOML config for required tags and critical-resource tag values. |
| `--role-arn ROLE_ARN` | Assume a read-only audit role before scanning. |
| `--external-id EXTERNAL_ID` | Pass an external ID when assuming a role. |
| `--regions REGION1,REGION2` | Scan only the listed AWS regions. |
| `--exclude-regions REGION1,REGION2` | Skip the listed AWS regions. |
| `--services ec2,s3,iam` | Scan only selected services. |
| `--output table,json,markdown,csv` | Choose the report format. |
| `--output-file PATH` | Write the report to a file. |
| `--severity HIGH,MEDIUM,LOW` | Show findings at this severity or higher. |
| `--fail-on HIGH,MEDIUM,LOW` | Exit with status `1` when this severity or higher is found. |
| `--no-color` | Disable terminal color. |
| `--verbose` | Show skipped regions and warnings. |
| `--snapshot-age-days 90` | Set the old snapshot threshold. |
| `--access-key-age-days 90` | Set the old access key threshold. |
| `--required-tags Owner,Environment,CostCenter` | Set required resource tags. |
| `--max-workers 5` | Set the maximum regional scan worker threads. |
| `--notify-on HIGH,MEDIUM,LOW` | Send a Slack notification when this severity or higher is found. |
| `--slack-webhook-url URL` | Send Slack notifications to this incoming webhook URL. |

## Regions

By default the scanner discovers all enabled AWS regions with `ec2:DescribeRegions`. It scans
`opt-in-not-required` and `opted-in` regions, and skips `not-opted-in` regions. IAM, STS, and
S3 bucket enumeration run once as global/account-level checks.

## Services

Use `--services` to scan only selected services.

| Service | Default | Scope |
| --- | --- | --- |
| `ec2` | Yes | EC2 instances, security groups, EBS volumes, snapshots, AMIs, and Elastic IPs. |
| `ecs` | Yes | ECS services and current task definitions. Standalone tasks are out of scope. |
| `ecr` | Yes | ECR repository scan-on-push settings. |
| `elbv2` | Yes | Application and Network Load Balancers. |
| `iam` | Yes | Account-level IAM posture. |
| `kms` | Yes | Customer-managed KMS key rotation. |
| `lambda` | Yes | Lambda Function URL authentication. |
| `rds` | Yes | RDS public access, encryption, and backup posture. |
| `s3` | Yes | S3 bucket public access, encryption, versioning, and logging. |
| `secretsmanager` | Yes | Customer-managed secret rotation. Secret values are never read. |
| `tags` | Yes | Required tags on supported resources. |
| `vpc` | Yes | VPC-level Flow Logs. |
| `accessanalyzer` | No | IAM Access Analyzer external-access analyzer baseline. |
| `cloudtrail` | No | Account baseline check for CloudTrail trails. |
| `config` | No | Account baseline check for AWS Config recorders. |
| `guardduty` | No | Account baseline check for GuardDuty detectors. |
| `securityhub` | No | Account baseline check for Security Hub enablement. |

## Severity filtering

Use `--severity MEDIUM` to show `HIGH` and `MEDIUM` findings. Use `--severity HIGH` to show only
high-severity findings.

Use `--fail-on HIGH` in CI or scheduled jobs when high-severity findings should fail the run.

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Scan completed and did not hit the configured `--fail-on` threshold. |
| `1` | Findings met the configured `--fail-on` threshold. |
| `2` | CLI usage, profile, region, config, or AWS API setup error prevented a clean scan. |

## Examples

Recommended scheduled scan:

```bash
aws-security-auditor scan \
  --profile audit \
  --config examples/aws-security-auditor.toml \
  --fail-on HIGH \
  --notify-on HIGH
```

Selected service scan:

```bash
aws-security-auditor scan \
  --profile audit \
  --services ec2,vpc,lambda,ecs,secretsmanager,rds
```

Baseline-only scan:

```bash
aws-security-auditor scan \
  --profile audit \
  --services cloudtrail,accessanalyzer
```

## Slack notifications

Use `--notify-on` with a Slack incoming webhook when scheduled scans should notify a channel.
The webhook can be passed directly or read from `AWS_SECURITY_AUDITOR_SLACK_WEBHOOK_URL`:

```bash
export AWS_SECURITY_AUDITOR_SLACK_WEBHOOK_URL="$SLACK_WEBHOOK_URL"
aws-security-auditor scan --profile audit --notify-on HIGH
```

`--notify-on HIGH` sends only when `HIGH` findings exist. `MEDIUM` includes `HIGH` and
`MEDIUM`; `LOW` sends for any finding. Slack delivery failure prints a warning but does not
change the scan exit code. `--fail-on` still controls CI failure behavior independently.

The webhook URL is never printed by the tool and must use HTTPS.
