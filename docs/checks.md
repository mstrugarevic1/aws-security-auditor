# Checks

## Severity

| Severity | Meaning |
| --- | --- |
| `HIGH` | Likely security exposure requiring prompt review. |
| `MEDIUM` | Cost, resilience, or exposure issue worth fixing. |
| `LOW` | Governance or security posture improvement. |

## Implemented checks

| Area | Checks |
| --- | --- |
| EC2 security groups | Public ingress for SSH, RDP, HTTP, HTTPS, database ports, all ports, and other ports; default security groups with public ingress; unused security groups. |
| EC2 capacity and images | Unused Elastic IPs, unattached or unencrypted EBS volumes, disabled EBS encryption by default, old account-owned EBS snapshots, public account-owned AMIs, public EBS snapshots. |
| EC2 instances | Public instances whose security groups expose internet ingress; IMDSv2 not required (`EC2_IMDSV2_NOT_REQUIRED`). |
| VPC | Missing active VPC-level Flow Logs (`VPC_FLOW_LOGS_DISABLED`). |
| Lambda | Public unauthenticated Function URLs (`LAMBDA_PUBLIC_FUNCTION_URL`). |
| ECS | Services assigning public IPs (`ECS_SERVICE_PUBLIC_IP_ENABLED`); privileged containers in service task definitions (`ECS_PRIVILEGED_CONTAINER`). |
| Secrets Manager | Customer-managed secrets without automatic rotation (`SECRETSMANAGER_ROTATION_DISABLED`). |
| RDS | Public, unencrypted, under-backed-up, deletion-protection-disabled, or production non-Multi-AZ database instances (`RDS_PRODUCTION_NOT_MULTI_AZ`). |
| S3 | Public ACL/policy, Public Access Block, encryption, versioning, and access logging. |
| IAM | Root MFA, root access keys, password policy, old or unused access keys, console users without MFA, direct inline user policies, AdministratorAccess exposure. |
| Load balancing | Internet-facing Application and Network Load Balancers. |
| ECR | Scan-on-push settings. |
| KMS | Key rotation for eligible customer-managed keys. |
| Tags | Missing required tags on EC2 instances, EBS volumes, and RDS instances. |
| Baseline services | CloudTrail trails, log-file validation and KMS encryption (`CLOUDTRAIL_LOG_VALIDATION_DISABLED`, `CLOUDTRAIL_LOGS_NOT_KMS_ENCRYPTED`); AWS Config recorders; GuardDuty detectors; Security Hub; Access Analyzer external-access analyzers (`ACCESS_ANALYZER_EXTERNAL_ACCESS_DISABLED`) when explicitly selected. |

## Hygiene vs baseline checks

The default scan focuses on resource hygiene: public exposure, weak IAM posture, missing
encryption, missing backups, unused network resources, and required tag coverage.

Account baseline services are available when explicitly selected:

```bash
aws-security-auditor scan --services cloudtrail,config,guardduty,securityhub,accessanalyzer
```

CloudTrail, AWS Config, GuardDuty, Security Hub, and IAM Access Analyzer are important account
setup controls. Their absence is treated as a baseline/setup gap rather than a default resource
hygiene finding.

Public access, IAM risk, public snapshots, and similar direct risks are evaluated from AWS
resource configuration whether tags exist or not.
