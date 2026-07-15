# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-15

Initial release. Read-only AWS security scanner covering common security, cost,
and governance issues.

### Added
- Service checks: IAM, S3, EC2, VPC, network, RDS, Lambda, ECS,
  Secrets Manager, Access Analyzer, account, and tagging.
- Report formats: console, JSON, CSV, and Markdown.
- Slack notifier for findings.
- Finding suppressions and TOML configuration.
- Multi-region scanning.

[Unreleased]: https://github.com/mstrugarevic1/aws-security-auditor/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mstrugarevic1/aws-security-auditor/releases/tag/v0.1.0
