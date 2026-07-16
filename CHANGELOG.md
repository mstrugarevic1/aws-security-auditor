# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-07-16

### Added
- `--version`, `list-checks`, and `list-services` CLI commands.
- Config-file defaults for regions, excluded regions, services, output format, severity, fail threshold, age thresholds, and worker count.
- Documented CLI exit codes.

### Fixed
- `--output table --output-file` now writes table text instead of Markdown.
- Operational setup errors now exit with code `2`.

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

[Unreleased]: https://github.com/mstrugarevic1/aws-security-auditor/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/mstrugarevic1/aws-security-auditor/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/mstrugarevic1/aws-security-auditor/releases/tag/v0.1.0
