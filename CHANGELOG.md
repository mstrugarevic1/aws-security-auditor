# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `requirements.lock`: pinned transitive dependencies generated with pip-tools
  (`pip-compile`) for reproducible installs.
- `pip-audit` job in CI to scan locked dependencies for known vulnerabilities.
- Release workflow (`.github/workflows/release.yml`) that builds the package
  and attaches the sdist/wheel to a GitHub Release on version tags (`v*`).

### Changed
- CI installs dependencies against `requirements.lock` for reproducible runs.

## [0.1.0]

Initial version. Read-only AWS security scanner covering common security, cost,
and governance issues.

### Added
- Service checks: IAM, S3, EC2, VPC, network, RDS, Lambda, ECS,
  Secrets Manager, Access Analyzer, account, and tagging.
- Report formats: console, JSON, CSV, and Markdown.
- Slack notifier for findings.
- Finding suppressions and TOML configuration.
- Multi-region scanning.
