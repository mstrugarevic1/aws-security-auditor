# Roadmap

This roadmap describes direction, not commitments. Items may move, change, or be dropped.

## Priority

| Priority | Meaning |
| --- | --- |
| `P1` | High value, likely next. |
| `P2` | Useful, but not blocking current users. |
| `P3` | Nice to have; only build with a clear use case. |

## Planned

| Priority | Area | Item | Why it matters |
| --- | --- | --- | --- |
| `P1` | Findings | Add filters by severity, service, check ID, and region. | Makes large reports usable without changing scan behavior. |
| `P1` | CI | Fail only when new findings exceed a configured severity threshold. | Lets teams prevent regressions without failing forever on known findings. |
| `P1` | State | Add baseline and diff scanning. | Separates new, resolved, and unchanged findings. |
| `P1` | State | Use stable finding identity: account ID, region, check ID, resource ID. | Required for reliable baseline comparisons. |
| `P2` | Checks | Add EKS checks for public API endpoints, endpoint CIDRs, control-plane logging, secrets encryption, node remote access, and unsupported versions. | EKS misconfiguration is common and high-signal. |
| `P2` | Output | Add SARIF output. | Useful for GitHub code-scanning style workflows. |
| `P2` | Output | Add HTML reports. | Easier to share with non-CLI users. |
| `P3` | Accounts | Add AWS Organizations multi-account scanning. | Useful for larger estates, but adds auth and runtime complexity. |
| `P3` | Runtime | Add scheduled ECS or Kubernetes execution examples. | Helpful only if users actually run it on a schedule. |

## Check Selection Rule

New checks should catch common AWS risks with low false-positive noise. Prefer checks that identify
direct exposure, weak identity posture, missing encryption, missing backups, or expensive unused
resources. Avoid shallow compliance-only checks unless users ask for them.

## Completed

- [x] Output: fixed `--output table --output-file` to write table text instead of Markdown.
- [x] Config: standardized precedence: CLI arguments, then config file, then application defaults.
- [x] CLI: added `--version`, `list-checks`, and `list-services`.
- [x] CI: improved exit codes for automation.
- [x] Tests: added coverage for output formats, config precedence, AWS API errors, invalid profiles, and invalid regions.

## Not Planned

| Item | Reason |
| --- | --- |
| Automatic remediation | The tool is intentionally read-only. |
| Replacement for AWS Config, Security Hub, Prowler, or a formal assessment | This project is a focused snapshot scanner. |
| Plugin framework | Adds complexity before there is a clear extension model. |
| Large collection of shallow checks | More checks are not useful if they create noise. |
| Container publishing | Add only if there is a real container runtime use case. |
| Security Hub integration | Useful later, but not needed for the current CLI workflow. |
