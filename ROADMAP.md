# Roadmap

This roadmap describes direction, not commitments. Items may change, move
between sections, or be dropped. There are no dates or fixed version numbers.

## Completed

- Fix inconsistent behavior when using `--output table` together with `--output-file`.
- Standardize configuration precedence:

  ```text
  CLI arguments > configuration file > application defaults
  ```

- Add or improve tests for:
  - output formats
  - configuration precedence
  - AWS API errors
  - invalid profiles and regions
- Add:
  - `--version`
  - `list-checks`
  - `list-services`
- Improve exit codes for CI usage.

## Next

- Keep check coverage focused on common, high-signal AWS posture issues.

## Later

- Add finding filters by:
  - severity
  - service
  - check ID
  - region
- Add baseline and diff scanning.
- Support:
  - new findings
  - resolved findings
  - unchanged findings
- Use a stable finding identity based on:

  ```text
  account ID + region + check ID + resource ID
  ```

- Allow CI to fail only when new findings exceed a configured severity threshold.
- Add EKS security checks, including:
  - public API endpoint
  - unrestricted public endpoint CIDRs
  - disabled control-plane logging
  - missing secrets encryption
  - node group remote access
  - unsupported Kubernetes versions

## Future Considerations

- Optional Dockerfile and container runtime support.
- GitHub Container Registry publishing only if there is a real use case.
- AWS Organizations multi-account scanning.
- SARIF output.
- HTML reports.
- Security Hub integration.
- Suppression expiration dates.
- Scheduled ECS or Kubernetes execution examples.
- Additional AWS service checks based on actual user needs.

## Non-Goals

This project should not become:

- an automatic remediation tool;
- a replacement for AWS Config or Security Hub;
- an unnecessarily complex plugin framework;
- a large collection of shallow, untested checks;
- a container publishing project without an actual container use case.
