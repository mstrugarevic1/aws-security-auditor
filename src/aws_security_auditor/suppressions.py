from __future__ import annotations

import logging
from datetime import UTC, datetime

from aws_security_auditor.config import Suppression
from aws_security_auditor.models import Finding, SuppressedFinding

LOG = logging.getLogger(__name__)


def apply_suppressions(
    findings: list[Finding],
    suppressions: tuple[Suppression, ...],
    account_id: str,
) -> tuple[list[Finding], list[SuppressedFinding]]:
    active: list[Finding] = []
    suppressed: list[SuppressedFinding] = []
    for finding in findings:
        suppression = _match(finding, suppressions, account_id)
        if suppression:
            suppressed.append(
                SuppressedFinding(finding, suppression.reason, suppression.expires)
            )
        else:
            active.append(finding)
    return active, suppressed


def _match(
    finding: Finding, suppressions: tuple[Suppression, ...], account_id: str
) -> Suppression | None:
    today = datetime.now(UTC).date()
    for suppression in suppressions:
        if suppression.expires < today:
            if (
                suppression.check_id == finding.check_id
                and suppression.resource_id == finding.resource_id
            ):
                LOG.warning(
                    "expired suppression ignored: check_id=%s resource_id=%s expires=%s",
                    suppression.check_id,
                    suppression.resource_id,
                    suppression.expires.isoformat(),
                )
            continue
        if suppression.check_id != finding.check_id:
            continue
        if suppression.resource_id != finding.resource_id:
            continue
        if suppression.region is not None and suppression.region != finding.region:
            continue
        if suppression.account_id is not None and suppression.account_id != account_id:
            continue
        return suppression
    return None
