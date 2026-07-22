"""Backup retention audit — check if recent backups exist and are not stale.

Policy-light: checks backup metadata for recency and count.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from ..service import Service
from .base import AuditResult, Finding


def audit_backup_retention(service: Service, device_id: str) -> AuditResult:
    """Check backup file metadata for recency and retention.

    - PASS: at least 2 backups, most recent within 30 days.
    - WARN: backups exist but most recent is older than 30 days, or only 1 backup.
    - FAIL: no backups found.
    - UNKNOWN: backup data not available.
    """
    backups = service.get_backup_info(device_id)
    result = AuditResult(audit_name="backup_retention", device_id=device_id)

    if not backups:
        result.findings.append(
            Finding(
                status="unknown",
                severity="info",
                finding="No backup data available",
                recommendation="Verify backup metadata can be collected from this device",
                confidence="low",
            )
        )
        return result

    now = datetime.now(UTC)
    stale_threshold = now - timedelta(days=30)

    # Parse dates and find most recent
    dates: list[datetime] = []
    for b in backups:
        created = b.get("created", "")
        if created:
            try:
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=UTC)
                dates.append(dt)
            except (ValueError, TypeError):
                pass

    if not dates:
        result.findings.append(
            Finding(
                status="warn",
                severity="medium",
                finding=f"{len(backups)} backup(s) found but no parseable dates",
                evidence=[b.get("name", "unnamed") for b in backups],
                recommendation="Ensure backup timestamps are properly formatted",
                confidence="medium",
            )
        )
        return result

    most_recent = max(dates)
    evidences: list[str] = [
        f"most_recent: {most_recent.strftime('%Y-%m-%d')}",
        f"total_backups: {len(backups)}",
    ]

    if most_recent < stale_threshold and len(backups) < 2:
        result.findings.append(
            Finding(
                status="warn",
                severity="high",
                finding="Backups are stale and retention is insufficient",
                evidence=evidences,
                recommendation="Create a recent backup and configure automatic backup retention (at least 2 recent copies)",
                confidence="high",
            )
        )
        return result

    if most_recent < stale_threshold:
        result.findings.append(
            Finding(
                status="warn",
                severity="medium",
                finding="Most recent backup is older than 30 days",
                evidence=evidences,
                recommendation="Schedule regular backups — weekly is recommended for critical devices",
                confidence="high",
            )
        )
        return result

    if len(backups) < 2:
        result.findings.append(
            Finding(
                status="warn",
                severity="low",
                finding="Only 1 backup found — retention is minimal",
                evidence=evidences,
                recommendation="Maintain at least 2 recent backups for safe rollback",
                confidence="high",
            )
        )
        return result

    result.findings.append(
        Finding(
            status="pass",
            severity="info",
            finding="Backup retention is adequate",
            evidence=evidences,
            confidence="high",
        )
    )
    return result
