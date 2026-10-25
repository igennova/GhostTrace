"""Tests for recreation-risk detection (active sync and restore paths).

Covers: an enabled connector that can resurrect data flags an active data flow,
a disabled connector does not, a restorable backup flags a restore risk, and a
restore-blocked backup does not.
"""

from __future__ import annotations


def test_enabled_connector_flags_active_data_flow() -> None:
    """An enabled sync connector for the subject is reported as active."""
    raise NotImplementedError


def test_disabled_connector_is_not_flagged() -> None:
    """A disabled connector is not reported as a recreation risk."""
    raise NotImplementedError


def test_restorable_backup_flags_restore_risk() -> None:
    """A backup whose restore is allowed is reported as a restore risk."""
    raise NotImplementedError
