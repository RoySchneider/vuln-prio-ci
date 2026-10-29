"""Scales shared by both methods: status, method choice, priority.

The codes correspond to the reference tables in db/seed_reference.sql.
"""

from __future__ import annotations

from enum import Enum


class EnrichmentStatus(str, Enum):
    """Enrichment status of a finding.

    Attributes
    ----------
    resolved
        CVE present/resolved, full signal coverage.
    cve_less
        No resolvable CVE (reduced evidence).
    pending
        Not enriched yet.
    """

    resolved = "resolved"      # CVE present/resolved, full signal coverage
    cve_less = "cve_less"      # no resolvable CVE (reduced evidence)
    pending = "pending"        # not enriched yet


class VexStatus(str, Enum):
    """VEX status of a finding."""

    not_affected = "not_affected"
    affected = "affected"
    under_investigation = "under_investigation"
    fixed = "fixed"


class PrioritizationMethod(str, Enum):
    """Prioritisation method.

    Attributes
    ----------
    cve_signals
        Method 1 (with CVE).
    ssvc_developer
        Method 2 (without CVE).
    cvss_only
        CVSS method: CVSS base score alone, only for single CVEs in the terminal
        (``--cve ... --cvss-method``).
    """

    cve_signals = "cve_signals"        # method 1 (with CVE)
    ssvc_developer = "ssvc_developer"  # method 2 (without CVE)
    cvss_only = "cvss_only"            # CVSS method (base score alone)


class PriorityLevel(str, Enum):
    """Priority level, from lowest to highest: deferred, planned, urgent, immediate."""

    deferred = "deferred"     # postponed
    planned = "planned"       # planned
    urgent = "urgent"         # urgent
    immediate = "immediate"   # immediate


class CvssSeverity(str, Enum):
    """Coarse CVSS rating used as the comparison baseline (plain CVSS sorting, AP-8.6)."""

    none = "none"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"
