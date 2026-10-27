"""Pydantic schemas and ordinal scales of the prioritisation.

Ordinal framing: priority level instead of a numeric value.

Split by domain so that each file stays small and tied to one concept:
  enums_common - status/method/priority, shared by both methods
  enums_v1     - method 1 (with CVE): evidence grade, CVSS range
  enums_v2     - method 2 (without CVE): exploitation state, exposure, impact, protection need
  findings     - raw/normalised finding [1][2]
  signals      - input signals exploitation/impact [3][4]
  enriched     - enriched finding [3]-[5]
  results      - prioritisation result [6]
"""

from __future__ import annotations

from .enriched import EnrichedFinding
from .enums_common import (
    CvssSeverity,
    EnrichmentStatus,
    PrioritizationMethod,
    PriorityLevel,
    VexStatus,
)
from .enums_v1 import CvssBand, EvidenceGrade
from .enums_v2 import ExploitationState, ExposureLevel, ProtectionLevel, ProtectionNeed, TechnicalImpact
from .findings import NormalizedFinding, RawFinding
from .results import PrioritizationResult
from .signals import ExploitationSignals, ImpactSignals

__all__ = [
    "CvssBand",
    "CvssSeverity",
    "EnrichedFinding",
    "EnrichmentStatus",
    "EvidenceGrade",
    "ExploitationSignals",
    "ExploitationState",
    "ExposureLevel",
    "ImpactSignals",
    "NormalizedFinding",
    "PrioritizationMethod",
    "PrioritizationResult",
    "PriorityLevel",
    "ProtectionLevel",
    "ProtectionNeed",
    "RawFinding",
    "TechnicalImpact",
    "VexStatus",
]
