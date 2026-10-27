"""[3]-[5] Enriched finding, input of the decision (AP-4)."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from .enums_common import VexStatus
from .enums_v1 import EvidenceGrade
from .enums_v2 import ExploitationState, ExposureLevel, ProtectionLevel, TechnicalImpact
from .findings import NormalizedFinding
from .signals import ExploitationSignals, ImpactSignals


class EnrichedFinding(BaseModel):
    """[3]-[5] Enriched finding.

    Attributes
    ----------
    finding : NormalizedFinding
        The normalised finding.
    exploitation : ExploitationSignals
        Exploitation signals.
    impact : ImpactSignals
        Impact signals.
    exposure_level : ExposureLevel or None
        Exposure of the vulnerable component.
    exploitation_state : ExploitationState or None
        Exploitation state (method 2).
    vex_status : VexStatus or None
        VEX status of the finding.
    evidence_grade : EvidenceGrade or None
        Evidence grade (method 1).
    technical_impact : TechnicalImpact or None
        Technical impact (method 2).
    protection_level : ProtectionLevel or None
        Protection need (method 2).
    defaults_applied : list[str]
        Defaults used for undetermined inputs, e.g. ``"exposure_level=remote (unbestimmt)"``.
    """

    finding: NormalizedFinding
    exploitation: ExploitationSignals = Field(default_factory=ExploitationSignals)
    impact: ImpactSignals = Field(default_factory=ImpactSignals)
    exposure_level: Optional[ExposureLevel] = None
    exploitation_state: Optional[ExploitationState] = None    # Verfahren 2

    vex_status: Optional[VexStatus] = None
    evidence_grade: Optional[EvidenceGrade] = None             # Verfahren 1
    technical_impact: Optional[TechnicalImpact] = None         # Verfahren 2
    protection_level: Optional[ProtectionLevel] = None         # Verfahren 2
    defaults_applied: list[str] = Field(default_factory=list)  # e.g. "exposure_level=remote (unbestimmt)"
