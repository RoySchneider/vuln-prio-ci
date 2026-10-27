"""[1][2] Finding before and after identifier normalisation."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field

from .enums_common import EnrichmentStatus, VexStatus
from .enums_v2 import ExploitationState, ExposureLevel, ProtectionLevel, ProtectionNeed, TechnicalImpact


class RawFinding(BaseModel):
    """[1] Raw finding from the GitLab/Semgrep export, before normalisation.

    The dimensions of the SSVC developer tree (exposure, VEX, exploitation state, technical
    impact, damage extent) are analyst assessments per finding that no scanner provides;
    they are optional here and are taken over by the pipeline (AP-5) when set.

    Attributes
    ----------
    title : str
        Title of the finding.
    description : str or None
        Description from the report.
    scanner : str or None
        Name of the scanner.
    gitlab_severity : str or None
        Severity label assigned by GitLab.
    cwe : str or None
        CWE identifier.
    location : str or None
        Location such as ``file:line``.
    identifiers : list[str]
        Identifiers from the report; may contain CVE/EUVD/GHSA/CWE.
    raw : dict
        Original report entry.
    vex_status : VexStatus or None
        VEX status.
    exposure_level : ExposureLevel or None
        Exposure of the vulnerable component.
    exploitation_state : ExploitationState or None
        Exploitation state (method 2).
    technical_impact : TechnicalImpact or None
        Technical impact (method 2).
    business_impact_levels : dict[ProtectionNeed, int]
        Damage extent (1..5) per protection goal (method 2, AP-6); the protection
        need is the maximum over them. Empty means undetermined (default
        ``very_high``, AP-5).
    protection_level : ProtectionLevel or None
        Protection need given directly, e.g. from the assessment file in the
        repository. Takes precedence over `business_impact_levels`; if empty,
        it is derived or defaults to ``very_high``.
    """

    title: str
    description: Optional[str] = None
    scanner: Optional[str] = None
    gitlab_severity: Optional[str] = None
    cwe: Optional[str] = None
    location: Optional[str] = None            # file:line or similar
    identifiers: list[str] = Field(default_factory=list)  # may contain CVE/EUVD/GHSA/CWE
    raw: dict = Field(default_factory=dict)

    vex_status: Optional[VexStatus] = None
    exposure_level: Optional[ExposureLevel] = None
    exploitation_state: Optional[ExploitationState] = None       # method 2
    technical_impact: Optional[TechnicalImpact] = None           # method 2
    # Damage extent (1..5) per protection goal (method 2, AP-6); protection need = maximum over them.
    # Empty -> undetermined (default very_high, AP-5).
    business_impact_levels: dict[ProtectionNeed, int] = Field(default_factory=dict)
    # Protection need given directly (normal/high/very_high), e.g. from the assessment file in the repository.
    # Takes precedence over business_impact_levels; empty -> derivation or default very_high.
    protection_level: Optional[ProtectionLevel] = None


class NormalizedFinding(BaseModel):
    """[2] Finding with determined identifier and CVE status.

    Attributes
    ----------
    title : str
        Title of the finding.
    cve_id, euvd_id, ghsa_id : str or None
        Identifiers extracted from the report, in upper case.
    cwe : str or None
        CWE identifier.
    finding_fingerprint : str or None
        Stable identity of a CVE-less finding, None if a CVE is present.
    cve_present : bool
        Whether a CVE ID was found.
    enrichment_status : EnrichmentStatus
        Enrichment path of the finding.
    source : RawFinding
        The raw finding this one was derived from.
    """

    title: str
    cve_id: Optional[str] = None
    euvd_id: Optional[str] = None
    ghsa_id: Optional[str] = None
    cwe: Optional[str] = None
    finding_fingerprint: Optional[str] = None
    cve_present: bool = False
    enrichment_status: EnrichmentStatus = EnrichmentStatus.pending
    source: RawFinding
