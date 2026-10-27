"""[6] Result: priority level with rationale (traceability)."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel

from .enums_common import CvssSeverity, EnrichmentStatus, PrioritizationMethod, PriorityLevel
from .enums_v1 import CvssBand, EvidenceGrade
from .enums_v2 import ExploitationState, ExposureLevel, ProtectionLevel, TechnicalImpact


class PrioritizationResult(BaseModel):
    """[6] Result: priority level with rationale (traceability).

    Attributes
    ----------
    title : str
        Title of the finding.
    cve_id, euvd_id : str or None
        Identifiers of the finding.
    enrichment_status : EnrichmentStatus
        Enrichment path of the finding.
    method : PrioritizationMethod
        Method used for the decision.
    evidence_grade, cvss_band : optional
        Inputs of method 1 (with CVE).
    exploitation_state, technical_impact, protection_level : optional
        Inputs of method 2 (without CVE).
    exposure_level : ExposureLevel or None
        Exposure of the vulnerable component.
    cvss_severity : CvssSeverity or None
        Coarse CVSS rating of the finding.
    priority : PriorityLevel
        Decided priority level.
    priority_rank : int or None
        Rank from the rule table, None if the table was not used.
    epss_threshold_used : float or None
        EPSS threshold applied for the evidence grade.
    cvss_only_rank_severity : CvssSeverity or None
        Comparison baseline: plain CVSS sorting.
    decision_note : str
        Human-readable rationale of the decision.
    finding_id, location, scanner, report_type, source_file, source_line, source_id : optional
        Reference to the input finding (CI output, Code Quality report); not
        part of the CSV export. `finding_id` is ``rule:path`` or ``CVE:package``;
        `report_type` is one of sast, dependency_scanning, container_scanning,
        inventory; `source_file` is the file named in the report (SAST: location,
        DS: manifest); `source_id` is the ID of the vulnerability in the GitLab report.
    cvss_base_score : float or None
        CVSS base score used.
    cvss_source : str or None
        Origin of the CVSS base score.
    """

    title: str
    cve_id: Optional[str] = None
    euvd_id: Optional[str] = None
    enrichment_status: EnrichmentStatus
    method: PrioritizationMethod

    # Method 1 (with CVE)
    evidence_grade: Optional[EvidenceGrade] = None
    cvss_band: Optional[CvssBand] = None

    # Method 2 (without CVE)
    exploitation_state: Optional[ExploitationState] = None
    technical_impact: Optional[TechnicalImpact] = None
    protection_level: Optional[ProtectionLevel] = None

    exposure_level: Optional[ExposureLevel] = None
    cvss_severity: Optional[CvssSeverity] = None
    priority: PriorityLevel
    priority_rank: Optional[int] = None
    epss_threshold_used: Optional[float] = None
    cvss_only_rank_severity: Optional[CvssSeverity] = None  # comparison baseline: plain CVSS sorting
    decision_note: str = ""

    # Reference to the input finding (CI output, Code Quality report); not part of the CSV export
    finding_id: Optional[str] = None       # identifier (rule:path or CVE:package)
    location: Optional[str] = None
    scanner: Optional[str] = None
    report_type: Optional[str] = None      # sast, dependency_scanning, container_scanning, inventory
    cvss_base_score: Optional[float] = None
    cvss_source: Optional[str] = None
    source_file: Optional[str] = None      # file according to the report (SAST: location, DS: manifest)
    source_line: Optional[int] = None
    source_id: Optional[str] = None        # ID of the vulnerability in the GitLab report
