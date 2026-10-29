"""[6] Decision -> priority level, rank and rationale (method 1/2).

Replaces the decision core of decide/ssvc.py (implementation plan AP-4). `_impact_level` is dropped
without replacement: protection need and CVSS are no longer mixed into one impact level, and each
method has its own fixed key into its rule table (table.py).
"""

from __future__ import annotations

from typing import Optional

from ..models import (
    EnrichedFinding,
    EnrichmentStatus,
    EvidenceGrade,
    ExploitationSignals,
    PrioritizationMethod,
    PrioritizationResult,
    PriorityLevel,
)
from .table import CVE_TABLE, CVELESS_TABLE, CVSS_TABLE

# Missing CVSS base score (method 1): classification by evidence grade alone (implementation plan AP-5).
_MISSING_CVSS_PRIORITY = {
    EvidenceGrade.e6: PriorityLevel.immediate,
    EvidenceGrade.e5: PriorityLevel.immediate,
    EvidenceGrade.e4: PriorityLevel.urgent,
    EvidenceGrade.e3: PriorityLevel.urgent,
    EvidenceGrade.e2: PriorityLevel.planned,
    EvidenceGrade.e1: PriorityLevel.planned,
}


def choose_method(enriched: EnrichedFinding) -> PrioritizationMethod:
    """Choose the prioritisation method: CVE resolved -> method 1 (with CVE), otherwise method 2 (without CVE).

    Parameters
    ----------
    enriched : EnrichedFinding
        The enriched finding.

    Returns
    -------
    PrioritizationMethod
        ``cve_signals`` (method 1) or ``ssvc_developer`` (method 2).
    """
    if enriched.finding.enrichment_status == EnrichmentStatus.resolved:
        return PrioritizationMethod.cve_signals
    return PrioritizationMethod.ssvc_developer


def decide_priority(enriched: EnrichedFinding, cvss_method: bool = False) -> PrioritizationResult:
    """Decide the priority level and rank of an enriched finding.

    Parameters
    ----------
    enriched : EnrichedFinding
        The enriched finding with all inputs of its method.
    cvss_method : bool, optional
        Decide by the CVSS base score alone (CVSS method) instead of method 1/2.

    Returns
    -------
    PrioritizationResult
        Priority level, rank and decision note together with the inputs used.

    Raises
    ------
    ValueError
        If an input required by the chosen method is missing.
    RuleMissError
        If the rule table has no row for the derived key.
    """
    method = PrioritizationMethod.cvss_only if cvss_method else choose_method(enriched)
    if method is PrioritizationMethod.cvss_only:
        priority, rank, note = _decide_cvss(enriched)
    elif method is PrioritizationMethod.cve_signals:
        priority, rank, note = _decide_v1(enriched)
    else:
        priority, rank, note = _decide_v2(enriched)

    finding = enriched.finding
    return PrioritizationResult(
        title=finding.title,
        cve_id=finding.cve_id,
        euvd_id=finding.euvd_id,
        enrichment_status=finding.enrichment_status,
        method=method,
        evidence_grade=enriched.evidence_grade,
        cvss_band=enriched.impact.cvss_band,
        exploitation_state=enriched.exploitation_state,
        technical_impact=enriched.technical_impact,
        protection_level=enriched.protection_level,
        exposure_level=enriched.exposure_level,
        cvss_severity=enriched.impact.cvss_severity,
        priority=PriorityLevel(priority),
        priority_rank=rank,
        cvss_only_rank_severity=enriched.impact.cvss_severity,
        decision_note=note,
    )


def _decide_v1(enriched: EnrichedFinding) -> tuple[str, Optional[int], str]:
    """Decide according to method 1 (evidence grade x CVSS range).

    Parameters
    ----------
    enriched : EnrichedFinding
        Finding with an evidence grade. The CVSS range may be missing.

    Returns
    -------
    priority : str
        Priority level code.
    rank : int or None
        Rank from the rule table, None if the CVSS range is missing.
    note : str
        Human-readable decision note.

    Raises
    ------
    ValueError
        If the evidence grade is missing.
    """
    grade = enriched.evidence_grade
    band = enriched.impact.cvss_band
    if grade is None:
        raise ValueError("Verfahren 1 benötigt evidence_grade auf EnrichedFinding")

    if band is None:
        # No CVSS base score: classify by evidence grade alone, no table rank (AP-5).
        level = _MISSING_CVSS_PRIORITY[grade]
        rule = f"Verfahren 1[Nachweisgrad={grade.value}, CVSS-Bereich=fehlt]"
        note = _build_note(rule, enriched.exploitation)
        return level.value, None, f"{note} Kein CVSS-Basiswert: Einordnung nach Nachweisgrad allein, zur Neubewertung markiert."

    priority, rank = CVE_TABLE.lookup((grade.value, band.value))
    rule = f"Verfahren 1[Nachweisgrad={grade.value}, CVSS-Bereich={band.value}]"
    note = _build_note(rule, enriched.exploitation)
    impact = enriched.impact
    if impact.cvss_base_score is not None and impact.cvss_source:
        note += f" CVSS {impact.cvss_base_score:.1f} ({impact.cvss_source})."
    return priority, rank, note


def _decide_v2(enriched: EnrichedFinding) -> tuple[str, Optional[int], str]:
    """Decide according to method 2 (exploitation x exposure x impact x protection need).

    Parameters
    ----------
    enriched : EnrichedFinding
        Finding with exploitation state, exposure level, technical impact and
        protection level.

    Returns
    -------
    priority : str
        Priority level code.
    rank : int
        Rank from the rule table.
    note : str
        Human-readable decision note (the applied rule).

    Raises
    ------
    ValueError
        If one of the four inputs is missing.
    """
    exploitation = enriched.exploitation_state
    exposure = enriched.exposure_level
    impact = enriched.technical_impact
    protection = enriched.protection_level
    if None in (exploitation, exposure, impact, protection):
        raise ValueError(
            "Verfahren 2 benötigt exploitation_state, exposure_level, technical_impact "
            "und protection_level auf EnrichedFinding"
        )

    priority, rank = CVELESS_TABLE.lookup((exploitation.value, exposure.value, impact.value, protection.value))
    rule = (
        f"Verfahren 2[Ausnutzung={exploitation.value}, Erreichbarkeit={exposure.value}, "
        f"Auswirkung={impact.value}, Schutzbedarf={protection.value}]"
    )
    return priority, rank, rule


def _decide_cvss(enriched: EnrichedFinding) -> tuple[str, int, str]:
    """Decide according to the CVSS method (qualitative severity of the CVSS base score alone).

    Parameters
    ----------
    enriched : EnrichedFinding
        Finding with a CVSS base score. The GitLab severity does not count as one.

    Returns
    -------
    priority : str
        Priority level code.
    rank : int
        Rank from the rule table.
    note : str
        Human-readable decision note (the applied rule and the base score).

    Raises
    ------
    ValueError
        If the CVSS base score is missing.
    """
    impact = enriched.impact
    if impact.cvss_base_score is None or impact.cvss_severity is None:
        raise ValueError("CVSS-Verfahren benötigt einen CVSS-Basiswert")
    priority, rank = CVSS_TABLE.lookup((impact.cvss_severity.value,))
    note = f"CVSS-Verfahren[Schwere={impact.cvss_severity.value}]; CVSS {impact.cvss_base_score:.1f}"
    if impact.cvss_source:
        note += f" ({impact.cvss_source})"
    return priority, rank, note + "."


def _build_note(rule: str, e: ExploitationSignals) -> str:
    """Build the decision note from the applied rule and the exploitation signals.

    Parameters
    ----------
    rule : str
        Description of the applied rule.
    e : ExploitationSignals
        Signals to list, with the snapshot each one comes from.

    Returns
    -------
    str
        The rule followed by the signals found, or "keine externen" if none.
    """
    signals = []
    if e.kev_listed:
        signals.append("KEV")
    if e.metasploit_commit:
        modules = ", ".join(e.metasploit_modules) or "keine"
        signals.append(f"Metasploit={modules} (Stand {e.metasploit_commit[:8]})")
    if e.exploit_db_commit:
        ids = ", ".join(f"EDB-{i}" for i in e.exploit_db_ids) or "keine"
        signals.append(f"Exploit-DB={ids} (Stand {e.exploit_db_commit[:8]})")
    if e.epss_as_of:
        value = f"{e.epss_score:.5f}" if e.epss_score is not None else "unbekannt"
        signals.append(f"EPSS={value} (Modell {e.epss_model_version or 'unbekannt'}, Stand {e.epss_as_of})")
    return f"{rule}; Signale: {', '.join(signals) or 'keine externen'}."
