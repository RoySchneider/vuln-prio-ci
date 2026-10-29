import pytest

from vuln_prio_ci.decide.priority import choose_method, decide_priority
from vuln_prio_ci.decide.table import CVE_TABLE, CVSS_TABLE, RuleMissError
from vuln_prio_ci.models import (
    CvssBand,
    CvssSeverity,
    EnrichedFinding,
    EnrichmentStatus,
    EvidenceGrade,
    ExploitationState,
    ExposureLevel,
    ImpactSignals,
    NormalizedFinding,
    PrioritizationMethod,
    PriorityLevel,
    ProtectionLevel,
    RawFinding,
    TechnicalImpact,
)


def _v1_finding(evidence_grade, cvss_band) -> EnrichedFinding:
    norm = NormalizedFinding(
        title="t",
        cve_id="CVE-2026-0001",
        enrichment_status=EnrichmentStatus.resolved,
        source=RawFinding(title="t"),
    )
    return EnrichedFinding(
        finding=norm,
        evidence_grade=evidence_grade,
        impact=ImpactSignals(cvss_band=cvss_band),
    )


def _v2_finding(exploitation, exposure, impact, protection) -> EnrichedFinding:
    norm = NormalizedFinding(title="t", enrichment_status=EnrichmentStatus.cve_less, source=RawFinding(title="t"))
    return EnrichedFinding(
        finding=norm,
        exploitation_state=exploitation,
        exposure_level=exposure,
        technical_impact=impact,
        protection_level=protection,
    )


def test_choose_method_resolved_is_v1():
    assert choose_method(_v1_finding(EvidenceGrade.e1, CvssBand.c1)) == PrioritizationMethod.cve_signals


def test_choose_method_cve_less_is_v2():
    finding = _v2_finding(ExploitationState.none, ExposureLevel.lokal, TechnicalImpact.partial, ProtectionLevel.normal)
    assert choose_method(finding) == PrioritizationMethod.ssvc_developer


@pytest.mark.parametrize(
    "grade,band,expected_priority,expected_rank",
    [
        (EvidenceGrade.e1, CvssBand.c1, PriorityLevel.deferred, 1),
        (EvidenceGrade.e1, CvssBand.c3, PriorityLevel.planned, 5),
        (EvidenceGrade.e5, CvssBand.c1, PriorityLevel.planned, 9),
        (EvidenceGrade.e3, CvssBand.c2, PriorityLevel.urgent, 10),
        (EvidenceGrade.e6, CvssBand.c3, PriorityLevel.immediate, 18),
    ],
)
def test_decide_priority_v1_one_example_per_category(grade, band, expected_priority, expected_rank):
    result = decide_priority(_v1_finding(grade, band))
    assert result.method == PrioritizationMethod.cve_signals
    assert result.priority == expected_priority
    assert result.priority_rank == expected_rank


@pytest.mark.parametrize(
    "exploitation,exposure,impact,protection,expected_priority,expected_rank",
    [
        (ExploitationState.none, ExposureLevel.lokal, TechnicalImpact.partial, ProtectionLevel.normal, PriorityLevel.deferred, 1),
        (ExploitationState.none, ExposureLevel.lokal, TechnicalImpact.partial, ProtectionLevel.very_high, PriorityLevel.planned, 6),
        (ExploitationState.none, ExposureLevel.intern, TechnicalImpact.total, ProtectionLevel.very_high, PriorityLevel.urgent, 28),
        (ExploitationState.active, ExposureLevel.remote, TechnicalImpact.total, ProtectionLevel.very_high, PriorityLevel.immediate, 54),
    ],
)
def test_decide_priority_v2_one_example_per_category(exploitation, exposure, impact, protection, expected_priority, expected_rank):
    result = decide_priority(_v2_finding(exploitation, exposure, impact, protection))
    assert result.method == PrioritizationMethod.ssvc_developer
    assert result.priority == expected_priority
    assert result.priority_rank == expected_rank


@pytest.mark.parametrize(
    "grade,expected_priority",
    [
        (EvidenceGrade.e6, PriorityLevel.immediate),
        (EvidenceGrade.e5, PriorityLevel.immediate),
        (EvidenceGrade.e4, PriorityLevel.urgent),
        (EvidenceGrade.e3, PriorityLevel.urgent),
        (EvidenceGrade.e2, PriorityLevel.planned),
        (EvidenceGrade.e1, PriorityLevel.planned),
    ],
)
def test_v1_missing_cvss_band_falls_back_to_grade_only(grade, expected_priority):
    result = decide_priority(_v1_finding(grade, None))
    assert result.priority == expected_priority
    assert result.priority_rank is None
    assert "Neubewertung" in result.decision_note


def test_v1_missing_dimensions_raises():
    with pytest.raises(ValueError):
        decide_priority(_v1_finding(None, None))


def test_v2_missing_dimensions_raises():
    with pytest.raises(ValueError):
        decide_priority(_v2_finding(None, None, None, None))


def test_rule_miss_raises_rule_miss_error():
    with pytest.raises(RuleMissError):
        CVE_TABLE.lookup(("nonexistent", "c1"))


@pytest.mark.parametrize(
    "score,severity,expected_priority,expected_rank",
    [
        (0.0, CvssSeverity.none, PriorityLevel.deferred, 1),
        (3.9, CvssSeverity.low, PriorityLevel.deferred, 2),
        (6.9, CvssSeverity.medium, PriorityLevel.planned, 3),
        (7.0, CvssSeverity.high, PriorityLevel.urgent, 4),
        (9.8, CvssSeverity.critical, PriorityLevel.immediate, 5),
    ],
)
def test_cvss_method_uses_base_score_alone(score, severity, expected_priority, expected_rank):
    finding = _v1_finding(EvidenceGrade.e6, CvssBand.c3)   # Nachweisgrad zählt nicht
    finding.impact = ImpactSignals(cvss_base_score=score, cvss_severity=severity, cvss_source="NVD Primary 3.1")
    result = decide_priority(finding, cvss_method=True)
    assert result.method == PrioritizationMethod.cvss_only
    assert result.priority == expected_priority
    assert result.priority_rank == expected_rank
    assert result.decision_note == f"CVSS-Verfahren[Schwere={severity.value}]; CVSS {score:.1f} (NVD Primary 3.1)."


def test_cvss_method_without_base_score_raises():
    finding = _v1_finding(EvidenceGrade.e6, None)
    finding.impact = ImpactSignals(cvss_severity=CvssSeverity.critical)   # nur GitLab-Schwere
    with pytest.raises(ValueError, match="CVSS-Basiswert"):
        decide_priority(finding, cvss_method=True)


def test_cvss_rule_miss_raises_rule_miss_error():
    with pytest.raises(RuleMissError):
        CVSS_TABLE.lookup(("nonexistent",))
