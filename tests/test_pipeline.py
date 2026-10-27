"""Pipeline-Orchestrierung (AP-5-Akzeptanz): Verfahrenswahl, VEX, Vorbelegungen.

Hermetisch: EPSS/Exploit-DB/Metasploit/KEV/EUVD werden gestubbt, damit die Tests weder Netzzugriff
noch einen befüllten Referenzdatenspeicher (cache/reference.sqlite) benötigen.
"""

from __future__ import annotations

import pytest

from vuln_prio_ci import pipeline
from vuln_prio_ci.models import (
    EnrichedFinding,
    EnrichmentStatus,
    ExploitationState,
    ExposureLevel,
    NormalizedFinding,
    PrioritizationMethod,
    ProtectionLevel,
    RawFinding,
    TechnicalImpact,
    VexStatus,
)

# EPSS/Exploit-DB/Metasploit/KEV/EUVD sind über tests/conftest.py gestubbt (nur in dieser Datei).
pytestmark = pytest.mark.usefixtures("stub_external_sources")


def _norm(**kwargs) -> NormalizedFinding:
    return NormalizedFinding(
        title="t", enrichment_status=EnrichmentStatus.cve_less, source=RawFinding(title="t"), **kwargs
    )


# --- Verfahrenswahl --------------------------------------------------------

def test_finding_with_cve_uses_v1():
    findings = [RawFinding(title="t", identifiers=["CVE-2026-0001"], raw={"cvss_base_score": 9.8})]
    [result] = pipeline.prioritize_findings(findings)
    assert result.method == PrioritizationMethod.cve_signals
    assert result.cve_id == "CVE-2026-0001"


def test_pure_sast_finding_uses_v2():
    findings = [
        RawFinding(
            title="SQLi",
            exploitation_state=ExploitationState.none,
            exposure_level=ExposureLevel.intern,
            technical_impact=TechnicalImpact.partial,
        )
    ]
    [result] = pipeline.prioritize_findings(findings)
    assert result.method == PrioritizationMethod.ssvc_developer
    assert result.cve_id is None


def test_euvd_finding_resolves_to_cve_uses_v1(monkeypatch):
    monkeypatch.setattr(pipeline.euvd, "cve_for_euvd", lambda euvd_id: "CVE-2026-9999")
    findings = [RawFinding(title="t", identifiers=["EUVD-2026-1234"], raw={"cvss_base_score": 5.0})]
    [result] = pipeline.prioritize_findings(findings)
    assert result.method == PrioritizationMethod.cve_signals
    assert result.cve_id == "CVE-2026-9999"


# --- VEX-Vorschaltung -------------------------------------------------------

def test_not_affected_produces_no_result():
    findings = [RawFinding(title="t", identifiers=["CVE-2026-0001"], vex_status=VexStatus.not_affected)]
    assert pipeline.prioritize_findings(findings) == []


def test_fixed_produces_no_result():
    findings = [RawFinding(title="t", identifiers=["CVE-2026-0001"], vex_status=VexStatus.fixed)]
    assert pipeline.prioritize_findings(findings) == []


def test_under_investigation_is_treated_like_affected():
    findings = [
        RawFinding(
            title="t",
            identifiers=["CVE-2026-0001"],
            vex_status=VexStatus.under_investigation,
            raw={"cvss_base_score": 9.8},
        )
    ]
    results = pipeline.prioritize_findings(findings)
    assert len(results) == 1


# --- Robustheit: ein nicht entscheidbarer Befund darf den Lauf nicht abbrechen -------------

def test_undecidable_finding_is_skipped_not_fatal():
    findings = [
        RawFinding(title="CVE-Befund", identifiers=["CVE-2026-0001"], raw={"cvss_base_score": 9.8}),
        RawFinding(title="SAST ohne SSVC-Angaben"),   # Verfahren 2, keine Dimensionen mitgeliefert
    ]
    results = pipeline.prioritize_findings(findings)
    assert [r.title for r in results] == ["CVE-Befund"]


# --- Vorbelegungen (defaults_applied) --------------------------------------

def test_apply_exposure_defaults_and_tracks_when_unset():
    enriched = EnrichedFinding(finding=_norm())
    raw = RawFinding(title="t")
    pipeline._apply_exposure(enriched, raw, ExposureLevel.remote)
    assert enriched.exposure_level == ExposureLevel.remote
    assert "exposure_level=remote (unbestimmt)" in enriched.defaults_applied


def test_apply_exposure_uses_explicit_value_without_default():
    enriched = EnrichedFinding(finding=_norm())
    raw = RawFinding(title="t", exposure_level=ExposureLevel.lokal)
    pipeline._apply_exposure(enriched, raw, ExposureLevel.remote)
    assert enriched.exposure_level == ExposureLevel.lokal
    assert enriched.defaults_applied == []


def test_apply_protection_level_defaults_and_tracks_when_unset():
    enriched = EnrichedFinding(finding=_norm())
    raw = RawFinding(title="t")
    pipeline._apply_protection_level(enriched, raw)
    assert enriched.protection_level == ProtectionLevel.very_high
    assert "protection_level=very_high (unbestimmt)" in enriched.defaults_applied


def test_apply_protection_level_uses_business_impact_levels_without_default():
    enriched = EnrichedFinding(finding=_norm())
    raw = RawFinding(title="t", business_impact_levels={"integrity": 4})
    pipeline._apply_protection_level(enriched, raw)
    assert enriched.protection_level == ProtectionLevel.high
    assert enriched.defaults_applied == []


def test_apply_protection_level_uses_maximum_over_protection_needs():
    enriched = EnrichedFinding(finding=_norm())
    raw = RawFinding(
        title="t",
        business_impact_levels={"confidentiality": 2, "integrity": 5, "availability": 3},
    )
    pipeline._apply_protection_level(enriched, raw)
    assert enriched.protection_level == ProtectionLevel.very_high
    assert enriched.impact.business_impact_level == 5
    assert enriched.defaults_applied == []
