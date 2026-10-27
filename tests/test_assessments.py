"""Einschätzungsdatei: Prüfung, Übertragung auf Befunde, verwaiste Einträge, VEX."""

import pytest

from vuln_prio_ci.ingest import assessments
from vuln_prio_ci.models import ExploitationState, ExposureLevel, ProtectionLevel, RawFinding, TechnicalImpact, VexStatus

VALID = """
protection_level: high
protection_level_basis: "Schutzbedarfsfeststellung ProjekteXY"
findings:
  - id: "bandit.B506:app/app.py"
    title: "Deserialization"
    exploitation_state: poc
    exploitation_basis: "verbreitete Klasse"
    exposure_level: intern
    exposure_basis: "Bedrohungsmodell"
    technical_impact: total
    technical_impact_basis: "Codeausführung"
    assessed_by: "N. N."
    assessed_on: 2026-10-14
  - id: "gosec.G106-1:og.go"
    vex_status: not_affected
    vex_justification: "nur Testcode"
  - id: "veraltet:alt.py"
    exploitation_state: none
    technical_impact: partial
vex:
  - cve: CVE-2025-30208
    package: vite
    status: not_affected
    justification: "Entwicklungsserver wird nicht ausgeliefert"
"""


def _finding(finding_id, cve=None, package=None):
    return RawFinding(title=finding_id, identifiers=[cve] if cve else [],
                      raw={"finding_id": finding_id, "package": package})


def test_parse_and_apply():
    parsed = assessments.parse(assessments.safe_load(VALID))
    sast = _finding("bandit.B506:app/app.py")
    fp = _finding("gosec.G106-1:og.go")
    vite = _finding("CVE-2025-30208:vite", cve="CVE-2025-30208", package="vite")
    other = _finding("CVE-2025-30208:other", cve="CVE-2025-30208", package="other")
    result = assessments.apply([sast, fp, vite, other], parsed)

    assert sast.exploitation_state is ExploitationState.poc
    assert sast.exposure_level is ExposureLevel.intern
    assert sast.technical_impact is TechnicalImpact.total
    assert sast.protection_level is ProtectionLevel.high
    assert fp.vex_status is VexStatus.not_affected
    assert vite.vex_status is VexStatus.not_affected
    assert other.vex_status is None                  # Aussage gilt nur für das Paket vite
    assert result.orphaned == ["veraltet:alt.py"]
    # fehlende Grundlagen werden als Hinweis gemeldet, nicht als Fehler
    assert any("veraltet:alt.py" in w and "exploitation_basis" in w for w in parsed.warnings)


@pytest.mark.parametrize("content, message", [
    ("findings:\n  - id: x\n    exploitation_state: high\n    technical_impact: total\n", "unbekannter Wert"),
    ("findings:\n  - id: x\n    exploitation_state: poc\n", "Pflicht"),
    ("findings:\n  - exploitation_state: poc\n    technical_impact: total\n", "'id' fehlt"),
    ("findings:\n  - {id: x, exploitation_state: poc, technical_impact: total}\n"
     "  - {id: x, exploitation_state: poc, technical_impact: total}\n", "doppelt"),
    ("findings:\n  - {id: x, exploitation_state: poc, technical_impact: total, foo: 1}\n", "unbekannte Schlüssel"),
    ("vex:\n  - {cve: CVE-xyz, status: not_affected}\n", "ungültige CVE"),
    ("protection_level: mittel\n", "unbekannter Wert"),
    ("- liste\n", "Mapping"),
])
def test_invalid_files(content, message):
    with pytest.raises(assessments.AssessmentError, match=message):
        assessments.parse(assessments.safe_load(content))


def test_load_invalid_yaml(tmp_path):
    path = tmp_path / "a.yaml"
    path.write_text("findings: [\n")
    with pytest.raises(assessments.AssessmentError):
        assessments.load(path)


def test_empty_file_is_valid(tmp_path):
    path = tmp_path / "a.yaml"
    path.write_text("")
    assert assessments.load(path).findings == {}
