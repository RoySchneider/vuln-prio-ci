import csv
from itertools import product
from pathlib import Path

from vuln_prio_ci.decide.table import CVE_TABLE, CVELESS_TABLE, CVSS_TABLE
from vuln_prio_ci.models import (
    CvssBand,
    CvssSeverity,
    EvidenceGrade,
    ExploitationState,
    ExposureLevel,
    PriorityLevel,
    ProtectionLevel,
    TechnicalImpact,
)

_RULES_DIR = Path(__file__).resolve().parent.parent / "src" / "vuln_prio_ci" / "rules"


def _raw_rows(filename: str) -> list[dict]:
    with (_RULES_DIR / filename).open(encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def test_cve_table_has_18_unique_rows():
    rows = _raw_rows("decision_table_cve.csv")
    assert len(rows) == 18
    keys = {(r["evidence_grade"], r["cvss_band"]) for r in rows}
    assert len(keys) == 18   # keine doppelten Schlüssel
    assert len(CVE_TABLE.rows()) == 18


def test_cveless_table_has_54_unique_rows():
    rows = _raw_rows("decision_table_cveless.csv")
    assert len(rows) == 54
    keys = {(r["exploitation"], r["exposure"], r["technical_impact"], r["protection_level"]) for r in rows}
    assert len(keys) == 54   # keine doppelten Schlüssel
    assert len(CVELESS_TABLE.rows()) == 54


def test_cve_table_codes_are_valid():
    for (grade, band), (priority, rank) in CVE_TABLE.rows().items():
        EvidenceGrade(grade)
        CvssBand(band)
        PriorityLevel(priority)
        assert 1 <= rank <= 18


def test_cveless_table_codes_are_valid():
    for (exploitation, exposure, impact, protection), (priority, rank) in CVELESS_TABLE.rows().items():
        ExploitationState(exploitation)
        ExposureLevel(exposure)
        TechnicalImpact(impact)
        ProtectionLevel(protection)
        PriorityLevel(priority)
        assert 1 <= rank <= 54


def test_cve_table_covers_every_grade_band_combination():
    expected = {
        (grade.value, band.value) for grade, band in product(EvidenceGrade, CvssBand)
    }
    assert set(CVE_TABLE.rows().keys()) == expected   # keine Kombination fehlt oder ist zusätzlich


def test_cveless_table_covers_every_dimension_combination():
    expected = {
        (exploitation.value, exposure.value, impact.value, protection.value)
        for exploitation, exposure, impact, protection in product(
            ExploitationState, ExposureLevel, TechnicalImpact, ProtectionLevel
        )
    }
    assert set(CVELESS_TABLE.rows().keys()) == expected   # keine Kombination fehlt oder ist zusätzlich


def test_cve_table_ranks_are_a_permutation_of_1_to_18():
    ranks = sorted(rank for _, rank in CVE_TABLE.rows().values())
    assert ranks == list(range(1, 19))


def test_cveless_table_ranks_are_a_permutation_of_1_to_54():
    ranks = sorted(rank for _, rank in CVELESS_TABLE.rows().values())
    assert ranks == list(range(1, 55))


def test_cvss_table_covers_every_severity_once():
    rows = _raw_rows("decision_table_cvss.csv")
    assert len(rows) == 5
    assert set(CVSS_TABLE.rows().keys()) == {(severity.value,) for severity in CvssSeverity}
    for _, (priority, _rank) in CVSS_TABLE.rows().items():
        PriorityLevel(priority)


def test_cvss_table_ranks_are_a_permutation_of_1_to_5():
    ranks = sorted(rank for _, rank in CVSS_TABLE.rows().values())
    assert ranks == list(range(1, 6))
