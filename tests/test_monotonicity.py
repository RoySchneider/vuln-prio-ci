from vuln_prio_ci.decide.table import CVE_TABLE, CVELESS_TABLE, CVSS_TABLE

from ._ordinal_checks import assert_monotonic_ranks

# Ordnungen "am wenigsten dringend" -> "am dringendsten" je Dimension.
_CVE_ORDERS = {
    "evidence_grade": ["e1", "e2", "e3", "e4", "e5", "e6"],
    "cvss_band": ["c1", "c2", "c3"],
}

_CVELESS_ORDERS = {
    "exploitation": ["none", "poc", "active"],
    "exposure": ["lokal", "intern", "remote"],
    "technical_impact": ["partial", "total"],
    "protection_level": ["normal", "high", "very_high"],
}


def test_cve_table_is_monotonic():
    assert_monotonic_ranks(CVE_TABLE.rows(), ("evidence_grade", "cvss_band"), _CVE_ORDERS)


def test_cveless_table_is_monotonic():
    assert_monotonic_ranks(
        CVELESS_TABLE.rows(),
        ("exploitation", "exposure", "technical_impact", "protection_level"),
        _CVELESS_ORDERS,
    )


def test_cvss_table_is_monotonic():
    orders = {"cvss_severity": ["none", "low", "medium", "high", "critical"]}
    assert_monotonic_ranks(CVSS_TABLE.rows(), ("cvss_severity",), orders)
