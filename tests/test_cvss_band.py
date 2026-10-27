from vuln_prio_ci.enrich.cvss import cvss_band
from vuln_prio_ci.models import CvssBand


def test_score_9_8_is_c3():
    assert cvss_band(9.8) == CvssBand.c3


def test_score_9_0_boundary_is_c3():
    assert cvss_band(9.0) == CvssBand.c3


def test_score_7_0_boundary_is_c2():
    assert cvss_band(7.0) == CvssBand.c2


def test_score_8_9_is_c2():
    assert cvss_band(8.9) == CvssBand.c2


def test_score_6_9_is_c1():
    assert cvss_band(6.9) == CvssBand.c1


def test_score_0_is_c1():
    assert cvss_band(0.0) == CvssBand.c1


def test_custom_thresholds_are_respected():
    assert cvss_band(8.0, high=8.5, critical=9.5) == CvssBand.c1
    assert cvss_band(8.5, high=8.5, critical=9.5) == CvssBand.c2
