from vuln_prio_ci.enrich import cvss
from vuln_prio_ci.models import CvssSeverity


def test_parse_vector_v31():
    parsed = cvss.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert parsed["version"] == "3.1"
    assert parsed["metrics"]["AV"] == "N"
    assert parsed["metrics"]["C"] == "H"


def test_parse_vector_v40():
    parsed = cvss.parse_vector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
    assert parsed["version"] == "4.0"
    assert parsed["metrics"]["VC"] == "H"


def test_severity_bands():
    assert cvss.severity_band(0.0) is CvssSeverity.none
    assert cvss.severity_band(3.9) is CvssSeverity.low
    assert cvss.severity_band(4.0) is CvssSeverity.medium
    assert cvss.severity_band(7.0) is CvssSeverity.high
    assert cvss.severity_band(9.8) is CvssSeverity.critical


def test_severity_from_gitlab():
    assert cvss.severity_from_gitlab("Critical") is CvssSeverity.critical
    assert cvss.severity_from_gitlab("unknown") is CvssSeverity.none
    assert cvss.severity_from_gitlab(None) is None
