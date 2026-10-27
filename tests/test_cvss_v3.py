"""CVSS-3.x-Basiswert aus dem Vektor (Spezifikation v3.1) und Auswahl des Vektors (3.x vor 4.0)."""

import pytest

from vuln_prio_ci.enrich import cvss


@pytest.mark.parametrize("vector, expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),   # Log4Shell
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4),
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
])
def test_base_score_v3_matches_specification(vector, expected):
    assert cvss.base_score_v3(vector) == expected


@pytest.mark.parametrize("vector", [
    None, "", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "AV:N/AC:L/Au:N/C:P/I:P/A:P",                      # CVSS 2.0
    "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",         # unvollständig
    "CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     # ungültiger Wert
])
def test_base_score_v3_without_value(vector):
    assert cvss.base_score_v3(vector) is None


def test_preferred_vector_takes_3x_before_4_0():
    v40 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
    v31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert cvss.preferred_vector([v40, v31]) == v31
    assert cvss.preferred_vector([v40]) == v40
    assert cvss.preferred_vector([]) is None
