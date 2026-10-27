"""Scales of method 1 (with CVE): evidence grade × CVSS range.

The codes correspond to EVIDENCE_GRADE/CVSS_BAND in db/seed_reference.sql.
"""

from __future__ import annotations

from enum import Enum


class EvidenceGrade(str, Enum):
    """Evidence grade of exploitation, from e1 (lowest) to e6 (highest).

    Attributes
    ----------
    e6
        Observed exploitation (KEV).
    e5
        Without exploit development (Metasploit).
    e4
        Exploit code available (ExploitDB/PoC).
    e3
        Predicted (EPSS >= tau).
    e2
        Undetermined (no EPSS value).
    e1
        Low (EPSS < tau).
    """

    e6 = "e6"   # observed exploitation (KEV)
    e5 = "e5"   # without exploit development (Metasploit)
    e4 = "e4"   # exploit code available (ExploitDB/PoC)
    e3 = "e3"   # predicted (EPSS >= tau)
    e2 = "e2"   # undetermined (no EPSS value)
    e1 = "e1"   # low (EPSS < tau)


class CvssBand(str, Enum):
    """CVSS range of method 1.

    Attributes
    ----------
    c3
        9.0-10.0.
    c2
        7.0-8.9.
    c1
        Up to 6.9.
    """

    c3 = "c3"   # 9.0-10.0
    c2 = "c2"   # 7.0-8.9
    c1 = "c1"   # up to 6.9
