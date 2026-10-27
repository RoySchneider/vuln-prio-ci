"""Scales of method 2 (without CVE): exploitation state × exposure × impact × protection need.

The codes correspond to EXPLOITATION_STATE/EXPOSURE_LEVEL/TECHNICAL_IMPACT/PROTECTION_LEVEL in
db/seed_reference.sql.
"""

from __future__ import annotations

from enum import Enum


class ExploitationState(str, Enum):
    """Exploitation state.

    Attributes
    ----------
    active
        Documented evidence of exploitation.
    poc
        Exploit code or a generally known exploitation method.
    none
        Documented search without result.
    """

    active = "active"   # documented evidence of exploitation
    poc = "poc"         # exploit code or generally known exploitation method
    none = "none"       # documented search without result


class ExposureLevel(str, Enum):
    """Exposure of the vulnerable component.

    Attributes
    ----------
    remote
        Reachable from an uncontrolled network without authentication.
    intern
        Reachable from a restricted network, after authentication or only in a chain.
    lokal
        Reachable only through physical access.
    """

    remote = "remote"   # reachable from an uncontrolled network without authentication
    intern = "intern"   # reachable from a restricted network, after authentication or only in a chain
    lokal = "lokal"     # reachable only through physical access


class TechnicalImpact(str, Enum):
    """Technical impact of exploitation.

    Attributes
    ----------
    total
        Complete control/disclosure.
    partial
        Limited control/disclosure.
    """

    total = "total"       # complete control/disclosure
    partial = "partial"   # limited control/disclosure


class ProtectionLevel(str, Enum):
    """BSI protection need category, separate from the 5-level damage extent."""

    very_high = "very_high"
    high = "high"
    normal = "normal"


class ProtectionNeed(str, Enum):
    """Protection goal, each with its own damage extent (1..5); the protection need is the maximum over them."""

    confidentiality = "confidentiality"
    integrity = "integrity"
    availability = "availability"
