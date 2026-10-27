"""[4] Extract features from the CVSS string + severity band.

Parses CVSS vectors (v3.0/v3.1/v4.0) into their individual metrics and derives the ordinal severity
band from the base score. The base score itself is NOT processed further, only binned
(methodology sect. 4). AV/PR/UI later support exposure/automatability, C/I/A the technical
impact.

`base_score_v3` computes the base score of a CVSS 3.x vector using the formula of the specification
(FIRST, CVSS v3.1 Specification, sect. 7). This is not a calculation of our own but the official
base score; it is needed when a scanner report contains only the vector. For CVSS 4.0 there is no
closed formula (lookup via macro vectors); a 4.0 vector without a base score stays without a value.
"""

from __future__ import annotations

import math
from typing import Optional

from ..models import CvssBand, CvssSeverity

# Qualitative bands according to the CVSS severity rating (v3.x/v4.0, identical limits).
_BANDS = [
    (0.0, 0.0, CvssSeverity.none),
    (0.1, 3.9, CvssSeverity.low),
    (4.0, 6.9, CvssSeverity.medium),
    (7.0, 8.9, CvssSeverity.high),
    (9.0, 10.0, CvssSeverity.critical),
]

# GitLab/scanner severity as a rough substitute when no CVSS base score is available (CVE-less case).
_GITLAB_SEVERITY = {
    "info": CvssSeverity.none,
    "unknown": CvssSeverity.none,
    "low": CvssSeverity.low,
    "medium": CvssSeverity.medium,
    "high": CvssSeverity.high,
    "critical": CvssSeverity.critical,
}


def parse_vector(vector: str) -> dict:
    """Split 'CVSS:3.1/AV:N/AC:L/...' into the version and a metrics dictionary.

    Parameters
    ----------
    vector : str
        CVSS vector string. Parts without a colon are ignored.

    Returns
    -------
    dict
        ``{"version": str or None, "metrics": dict[str, str]}``. Keys and values
        are upper case. An empty vector yields version None and no metrics.
    """
    result: dict = {"version": None, "metrics": {}}
    if not vector:
        return result
    parts = [p for p in vector.strip().split("/") if p]
    for part in parts:
        if ":" not in part:
            continue
        key, value = part.split(":", 1)
        key = key.strip().upper()
        value = value.strip().upper()
        if key == "CVSS":
            result["version"] = value
        else:
            result["metrics"][key] = value
    return result


def severity_band(base_score: float) -> CvssSeverity:
    """Map a CVSS base score (0.0-10.0) to the ordinal severity band.

    Parameters
    ----------
    base_score : float
        CVSS base score. Values outside 0.0-10.0 are clamped.

    Returns
    -------
    CvssSeverity
        Severity band: none, low, medium, high or critical.
    """
    score = max(0.0, min(10.0, float(base_score)))
    if score == 0.0:
        return CvssSeverity.none
    for low, high, band in _BANDS:
        if low <= score <= high:
            return band
    return CvssSeverity.critical


def severity_from_gitlab(severity: str | None) -> CvssSeverity | None:
    """Map a GitLab/scanner severity label to a severity band.

    Parameters
    ----------
    severity : str or None
        Severity label such as ``'high'``; matching is case-insensitive.

    Returns
    -------
    CvssSeverity or None
        The band, or None if `severity` is empty or unknown.
    """
    if not severity:
        return None
    return _GITLAB_SEVERITY.get(severity.strip().lower())


def cvss_band(base_score: float, *, high: float = 7.0, critical: float = 9.0) -> CvssBand:
    """Map the CVSS base score to the range of method 1 (appendix C).

    The limits are parameters (config.cvss_band_high/cvss_band_critical), not hard-coded.
    No base score -> no call; the special case is handled at the call site (AP-5).

    Parameters
    ----------
    base_score : float
        CVSS base score.
    high : float, optional
        Lower limit of range c2 (default 7.0).
    critical : float, optional
        Lower limit of range c3 (default 9.0).

    Returns
    -------
    CvssBand
        ``c3`` if the score is at least `critical`, ``c2`` if it is at least
        `high`, otherwise ``c1``.
    """
    score = float(base_score)
    if score >= critical:
        return CvssBand.c3
    if score >= high:
        return CvssBand.c2
    return CvssBand.c1


# --- CVSS 3.x: base score from the vector (specification v3.1, sect. 7.1/7.4) ----------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")


def _roundup_v31(value: float) -> float:
    """Round up as defined in appendix A of specification 3.1 (avoids floating-point artefacts).

    Parameters
    ----------
    value : float
        Value to round up.

    Returns
    -------
    float
        `value` rounded up to one decimal place.
    """
    int_input = round(value * 100000)
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def _roundup_v30(value: float) -> float:
    """Round up to one decimal place as defined in specification 3.0.

    Parameters
    ----------
    value : float
        Value to round up.

    Returns
    -------
    float
        `value` rounded up to one decimal place.
    """
    return math.ceil(value * 10) / 10.0


def base_score_v3(vector: Optional[str]) -> Optional[float]:
    """Compute the base score of a CVSS 3.0/3.1 vector.

    Parameters
    ----------
    vector : str or None
        CVSS vector string.

    Returns
    -------
    float or None
        The base score, or None for another version, an incomplete vector or
        an unknown metric value.
    """
    if not vector:
        return None
    parsed = parse_vector(vector)
    version = parsed["version"]
    metrics = parsed["metrics"]
    if version not in ("3.0", "3.1") or any(m not in metrics for m in _BASE_METRICS):
        return None
    try:
        scope_changed = {"U": False, "C": True}[metrics["S"]]
        av, ac, ui = _AV[metrics["AV"]], _AC[metrics["AC"]], _UI[metrics["UI"]]
        pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[metrics["PR"]]
        c, i, a = _CIA[metrics["C"]], _CIA[metrics["I"]], _CIA[metrics["A"]]
    except KeyError:
        return None

    iss = 1 - ((1 - c) * (1 - i) * (1 - a))
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    roundup = _roundup_v31 if version == "3.1" else _roundup_v30
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def preferred_vector(vectors: list[str]) -> Optional[str]:
    """Choose the vector to use from several vectors of a finding: version 3.x over 4.0 over 2.0.

    Corresponds to the rule in chapter 5 (application to a scan result): 3.x over 4.0.
    Vectors without a version prefix (CVSS 2.0) are only taken if nothing else is available.

    Parameters
    ----------
    vectors : list[str]
        Candidate vectors. Empty and blank entries are ignored.

    Returns
    -------
    str or None
        The preferred vector, or None if there is no candidate.
    """
    def rank(vector: str) -> int:
        """Return the preference rank of a vector; lower is preferred."""
        version = parse_vector(vector)["version"]
        if version in ("3.1", "3.0"):
            return 0 if version == "3.1" else 1
        if version == "4.0":
            return 2
        return 3

    candidates = [v.strip() for v in vectors if v and v.strip()]
    return min(candidates, key=rank) if candidates else None
