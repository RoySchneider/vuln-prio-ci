"""[2] Preparation and identifier normalisation.

Determines the identifier used for enrichment later on and decides on the CVE-less case.
Identifier hierarchy (implementation plan sect. 4):
  1. CVE present                         -> primary identifier, full signal coverage
  2. no CVE, but EUVD/GHSA               -> resolution attempt (here: remember the identifier; CVE
                                            resolution via the EUVD mapping happens in enrichment, euvd.py)
  3. no resolvable CVE (SAST finding)    -> CVE-less branch, fingerprint as stable identity
"""

from __future__ import annotations

import hashlib
import re

from ..models import EnrichmentStatus, NormalizedFinding, RawFinding

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_EUVD_RE = re.compile(r"\bEUVD-\d{4}-\d+\b", re.IGNORECASE)
_GHSA_RE = re.compile(r"\bGHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\b", re.IGNORECASE)
_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)


def _first(patterns: list[str], regex: re.Pattern) -> str | None:
    """Return the first match of a pattern in a list of values.

    Parameters
    ----------
    patterns : list[str]
        Values to search, for example the identifiers of a finding.
    regex : re.Pattern
        Pattern to search for.

    Returns
    -------
    str or None
        The first match in upper case, or None if no value matches.
    """
    for value in patterns:
        m = regex.search(value)
        if m:
            return m.group(0).upper()
    return None


def fingerprint(raw: RawFinding) -> str:
    """Compute a stable identity for a CVE-less SAST finding from rule/title and normalised location.

    Parameters
    ----------
    raw : RawFinding
        The raw finding. The scanner ID (or the title) and the location are used.

    Returns
    -------
    str
        Fingerprint of the form ``sast-<16 hex digits>``.
    """
    rule = (raw.raw.get("scanner_id") or raw.title or "").strip().lower()
    location = (raw.location or "").strip().lower()
    digest = hashlib.sha1(f"{rule}|{location}".encode("utf-8")).hexdigest()
    return f"sast-{digest[:16]}"


def normalize(raw: RawFinding) -> NormalizedFinding:
    """Extract the identifiers of a finding and decide on the enrichment path.

    Parameters
    ----------
    raw : RawFinding
        The raw finding as ingested from a scanner report.

    Returns
    -------
    NormalizedFinding
        The finding with CVE, EUVD, GHSA and CWE identifiers. The enrichment
        status is ``resolved`` if a CVE is present, ``pending`` if only an
        EUVD or GHSA ID is present, and ``cve_less`` otherwise; only CVE-less
        findings get a fingerprint.
    """
    values = list(raw.identifiers)
    if raw.cwe:
        values.append(raw.cwe)

    cve = _first(values, _CVE_RE)
    euvd = _first(values, _EUVD_RE)
    ghsa = _first(values, _GHSA_RE)
    cwe = _first(values, _CWE_RE) or raw.cwe

    if cve:
        status = EnrichmentStatus.resolved
    elif euvd or ghsa:
        # A CVE may be recoverable via the EUVD/OSV mapping -> open for now.
        status = EnrichmentStatus.pending
    else:
        status = EnrichmentStatus.cve_less

    return NormalizedFinding(
        title=raw.title,
        cve_id=cve,
        euvd_id=euvd,
        ghsa_id=ghsa,
        cwe=cwe,
        finding_fingerprint=None if cve else fingerprint(raw),
        cve_present=cve is not None,
        enrichment_status=status,
        source=raw,
    )
