"""Code Quality report for GitLab (artifacts:reports:codequality).

GitLab shows the report in the merge request and compares it, via the fingerprint, with the
report of a pipeline of the target branch (new and fixed entries). Required fields per entry:
description, check_name, fingerprint, severity, location.path, location.lines.begin.
"""

from __future__ import annotations

import hashlib
from typing import Iterable, Optional

from ..models import PrioritizationResult, PriorityLevel

LEVEL_LABEL = {
    PriorityLevel.immediate: "Sofort",
    PriorityLevel.urgent: "Außerplanmäßig",
    PriorityLevel.planned: "Planmäßig",
    PriorityLevel.deferred: "Zurückgestellt",
}

SEVERITY = {
    PriorityLevel.immediate: "blocker",
    PriorityLevel.urgent: "critical",
    PriorityLevel.planned: "major",
    PriorityLevel.deferred: "minor",
}
UNDECIDED_SEVERITY = "info"


def _path(file: Optional[str], report_type: Optional[str], image_path: str) -> str:
    """Return the repository path to report for a finding.

    Parameters
    ----------
    file : str or None
        File named in the scanner report.
    report_type : str or None
        Report type of the finding (currently unused).
    image_path : str
        Path to report for findings without a file, such as the Dockerfile.

    Returns
    -------
    str
        `file` without a leading ``./``, or `image_path` if there is no file.
    """
    if file:
        return file[2:] if file.startswith("./") else file
    # Container scanning findings have no file in the repository but an image
    return image_path


def _fingerprint(*parts: Optional[str]) -> str:
    """Compute a stable fingerprint from the given parts.

    Parameters
    ----------
    *parts : str or None
        Values to combine; None is treated as an empty string.

    Returns
    -------
    str
        SHA-256 hex digest of the parts joined by ``|``.
    """
    return hashlib.sha256("|".join(p or "" for p in parts).encode("utf-8")).hexdigest()


def build(results: Iterable[PrioritizationResult], undecided: Iterable, image_path: str = "Dockerfile") -> list[dict]:
    """Build the Code Quality report.

    Parameters
    ----------
    results : Iterable[PrioritizationResult]
        Prioritised findings; one entry each, with severity by priority level.
    undecided : Iterable
        Skipped findings without an assessment (method 2); one ``info`` entry each.
    image_path : str, optional
        Path to report for findings without a file (default ``"Dockerfile"``).

    Returns
    -------
    list[dict]
        Report entries in the GitLab Code Quality format.
    """
    report = []
    for r in results:
        label = LEVEL_LABEL[r.priority]
        rank = f", Rang {r.priority_rank}" if r.priority_rank is not None else ""
        subject = r.cve_id or r.finding_id or r.title
        report.append({
            "description": f"Priorität {label}{rank}: {r.title} [{subject}] – {r.decision_note}",
            "check_name": f"vuln-prio/{r.method.value}",
            # stable across runs: identifier and location, not the ID of the analyser
            "fingerprint": _fingerprint("result", r.finding_id, r.location, r.title),
            "severity": SEVERITY[r.priority],
            "location": {
                "path": _path(r.source_file, r.report_type, image_path),
                "lines": {"begin": int(r.source_line or 1)},
            },
        })
    for skipped in undecided:
        f = skipped.finding
        report.append({
            "description": f"Einschätzung fehlt (Verfahren 2): {f.title} [{f.raw.get('finding_id')}] – "
                           "Eintrag in der Einschätzungsdatei nötig",
            "check_name": "vuln-prio/assessment-missing",
            "fingerprint": _fingerprint("undecided", f.raw.get("finding_id"), f.location, f.title),
            "severity": UNDECIDED_SEVERITY,
            "location": {
                "path": _path(f.raw.get("file"), f.raw.get("report_type"), image_path),
                "lines": {"begin": int(f.raw.get("line") or 1)},
            },
        })
    return report
