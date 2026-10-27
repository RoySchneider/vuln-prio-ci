"""[1] Import of the GitLab security reports from the artifacts of a pipeline run.

The input is the reports in the format of the GitLab security reports (Security Report Schemas)
that the scanners of a run store as artifacts:

    gl-sast-report.json                  static analysis (Semgrep and others)
    gl-dependency-scanning-report.json   dependency scanning
    gl-container-scanning-report.json    container scanning

Each vulnerability becomes a `RawFinding`. The identifiers are evaluated by type: `cve`, `ghsa`
and `cwe` enter the identifier hierarchy; by GitLab convention the first entry is the primary
identifier and serves as the rule ID for findings without a CVE. From `cvss_vectors` one vector
is chosen by the rule 3.x over 4.0 (enrich/cvss.py::preferred_vector).

Every finding gets an identifier (`raw["finding_id"]`) used to match the assessment file
(ingest/assessments.py):
    without CVE  ->  "<rule ID>:<file>"       e.g. "bandit.B506:app/app.py"
    with CVE     ->  "<CVE>:<package>"        e.g. "CVE-2021-44228:log4j-core"
The line number is deliberately not part of the identifier, so that a shift in the code does not
orphan the assessment. Consequence: findings of the same rule in the same file share one assessment.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Optional

from ..enrich.cvss import preferred_vector
from ..models import RawFinding

# File names of the supported reports -> report type
REPORT_FILES = {
    "gl-sast-report.json": "sast",
    "gl-dependency-scanning-report.json": "dependency_scanning",
    "gl-container-scanning-report.json": "container_scanning",
}

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


class ReportError(Exception):
    """Raised when a report is missing, is not valid JSON, or does not have the expected structure."""


def find_reports(directory: Path | str) -> list[Path]:
    """Find the known report files in a directory (artifacts end up in the project directory).

    Parameters
    ----------
    directory : Path or str
        Directory to search.

    Returns
    -------
    list[Path]
        Paths of the report files that exist, in the order of `REPORT_FILES`.
    """
    base = Path(directory)
    return [base / name for name in REPORT_FILES if (base / name).is_file()]


def load_report(path: Path | str) -> list[RawFinding]:
    """Read a GitLab security report and convert it into raw findings.

    Parameters
    ----------
    path : Path or str
        Location of the JSON report.

    Returns
    -------
    list[RawFinding]
        One finding per vulnerability.

    Raises
    ------
    ReportError
        If the file is missing, not valid JSON, or not a security report.
    """
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as exc:
        raise ReportError(f"Bericht nicht gefunden: {path}") from exc
    except ValueError as exc:
        raise ReportError(f"Bericht ist kein gültiges JSON: {path}: {exc}") from exc
    return parse_report(data, source=path.name)


def parse_report(data: Any, source: str = "") -> list[RawFinding]:
    """Convert a parsed security report into raw findings.

    Parameters
    ----------
    data : Any
        Parsed JSON document with a ``vulnerabilities`` list.
    source : str, optional
        File name of the report; used for the report type if the document does
        not state one.

    Returns
    -------
    list[RawFinding]
        One finding per vulnerability.

    Raises
    ------
    ReportError
        If the document is not a security report.
    """
    if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        raise ReportError(f"kein GitLab-Sicherheitsbericht (Liste 'vulnerabilities' fehlt): {source}")
    scan = data.get("scan") or {}
    report_type = scan.get("type") or REPORT_FILES.get(source)
    report_scanner = (scan.get("scanner") or {}).get("name")
    return [_to_finding(v, report_type, report_scanner, source) for v in data["vulnerabilities"]]


def _to_finding(v: dict, report_type: Optional[str], report_scanner: Optional[str], source: str) -> RawFinding:
    """Convert one vulnerability of a report into a raw finding.

    Parameters
    ----------
    v : dict
        The vulnerability entry.
    report_type : str or None
        Report type, used if the entry has no category.
    report_scanner : str or None
        Scanner name of the report, used if the entry names none.
    source : str
        File name of the report, stored in the raw data.

    Returns
    -------
    RawFinding
        The finding with its identifiers, location and ``finding_id``.
    """
    identifiers = [i for i in (v.get("identifiers") or []) if isinstance(i, dict)]
    cve = _first_value(identifiers, "cve", normalize=lambda x: x.upper() if _CVE_RE.match(x) else None)
    ghsa = _first_value(identifiers, "ghsa", normalize=lambda x: x.upper())
    cwe = _first_value(identifiers, "cwe", normalize=lambda x: f"CWE-{x}" if x.isdigit() else x.upper())
    rule_id = _primary_rule_id(identifiers)

    location = v.get("location") or {}
    dependency = location.get("dependency") or {}
    package = (dependency.get("package") or {}).get("name")
    version = dependency.get("version")
    file = location.get("file")
    line = location.get("start_line")
    image = location.get("image")

    report_type = v.get("category") or report_type
    if cve:
        finding_id = f"{cve}:{package}" if package else cve
    else:
        finding_id = f"{rule_id}:{file}" if file else rule_id

    vectors = [c.get("vector") for c in (v.get("cvss_vectors") or []) if isinstance(c, dict)]
    ids = [x for x in (cve, ghsa, cwe) if x]
    return RawFinding(
        title=v.get("name") or v.get("message") or _first_name(identifiers) or "(ohne Titel)",
        description=v.get("description"),
        scanner=(v.get("scanner") or {}).get("name") or report_scanner,
        gitlab_severity=v.get("severity"),
        cwe=cwe,
        location=_format_location(file, line, image, package, version),
        identifiers=ids,
        raw={
            "report": source,
            "report_type": report_type,
            "gitlab_id": v.get("id"),
            "finding_id": finding_id,
            "rule_id": rule_id,
            "file": file,
            "line": line,
            "image": image,
            "package": package,
            "version": version,
            "cvss_vector": preferred_vector([x for x in vectors if x]),
        },
    )


def _first_value(identifiers: list[dict], type_: str, normalize) -> Optional[str]:
    """Return the first normalised identifier value of a given type.

    Parameters
    ----------
    identifiers : list[dict]
        Identifier entries of a vulnerability.
    type_ : str
        Identifier type to look for, in lower case.
    normalize : Callable[[str], Optional[str]]
        Converts a raw value; returns None to reject it.

    Returns
    -------
    str or None
        The first accepted value, or None if there is none.
    """
    for ident in identifiers:
        if str(ident.get("type", "")).lower() == type_:
            value = str(ident.get("value") or ident.get("name") or "").strip()
            normalized = normalize(value) if value else None
            if normalized:
                return normalized
    return None


def _primary_rule_id(identifiers: list[dict]) -> Optional[str]:
    """Return the first identifier = primary identifier (GitLab convention); for SAST the rule ID of the scanner.

    Parameters
    ----------
    identifiers : list[dict]
        Identifier entries of a vulnerability.

    Returns
    -------
    str or None
        The value of the first identifier, or None if there is none.
    """
    for ident in identifiers:
        value = ident.get("value") or ident.get("name")
        if value:
            return str(value).strip()
    return None


def _first_name(identifiers: list[dict]) -> Optional[str]:
    """Return the name of the first identifier that has one, or None."""
    for ident in identifiers:
        if ident.get("name"):
            return str(ident["name"])
    return None


def _format_location(file, line, image, package, version) -> Optional[str]:
    """Format a human-readable location of a finding.

    Parameters
    ----------
    file : str or None
        File path.
    line : int or None
        Start line.
    image : str or None
        Container image; takes precedence over `file`.
    package : str or None
        Affected package.
    version : str or None
        Version of the affected package.

    Returns
    -------
    str or None
        ``image (package@version)``, ``file:line`` or the bare file/image, or
        None if nothing is known.
    """
    where = image or file
    if package:
        dep = f"{package}@{version}" if version else package
        return f"{where} ({dep})" if where else dep
    if file and line:
        return f"{file}:{line}"
    return where
