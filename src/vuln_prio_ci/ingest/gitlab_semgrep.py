"""[1] Security scan as input: import of the CSV export of the GitLab vulnerability report.

According to the GitLab documentation, the export (Security & Compliance -> Vulnerability report
-> Export, or the Vulnerability Export API) has the columns

    Group Name, Project Name, Tool, Scanner Name, Status, Vulnerability, Details, Additional Info,
    Severity, CVE, CWE, Other Identifiers, Detected At, Location, Activity, Comments, Full Path,
    CVSS Vectors, Dismissal Reason

The mapping below covers these columns and older/deviating names. Vulnerabilities with the status
`dismissed` or `resolved` are not taken over (they are dismissed or fixed).
The column `Location` is Ruby hash text; file, image, package and version are read from it to
build the finding identifier (CVE:package or rule:file) as in the report import.
"""

from __future__ import annotations

import csv
import io
import re
from collections import Counter

from ..enrich.cvss import preferred_vector
from ..models import RawFinding

# Possible CSV column names -> internal field. Case-insensitive.
_COLUMN_ALIASES = {
    "title": ["title", "name", "vulnerability"],
    "description": ["description", "details"],
    "scanner": ["scanner", "scanner name", "tool"],
    "report_type": ["tool", "report type"],
    "gitlab_severity": ["severity"],
    "cwe": ["cwe", "identifier cwe"],
    "location": ["location", "file", "path"],
    "identifiers": ["identifiers", "identifier", "cve"],
    "other_identifiers": ["other identifiers"],
    "cvss_vectors": ["cvss vectors", "cvss vector", "cvss_vector"],
    "status": ["status", "state"],
}

# Statuses of the vulnerability report that are not prioritised
SKIP_STATUSES = {"dismissed", "resolved"}

_VECTOR_RE = re.compile(r"CVSS:\d\.\d(?:/[A-Za-z]+:[A-Za-z])+")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_HASH_FIELDS = {
    "file": re.compile(r'"file"\s*=>\s*"([^"]+)"'),
    "image": re.compile(r'"image"\s*=>\s*"([^"]+)"'),
    "package": re.compile(r'"package"\s*=>\s*\{\s*"name"\s*=>\s*"([^"]+)"'),
    "version": re.compile(r'"version"\s*=>\s*"([^"]+)"'),
    "line": re.compile(r'"start_line"\s*=>\s*(\d+)'),
}


def _pick(row: dict[str, str], field: str) -> str | None:
    """Pick the value of an internal field from a CSV row.

    Parameters
    ----------
    row : dict[str, str]
        CSV row keyed by column name.
    field : str
        Internal field, a key of `_COLUMN_ALIASES`.

    Returns
    -------
    str or None
        The stripped value of the first alias column that is non-empty (column
        names are matched case-insensitively), or None.
    """
    lower = {(k or "").lower().strip(): v for k, v in row.items()}
    for alias in _COLUMN_ALIASES[field]:
        if alias in lower and lower[alias]:
            return lower[alias].strip()
    return None


def _split_identifiers(value: str | None) -> list[str]:
    """Split a list of identifiers from one CSV cell.

    Parameters
    ----------
    value : str or None
        Cell content with identifiers separated by comma, semicolon or pipe.

    Returns
    -------
    list[str]
        Non-empty, stripped identifiers.
    """
    if not value:
        return []
    # Depending on the export, GitLab separates identifiers with a comma, semicolon or pipe.
    parts: list[str] = []
    for chunk in value.replace("|", ",").replace(";", ",").split(","):
        chunk = chunk.strip()
        if chunk:
            parts.append(chunk)
    return parts


def _location_fields(location: str | None) -> dict:
    """Read file, image, package, version and line from a ``Location`` cell.

    Parameters
    ----------
    location : str or None
        Ruby hash text, or a plain ``file:line`` specification.

    Returns
    -------
    dict
        The fields found, among ``file``, ``image``, ``package``, ``version``
        and ``line`` (int).
    """
    fields: dict = {}
    if not location:
        return fields
    for key, pattern in _HASH_FIELDS.items():
        match = pattern.search(location)
        if match:
            fields[key] = int(match.group(1)) if key == "line" else match.group(1)
    if not fields and "=>" not in location:
        # plain "file:line" specification
        path, _, line = location.partition(":")
        fields["file"] = path
        if line.isdigit():
            fields["line"] = int(line)
    return fields


def parse_csv_with_stats(content: str) -> tuple[list[RawFinding], Counter]:
    """Parse the export; return the findings and the number of rows left out by status.

    Parameters
    ----------
    content : str
        CSV content of the export.

    Returns
    -------
    findings : list[RawFinding]
        One finding per row that is not dismissed or resolved.
    skipped : Counter
        Number of left-out rows per status.
    """
    findings: list[RawFinding] = []
    skipped: Counter = Counter()
    reader = csv.DictReader(io.StringIO(content))
    for row in reader:
        status = (_pick(row, "status") or "").lower()
        if status in SKIP_STATUSES:
            skipped[status] += 1
            continue
        title = _pick(row, "title") or "(ohne Titel)"
        idents = _split_identifiers(_pick(row, "identifiers"))
        for extra in _split_identifiers(_pick(row, "other_identifiers")):
            if extra not in idents:
                idents.append(extra)
        cwe = _pick(row, "cwe")
        if cwe and cwe.isdigit():
            cwe = f"CWE-{cwe}"
        if cwe and cwe not in idents:
            idents.append(cwe)
        location = _pick(row, "location")
        loc = _location_fields(location)
        cve = next((m.group(0).upper() for i in idents for m in [_CVE_RE.search(i)] if m), None)
        package = loc.get("package")
        if cve:
            finding_id = f"{cve}:{package}" if package else cve
        else:
            finding_id = f"{title}:{loc['file']}" if loc.get("file") else title
        raw = {k: v for k, v in row.items()}
        raw.update({
            "report_type": _pick(row, "report_type"),
            "finding_id": finding_id,
            "file": loc.get("file"),
            "line": loc.get("line"),
            "image": loc.get("image"),
            "package": package,
            "version": loc.get("version"),
            "status": status or None,
        })
        vectors = _VECTOR_RE.findall(_pick(row, "cvss_vectors") or "")
        if vectors:
            raw["cvss_vector"] = preferred_vector(vectors)
        findings.append(
            RawFinding(
                title=title,
                description=_pick(row, "description"),
                scanner=_pick(row, "scanner"),
                gitlab_severity=_pick(row, "gitlab_severity"),
                cwe=cwe,
                location=_display_location(loc) or location,
                identifiers=idents,
                raw=raw,
            )
        )
    return findings, skipped


def parse_csv(content: str) -> list[RawFinding]:
    """Parse the CSV content of a GitLab vulnerability report export into raw findings.

    Parameters
    ----------
    content : str
        CSV content of the export.

    Returns
    -------
    list[RawFinding]
        One finding per row that is not dismissed or resolved.
    """
    findings, _ = parse_csv_with_stats(content)
    return findings


def _display_location(loc: dict) -> str | None:
    """Format a human-readable location from the fields of `_location_fields`.

    Parameters
    ----------
    loc : dict
        Location fields.

    Returns
    -------
    str or None
        ``image (package@version)``, ``file:line`` or the bare file/image, or
        None if nothing is known.
    """
    where = loc.get("image") or loc.get("file")
    if loc.get("package"):
        dep = f"{loc['package']}@{loc['version']}" if loc.get("version") else loc["package"]
        return f"{where} ({dep})" if where else dep
    if loc.get("file") and loc.get("line"):
        return f"{loc['file']}:{loc['line']}"
    return where
