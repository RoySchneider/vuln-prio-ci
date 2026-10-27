"""Assessment file in the repository of the product (method 2 and VEX statements).

The file records the assessments of the development team that no scanner provides, and is
versioned with the code and changed via merge request (role like `risk_tracking` in Threagile).
Example (YAML):

    protection_level: high
    protection_level_basis: "Schutzbedarfsfeststellung ProjekteXY, Asset Core"
    findings:
      - id: "java_inject_rule-SqlInjection:src/app/OrderRepository.java"
        title: "SQL-Injection in OrderRepository"
        exploitation_state: poc          # none | poc | active
        exploitation_basis: "..."
        exposure_level: intern           # lokal | intern | remote (optional, default remote otherwise)
        exposure_basis: "..."
        technical_impact: total          # partial | total
        technical_impact_basis: "..."
        assessed_by: "N. N."
        assessed_on: 2026-10-14
      - id: "bandit.B506:app/app.py"     # false positive: VEX statement instead of assessment
        vex_status: not_affected
        vex_justification: "Eingabe stammt nur aus der eigenen Konfiguration"
    vex:                                 # VEX statements for findings with a CVE
      - cve: CVE-2025-30208
        package: vite                    # optional; without a package the statement applies to all packages
        status: not_affected             # not_affected | fixed | affected | under_investigation
        justification: "Entwicklungsserver wird nicht ausgeliefert"

The values correspond to the codes of the rule tables (models/enums_v2.py), so that the entries are
taken over into `RawFinding` without conversion. `protection_level` applies to the product; give
the highest protection need of the projects that use it (chapter 5, method 2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

from ..models import ExploitationState, ExposureLevel, ProtectionLevel, RawFinding, TechnicalImpact, VexStatus

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

_TOP_KEYS = {"protection_level", "protection_level_basis", "findings", "vex"}
_FINDING_KEYS = {
    "id", "title", "exploitation_state", "exploitation_basis", "exposure_level", "exposure_basis",
    "technical_impact", "technical_impact_basis", "vex_status", "vex_justification",
    "assessed_by", "assessed_on",
}
_VEX_KEYS = {"cve", "package", "status", "justification", "assessed_by", "assessed_on"}


class AssessmentError(Exception):
    """Raised when the assessment file is invalid (structure, unknown keys or values, duplicate IDs)."""


@dataclass
class FindingAssessment:
    """Assessment of a single finding without CVE.

    Attributes
    ----------
    id : str
        Finding identifier, ``<rule ID>:<file>``.
    title : str or None
        Title of the finding, for readability of the file.
    exploitation_state : ExploitationState or None
        Exploitation state.
    exposure_level : ExposureLevel or None
        Exposure of the vulnerable component.
    technical_impact : TechnicalImpact or None
        Technical impact.
    vex_status : VexStatus or None
        VEX status, used instead of an assessment for false positives.
    """

    id: str
    title: Optional[str] = None
    exploitation_state: Optional[ExploitationState] = None
    exposure_level: Optional[ExposureLevel] = None
    technical_impact: Optional[TechnicalImpact] = None
    vex_status: Optional[VexStatus] = None


@dataclass
class VexStatement:
    """VEX statement for a finding with CVE.

    Attributes
    ----------
    cve : str
        CVE ID in upper case.
    package : str or None
        Affected package; None means the statement applies to all packages.
    status : VexStatus
        VEX status.
    """

    cve: str
    package: Optional[str]
    status: VexStatus


@dataclass
class Assessments:
    """Parsed content of an assessment file.

    Attributes
    ----------
    protection_level : ProtectionLevel or None
        Protection need of the product.
    findings : dict[str, FindingAssessment]
        Assessments by finding identifier.
    vex : list[VexStatement]
        VEX statements.
    warnings : list[str]
        Notes on missing justifications or assessment details.
    """

    protection_level: Optional[ProtectionLevel] = None
    findings: dict[str, FindingAssessment] = field(default_factory=dict)
    vex: list[VexStatement] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class ApplyResult:
    """Outcome of `apply`.

    Attributes
    ----------
    matched : set[str]
        Entries that were used (identifier or ``CVE:package``).
    orphaned : list[str]
        Entries without a matching finding.
    """

    matched: set[str] = field(default_factory=set)          # entries used (identifier or CVE:package)
    orphaned: list[str] = field(default_factory=list)       # entries without a matching finding


def safe_load(text: str) -> Any:
    """Load YAML without object construction (safe loader, pure Python; duplicate keys are an error).

    Parameters
    ----------
    text : str
        YAML document.

    Returns
    -------
    Any
        The parsed document.

    Raises
    ------
    YAMLError
        If the text is not valid YAML or contains duplicate keys.
    """
    return YAML(typ="safe", pure=True).load(text)


def load(path: Path | str) -> Assessments:
    """Read and parse an assessment file.

    Parameters
    ----------
    path : Path or str
        Location of the YAML file.

    Returns
    -------
    Assessments
        The parsed assessments. An empty file yields empty assessments.

    Raises
    ------
    AssessmentError
        If the file is not valid YAML or its content is invalid.
    """
    path = Path(path)
    try:
        data = safe_load(path.read_text(encoding="utf-8-sig"))
    except YAMLError as exc:
        raise AssessmentError(f"{path}: kein gültiges YAML: {exc}") from exc
    return parse(data if data is not None else {}, str(path))


def parse(data: Any, source: str = "Einschätzungsdatei") -> Assessments:
    """Validate and convert the loaded YAML document.

    Missing justifications and basis fields only produce warnings; structural
    problems, unknown keys or values, and duplicate identifiers are errors.

    Parameters
    ----------
    data : Any
        Parsed YAML document, expected to be a mapping.
    source : str, optional
        Name used in error messages, usually the file path.

    Returns
    -------
    Assessments
        The validated assessments including warnings.

    Raises
    ------
    AssessmentError
        If the document is invalid.
    """
    if not isinstance(data, dict):
        raise AssessmentError(f"{source}: oberste Ebene muss ein Mapping sein")
    _unknown_keys(data, _TOP_KEYS, source)
    result = Assessments()
    if data.get("protection_level") is not None:
        result.protection_level = _enum(ProtectionLevel, data["protection_level"], f"{source}: protection_level")
        if not data.get("protection_level_basis"):
            result.warnings.append("protection_level ohne protection_level_basis")

    for n, entry in enumerate(_as_list(data.get("findings"), f"{source}: findings"), start=1):
        where = f"{source}: findings[{n}]"
        if not isinstance(entry, dict):
            raise AssessmentError(f"{where}: Eintrag muss ein Mapping sein")
        _unknown_keys(entry, _FINDING_KEYS, where)
        finding_id = str(entry.get("id") or "").strip()
        if not finding_id:
            raise AssessmentError(f"{where}: Kennung 'id' fehlt")
        if finding_id in result.findings:
            raise AssessmentError(f"{where}: Kennung doppelt: {finding_id}")
        item = FindingAssessment(id=finding_id, title=entry.get("title"))
        if entry.get("vex_status") is not None:
            item.vex_status = _enum(VexStatus, entry["vex_status"], f"{where}: vex_status")
            if not entry.get("vex_justification"):
                result.warnings.append(f"{finding_id}: vex_status ohne vex_justification")
        if entry.get("exploitation_state") is not None:
            item.exploitation_state = _enum(ExploitationState, entry["exploitation_state"], f"{where}: exploitation_state")
        if entry.get("technical_impact") is not None:
            item.technical_impact = _enum(TechnicalImpact, entry["technical_impact"], f"{where}: technical_impact")
        if entry.get("exposure_level") is not None:
            item.exposure_level = _enum(ExposureLevel, entry["exposure_level"], f"{where}: exposure_level")
        if item.vex_status is None and (item.exploitation_state is None or item.technical_impact is None):
            raise AssessmentError(
                f"{where} ({finding_id}): exploitation_state und technical_impact sind Pflicht, "
                "sofern kein vex_status angegeben ist"
            )
        for point in ("exploitation", "exposure", "technical_impact"):
            value_key = "exploitation_state" if point == "exploitation" else (
                "exposure_level" if point == "exposure" else "technical_impact")
            if entry.get(value_key) is not None and not entry.get(f"{point}_basis"):
                result.warnings.append(f"{finding_id}: {value_key} ohne {point}_basis")
        if item.vex_status is None and not (entry.get("assessed_by") and entry.get("assessed_on")):
            result.warnings.append(f"{finding_id}: assessed_by/assessed_on fehlen")
        result.findings[finding_id] = item

    for n, entry in enumerate(_as_list(data.get("vex"), f"{source}: vex"), start=1):
        where = f"{source}: vex[{n}]"
        if not isinstance(entry, dict):
            raise AssessmentError(f"{where}: Eintrag muss ein Mapping sein")
        _unknown_keys(entry, _VEX_KEYS, where)
        cve = str(entry.get("cve") or "").strip().upper()
        if not _CVE_RE.fullmatch(cve):
            raise AssessmentError(f"{where}: ungültige CVE-Kennung: {entry.get('cve')!r}")
        status = _enum(VexStatus, entry.get("status"), f"{where}: status")
        package = str(entry["package"]).strip() if entry.get("package") else None
        if not entry.get("justification"):
            result.warnings.append(f"{cve}: VEX-Aussage ohne justification")
        result.vex.append(VexStatement(cve=cve, package=package, status=status))
    return result


def apply(findings: list[RawFinding], assessments: Assessments) -> ApplyResult:
    """Transfer assessments and VEX statements to the findings (modifies them in place).

    Findings with a CVE receive a matching VEX statement. Findings without a
    CVE receive the protection need of the product and the assessment with
    their finding identifier.

    Parameters
    ----------
    findings : list[RawFinding]
        Findings to update.
    assessments : Assessments
        Parsed assessment file.

    Returns
    -------
    ApplyResult
        The entries that were used and those without a matching finding.
    """
    result = ApplyResult()
    for finding in findings:
        cve = _cve_of(finding)
        if cve:
            package = finding.raw.get("package")
            for statement in assessments.vex:
                if statement.cve == cve and (statement.package is None or statement.package == package):
                    finding.vex_status = statement.status
                    result.matched.add(_vex_key(statement))
                    break
            continue
        if assessments.protection_level is not None:
            finding.protection_level = assessments.protection_level
        entry = assessments.findings.get(finding.raw.get("finding_id") or "")
        if entry is None:
            continue
        result.matched.add(entry.id)
        if entry.vex_status is not None:
            finding.vex_status = entry.vex_status
        if entry.exploitation_state is not None:
            finding.exploitation_state = entry.exploitation_state
        if entry.technical_impact is not None:
            finding.technical_impact = entry.technical_impact
        if entry.exposure_level is not None:
            finding.exposure_level = entry.exposure_level
    result.orphaned = [k for k in assessments.findings if k not in result.matched]
    result.orphaned += [_vex_key(s) for s in assessments.vex if _vex_key(s) not in result.matched]
    return result


def _vex_key(statement: VexStatement) -> str:
    """Return the key of a VEX statement: ``CVE:package`` or just the CVE."""
    return f"{statement.cve}:{statement.package}" if statement.package else statement.cve


def _cve_of(finding: RawFinding) -> Optional[str]:
    """Return the CVE ID of a finding in upper case, or None if it has none."""
    for value in list(finding.identifiers) + [finding.cwe or ""]:
        match = _CVE_RE.search(value or "")
        if match:
            return match.group(0).upper()
    return None


def _as_list(value: Any, where: str) -> list:
    """Return `value` as a list; None yields an empty list.

    Parameters
    ----------
    value : Any
        Value from the document.
    where : str
        Location used in the error message.

    Raises
    ------
    AssessmentError
        If `value` is neither None nor a list.
    """
    if value is None:
        return []
    if not isinstance(value, list):
        raise AssessmentError(f"{where}: muss eine Liste sein")
    return value


def _unknown_keys(entry: dict, allowed: set[str], where: str) -> None:
    """Check that a mapping contains only allowed keys.

    Parameters
    ----------
    entry : dict
        Mapping to check.
    allowed : set[str]
        Allowed keys.
    where : str
        Location used in the error message.

    Raises
    ------
    AssessmentError
        If `entry` contains a key that is not allowed.
    """
    unknown = sorted(set(map(str, entry)) - allowed)
    if unknown:
        raise AssessmentError(f"{where}: unbekannte Schlüssel: {', '.join(unknown)}")


def _enum(enum_cls, value: Any, where: str):
    """Convert a document value to a member of an enumeration.

    Parameters
    ----------
    enum_cls : type[Enum]
        Enumeration to convert to.
    value : Any
        Value from the document; surrounding whitespace is ignored.
    where : str
        Location used in the error message.

    Returns
    -------
    Enum
        The matching member of `enum_cls`.

    Raises
    ------
    AssessmentError
        If `value` is not a member of the enumeration.
    """
    try:
        return enum_cls(str(value).strip())
    except ValueError as exc:
        allowed = " | ".join(e.value for e in enum_cls)
        raise AssessmentError(f"{where}: unbekannter Wert {value!r} (zulässig: {allowed})") from exc
