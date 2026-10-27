"""Prioritisation run in the pipeline: read findings, apply assessments, decide, and write the
result, the Code Quality report and the exit code.

Exit codes (chapter 6, table of exit codes):
    0  no finding of level Sofort or Außerplanmäßig, all findings decided, bundle up to date
    3  limited result: findings without assessment or signal bundle older than the maximum age
    4  at least one finding of level Außerplanmäßig
    5  at least one finding of level Sofort
    1  technical error (report missing/invalid, signal bundle missing, assessment file invalid)
If several conditions apply, the highest code is used; the others are listed in the log.
Codes 3 to 5 are permitted in the pipeline via allow_failure:exit_codes (warning only).
"""

from __future__ import annotations

import json
import logging
import os
from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

from ..config import get_settings
from ..ingest import assessments as assessments_mod
from ..ingest import gitlab_report
from ..ingest.gitlab_semgrep import parse_csv_with_stats
from ..models import ExposureLevel, PrioritizationResult, PriorityLevel, RawFinding
from ..normalize.identifiers import normalize
from ..pipeline import SkippedFinding, prioritize_findings
from . import codequality, freshness

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_LIMITED = 3
EXIT_URGENT = 4
EXIT_IMMEDIATE = 5

log = logging.getLogger(__name__)


class RunError(Exception):
    """Raised on a technical error: the run yields no usable result (exit code 1)."""


@dataclass
class RunOptions:
    """Options of a prioritisation run.

    Attributes
    ----------
    reports : list[Path]
        GitLab security reports (JSON).
    report_dir : Path or None
        Directory searched for the known report files.
    gitlab_csv : Path or None
        CSV export of the GitLab vulnerability report.
    assessments : Path or None
        Assessment file in the repository.
    output : Path or None
        File for the JSON result.
    codequality : Path or None
        File for the Code Quality report.
    max_age_days : int
        Maximum permitted age of the signal bundle in days.
    cve_only : bool
        Only prioritise findings with a CVE.
    default_exposure : ExposureLevel
        Exposure assumed when an assessment gives none.
    image_path : str
        Path reported for findings without a file in the Code Quality report.
    offline : bool
        Disable live EUVD lookups.
    today : date or None
        Reference day for the freshness check. Defaults to the current day.
    """

    reports: list[Path] = field(default_factory=list)
    report_dir: Optional[Path] = None
    gitlab_csv: Optional[Path] = None
    assessments: Optional[Path] = None
    output: Optional[Path] = None
    codequality: Optional[Path] = None
    max_age_days: int = 2
    cve_only: bool = False
    default_exposure: ExposureLevel = ExposureLevel.remote
    image_path: str = "Dockerfile"
    offline: bool = True
    today: Optional[date] = None


@dataclass
class RunOutcome:
    """Outcome of a prioritisation run.

    Attributes
    ----------
    exit_code : int
        Exit code of the run.
    results : list[PrioritizationResult]
        Prioritised findings.
    undecided : list[SkippedFinding]
        Findings skipped for lack of an assessment.
    vex_skipped : list[SkippedFinding]
        Findings excluded by a VEX statement.
    orphaned : list[str]
        Assessment entries without a matching finding.
    warnings : list[str]
        Notes on the assessment file.
    freshness : Freshness or None
        Result of the freshness check, None if no finding has a CVE.
    inputs : list[str]
        Names of the input files.
    status_skipped : dict
        Number of rows left out of the CSV export per status.
    """

    exit_code: int
    results: list[PrioritizationResult]
    undecided: list[SkippedFinding]
    vex_skipped: list[SkippedFinding]
    orphaned: list[str]
    warnings: list[str]
    freshness: Optional[freshness.Freshness]
    inputs: list[str]
    status_skipped: dict


def _load_findings(opts: RunOptions) -> tuple[list[RawFinding], list[str], dict]:
    """Read the findings from all configured inputs.

    Parameters
    ----------
    opts : RunOptions
        Run options naming the inputs.

    Returns
    -------
    findings : list[RawFinding]
        All findings.
    inputs : list[str]
        Names of the input files.
    status_skipped : dict
        Rows left out of the CSV export per status.

    Raises
    ------
    RunError
        If no input is given, a report is missing or invalid, or the CSV export
        is not found.
    """
    paths = list(opts.reports)
    if opts.report_dir is not None:
        found = gitlab_report.find_reports(opts.report_dir)
        if not found:
            raise RunError(f"keine Sicherheitsberichte in {opts.report_dir} "
                           f"({', '.join(gitlab_report.REPORT_FILES)})")
        paths += found
    findings: list[RawFinding] = []
    inputs: list[str] = []
    status_skipped: dict = {}
    for path in paths:
        try:
            findings += gitlab_report.load_report(path)
        except gitlab_report.ReportError as exc:
            raise RunError(str(exc)) from exc
        inputs.append(Path(path).name)
    if opts.gitlab_csv is not None:
        try:
            content = Path(opts.gitlab_csv).read_text(encoding="utf-8-sig")
        except FileNotFoundError as exc:
            raise RunError(f"CSV-Export nicht gefunden: {opts.gitlab_csv}") from exc
        rows, skipped = parse_csv_with_stats(content)
        for row in rows:
            row.raw.setdefault("report_type", None)
        findings += rows
        inputs.append(Path(opts.gitlab_csv).name)
        status_skipped = dict(skipped)
    if not inputs:
        raise RunError("keine Eingabe: --report, --report-dir oder --gitlab-csv angeben")
    return findings, inputs, status_skipped


def execute(opts: RunOptions) -> RunOutcome:
    """Run the prioritisation.

    Reads the findings, applies the assessment file, checks the freshness of
    the signal bundle, prioritises, and derives the exit code. The highest
    applicable code wins: 5 (immediate), 4 (urgent), 3 (limited), 0 (ok).

    Parameters
    ----------
    opts : RunOptions
        Run options.

    Returns
    -------
    RunOutcome
        Results, skipped findings, warnings and the exit code.

    Raises
    ------
    RunError
        On a technical error: invalid or missing input, invalid assessment
        file, or missing signal bundle.
    """
    if opts.offline:
        os.environ["EUVD_LIVE_LOOKUP"] = "false"
        get_settings.cache_clear()

    findings, inputs, status_skipped = _load_findings(opts)
    if opts.cve_only:
        findings = [f for f in findings if normalize(f).cve_present]

    warnings: list[str] = []
    orphaned: list[str] = []
    if opts.assessments is not None:
        if Path(opts.assessments).is_file():
            try:
                parsed = assessments_mod.load(opts.assessments)
            except assessments_mod.AssessmentError as exc:
                raise RunError(f"Einschätzungsdatei ungültig: {exc}") from exc
            applied = assessments_mod.apply(findings, parsed)
            warnings += parsed.warnings
            orphaned = applied.orphaned
            if opts.cve_only:
                # Findings without a CVE are excluded, so their assessments are not orphaned
                orphaned = [o for o in orphaned if o not in parsed.findings]
        else:
            warnings.append(f"Einschätzungsdatei {opts.assessments} nicht vorhanden")

    fresh = None
    if any(normalize(f).cve_present for f in findings):
        try:
            fresh = freshness.check(get_settings().cache_dir, opts.max_age_days, opts.today)
        except freshness.BundleMissing as exc:
            raise RunError(str(exc)) from exc

    skipped: list[SkippedFinding] = []
    results = prioritize_findings(findings, default_exposure=opts.default_exposure, skipped=skipped)
    undecided = [s for s in skipped if s.reason == "undecided"]
    vex_skipped = [s for s in skipped if s.reason == "vex"]

    levels = {r.priority for r in results}
    if PriorityLevel.immediate in levels:
        code = EXIT_IMMEDIATE
    elif PriorityLevel.urgent in levels:
        code = EXIT_URGENT
    elif undecided or (fresh is not None and fresh.limited):
        code = EXIT_LIMITED
    else:
        code = EXIT_OK
    return RunOutcome(code, results, undecided, vex_skipped, orphaned, warnings, fresh, inputs, status_skipped)


# --- Output ----------------------------------------------------------------------------------------

_ORDER = [PriorityLevel.immediate, PriorityLevel.urgent, PriorityLevel.planned, PriorityLevel.deferred]


def _sorted(results: list[PrioritizationResult]) -> list[PrioritizationResult]:
    """Sort results by priority level, then descending rank, then title."""
    return sorted(results, key=lambda r: (_ORDER.index(r.priority), -(r.priority_rank or 0), r.title))


def write_outputs(outcome: RunOutcome, opts: RunOptions) -> None:
    """Write the JSON result and the Code Quality report, as far as configured.

    Parameters
    ----------
    outcome : RunOutcome
        Outcome of the run.
    opts : RunOptions
        Run options naming the output files (``output``, ``codequality``).
    """
    if opts.output is not None:
        payload = {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "exit_code": outcome.exit_code,
            "inputs": outcome.inputs,
            "summary": summary_counts(outcome),
            "reference_data": outcome.freshness.as_dict() if outcome.freshness else None,
            "results": [r.model_dump(mode="json") for r in _sorted(outcome.results)],
            "undecided": [_skipped_dict(s) for s in outcome.undecided],
            "vex_skipped": [_skipped_dict(s) for s in outcome.vex_skipped],
            "orphaned_assessments": outcome.orphaned,
            "assessment_warnings": outcome.warnings,
            "status_skipped": outcome.status_skipped,
        }
        Path(opts.output).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    if opts.codequality is not None:
        report = codequality.build(outcome.results, outcome.undecided, image_path=opts.image_path)
        Path(opts.codequality).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")


def _skipped_dict(s: SkippedFinding) -> dict:
    """Convert a skipped finding into a dictionary for the JSON output."""
    return {"title": s.finding.title, "finding_id": s.finding.raw.get("finding_id"),
            "location": s.finding.location, "scanner": s.finding.scanner, "detail": s.detail}


def summary_counts(outcome: RunOutcome) -> dict:
    """Count the results per priority level and the skipped findings.

    Parameters
    ----------
    outcome : RunOutcome
        Outcome of the run.

    Returns
    -------
    dict
        Counts keyed by the German level labels, plus ``"ohne Einschätzung"``
        and ``"VEX ausgenommen"``.
    """
    counts = Counter(r.priority for r in outcome.results)
    return {
        "Sofort": counts.get(PriorityLevel.immediate, 0),
        "Außerplanmäßig": counts.get(PriorityLevel.urgent, 0),
        "Planmäßig": counts.get(PriorityLevel.planned, 0),
        "Zurückgestellt": counts.get(PriorityLevel.deferred, 0),
        "ohne Einschätzung": len(outcome.undecided),
        "VEX ausgenommen": len(outcome.vex_skipped),
    }


_EXIT_TEXT = {
    EXIT_OK: "keine Warnung",
    EXIT_LIMITED: "Warnung: Ergebnis eingeschränkt (Einschätzungen fehlen oder Signalpaket veraltet)",
    EXIT_URGENT: "Warnung: Befund der Stufe Außerplanmäßig",
    EXIT_IMMEDIATE: "Warnung: Befund der Stufe Sofort",
}


def render_log(outcome: RunOutcome, assessments_path: Optional[Path]) -> str:
    """Render the human-readable log of a run.

    Lists the summary, bundle state, immediate and urgent findings, findings
    without assessment (with a template for the assessment file), orphaned
    entries, warnings and the exit code.

    Parameters
    ----------
    outcome : RunOutcome
        Outcome of the run.
    assessments_path : Path or None
        Assessment file named in the template for undecided findings.

    Returns
    -------
    str
        The log text.
    """
    lines = [f"Priorisierung der Befunde aus: {', '.join(outcome.inputs)}"]
    counts = summary_counts(outcome)
    lines.append("  " + ", ".join(f"{k}: {v}" for k, v in counts.items()))
    if outcome.status_skipped:
        lines.append("  nach Status nicht übernommen: "
                     + ", ".join(f"{k}: {v}" for k, v in outcome.status_skipped.items()))
    fresh = outcome.freshness
    if fresh is not None:
        epss = (fresh.sources.get("epss") or {})
        created = fresh.created_at or "ohne Manifest"
        lines.append(f"Signalpaket: erstellt {created}, Alter {fresh.age_days} Tag(e), "
                     f"Höchstalter {fresh.max_age_days}; EPSS {epss.get('score_date')} "
                     f"(Modell {epss.get('model_version')})")
        if fresh.stale:
            lines.append("WARNUNG: Signalpaket älter als das Höchstalter – Ergebnis eingeschränkt.")
        if fresh.missing_sources:
            lines.append("WARNUNG: Quellen fehlen im Signalpaket: " + ", ".join(fresh.missing_sources))

    for r in _sorted(outcome.results):
        if r.priority not in (PriorityLevel.immediate, PriorityLevel.urgent):
            continue
        label = codequality.LEVEL_LABEL[r.priority]
        lines.append(f"[{label}] {r.cve_id or r.finding_id or r.title} – {r.location or ''}")
        lines.append(f"    {r.decision_note}")

    if outcome.undecided:
        target = assessments_path or "Einschätzungsdatei"
        lines.append(f"Ohne Einschätzung (Verfahren 2): {len(outcome.undecided)} Befund(e). "
                     f"Vorlage für {target}:")
        lines.append("findings:")
        for s in outcome.undecided:
            lines.append(f'  - id: "{s.finding.raw.get("finding_id")}"')
            lines.append(f'    title: "{s.finding.title}"')
            lines.append("    exploitation_state:      # none | poc | active")
            lines.append("    exploitation_basis: \"\"")
            lines.append("    exposure_level:          # lokal | intern | remote (leer: remote)")
            lines.append("    exposure_basis: \"\"")
            lines.append("    technical_impact:        # partial | total")
            lines.append("    technical_impact_basis: \"\"")
            lines.append("    assessed_by: \"\"")
            lines.append("    assessed_on: ")
    if outcome.orphaned:
        lines.append("Einträge der Einschätzungsdatei ohne passenden Befund (verwaist): "
                     + ", ".join(outcome.orphaned))
    for warning in outcome.warnings:
        lines.append(f"Hinweis Einschätzungsdatei: {warning}")
    lines.append(f"Exit-Code {outcome.exit_code}: {_EXIT_TEXT[outcome.exit_code]}")
    return "\n".join(lines)
