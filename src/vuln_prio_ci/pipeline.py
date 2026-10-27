"""Orchestration of the prioritisation pipeline.

Each step is a module of its own; here they are chained in a fixed order:
normalisation -> identifier resolution -> VEX pre-filter -> enrichment -> evidence grade/CVSS range
-> exposure/protection need (with defaults). The result per finding is a priority level, plus the
plain CVSS rating as a comparison baseline.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from .config import get_settings
from .decide.evidence import derive_evidence_grade
from .decide.priority import decide_priority
from .decide.protection import combined_business_impact_level, derive_protection_level
from .enrich import cvss, epss, euvd, exploits, kev, nvd
from .models import (
    EnrichedFinding,
    EnrichmentStatus,
    ExposureLevel,
    ImpactSignals,
    PrioritizationMethod,
    PrioritizationResult,
    RawFinding,
    VexStatus,
)
from .normalize.identifiers import normalize

logger = logging.getLogger(__name__)

# VEX pre-filter: these states are not prioritised (appendix C / AP-5).
_VEX_SKIP_STATUSES = {VexStatus.not_affected, VexStatus.fixed}


@dataclass
class SkippedFinding:
    """A finding that was not prioritised.

    Attributes
    ----------
    finding : RawFinding
        The skipped finding.
    reason : str
        ``"vex"`` (VEX pre-filter) or ``"undecided"`` (decision not possible,
        e.g. method 2 without an assessment).
    detail : str
        The VEX status, or the error message explaining the missing decision.
    """

    finding: RawFinding
    reason: str
    detail: str


def prioritize_findings(
    findings: list[RawFinding],
    default_exposure: ExposureLevel = ExposureLevel.remote,
    project_id: Optional[int] = None,
    skipped: Optional[list[SkippedFinding]] = None,
) -> list[PrioritizationResult]:
    """Prioritise the findings.

    Skipped findings are logged and, if `skipped` is passed, collected there
    with the reason (CI output).

    Parameters
    ----------
    findings : list[RawFinding]
        Findings to prioritise.
    default_exposure : ExposureLevel, optional
        Exposure assumed when a finding gives none (default ``remote``).
    project_id : int, optional
        Project ID (currently unused).
    skipped : list[SkippedFinding], optional
        List that receives the findings that were not prioritised.

    Returns
    -------
    list[PrioritizationResult]
        One result per prioritised finding, in input order.
    """
    settings = get_settings()
    results: list[PrioritizationResult] = []
    kev_index = kev.load_index()   # EUVD-consolidated KEV dump (cached)

    # one snapshot per source for the whole run
    with epss.open_lookup() as epss_lookup, exploits.open_lookup() as exploit_lookup, \
            nvd.open_lookup() as nvd_lookup:
        for raw in findings:
            # [2] Normalisation + identifier hierarchy
            norm = normalize(raw)
            _resolve_pending_identifier(norm)

            # VEX pre-filter: not_affected/fixed are not prioritised (documented in the log).
            if raw.vex_status in _VEX_SKIP_STATUSES:
                logger.info(
                    "VEX %s: %s (%s) wird nicht priorisiert",
                    raw.vex_status.value, norm.title, norm.cve_id or norm.euvd_id or norm.finding_fingerprint,
                )
                if skipped is not None:
                    skipped.append(SkippedFinding(raw, "vex", raw.vex_status.value))
                continue

            enriched = EnrichedFinding(finding=norm, vex_status=raw.vex_status)
            _apply_exposure(enriched, raw, default_exposure)
            _apply_v2_dimensions(enriched, raw)

            # [3] Enrichment: CVE-keyed sources only if a CVE is present
            cve = norm.cve_id
            if cve:
                if epss_lookup.snapshot:
                    enriched.exploitation.epss_model_version = epss_lookup.snapshot.model_version
                    enriched.exploitation.epss_as_of = epss_lookup.snapshot.score_date
                hit = epss_lookup.score(cve)
                if hit:
                    enriched.exploitation.epss_score, enriched.exploitation.epss_percentile = hit
                k = kev.lookup(kev_index, cve, norm.euvd_id)
                if k:
                    enriched.exploitation.kev_listed = True
                    enriched.exploitation.kev_date_added = k.get("dateAdded")
                    enriched.exploitation.kev_sources = k.get("sources", [])
                if exploit_lookup.exploitdb:
                    enriched.exploitation.exploit_db_commit = exploit_lookup.exploitdb.commit_sha
                    enriched.exploitation.exploit_db_ids = [r.entry_id for r in exploit_lookup.exploit_db(cve)]
                    enriched.exploitation.exploit_db_listed = bool(enriched.exploitation.exploit_db_ids)
                if exploit_lookup.metasploit:
                    enriched.exploitation.metasploit_commit = exploit_lookup.metasploit.commit_sha
                    enriched.exploitation.metasploit_modules = [r.entry_id for r in exploit_lookup.metasploit_modules(cve)]
                    enriched.exploitation.metasploit_listed = bool(enriched.exploitation.metasploit_modules)

            # [3] EUVD as a further CVSS source (single lookup, disabled in offline operation)
            euvd_record = euvd.lookup(cve or norm.euvd_id) if settings.euvd_live_lookup else None

            # [4] Impact: determine CVSS base score and vector (order see _select_cvss)
            vector, base_score, source = _select_cvss(raw, cve, nvd_lookup, euvd_record)
            enriched.impact = _build_impact(vector, base_score, raw.gitlab_severity, settings)
            enriched.impact.cvss_source = source

            # [5] Evidence grade (method 1): only meaningful with a resolved CVE
            if norm.enrichment_status == EnrichmentStatus.resolved:
                enriched.evidence_grade = derive_evidence_grade(enriched.exploitation, settings.epss_threshold)

            _apply_protection_level(enriched, raw)

            if enriched.defaults_applied:
                logger.info("Vorbelegungen für %s: %s", norm.title, ", ".join(enriched.defaults_applied))

            # [6] Decision -> priority level (incl. the CVE-less branch)
            try:
                result = decide_priority(enriched)
            except ValueError as exc:
                # no silent default (AP-4): the finding is skipped and documented, not guessed.
                # Mainly affects method 2 without the supplied SSVC dimensions.
                logger.warning("Befund kann nicht priorisiert werden, übersprungen: %s (%s)", norm.title, exc)
                if skipped is not None:
                    skipped.append(SkippedFinding(raw, "undecided", str(exc)))
                continue
            if result.method == PrioritizationMethod.cve_signals:
                result.epss_threshold_used = settings.epss_threshold
            result.finding_id = raw.raw.get("finding_id")
            result.location = raw.location
            result.scanner = raw.scanner
            result.report_type = raw.raw.get("report_type")
            result.cvss_base_score = enriched.impact.cvss_base_score
            result.cvss_source = enriched.impact.cvss_source
            result.source_file = raw.raw.get("file")
            result.source_line = raw.raw.get("line")
            result.source_id = raw.raw.get("gitlab_id")
            results.append(result)

    return results


def _resolve_pending_identifier(norm) -> None:
    """Resolve identifiers: EUVD/GHSA without CVE -> resolution attempt via the EUVD mapping (AP-5).

    Parameters
    ----------
    norm : NormalizedFinding
        Normalised finding, modified in place. Only findings with status
        ``pending`` are touched: they become ``resolved`` with the CVE found in
        the mapping, otherwise ``cve_less``.
    """
    if norm.enrichment_status != EnrichmentStatus.pending:
        return
    resolved_cve = euvd.cve_for_euvd(norm.euvd_id) if norm.euvd_id else None
    if resolved_cve:
        norm.cve_id = resolved_cve
        norm.cve_present = True
        norm.enrichment_status = EnrichmentStatus.resolved
    else:
        norm.enrichment_status = EnrichmentStatus.cve_less


def _apply_exposure(enriched: EnrichedFinding, raw: RawFinding, default_exposure: ExposureLevel) -> None:
    """Set the exposure per finding; undetermined -> default_exposure (appendix C: remote).

    Parameters
    ----------
    enriched : EnrichedFinding
        Finding to update in place; a used default is recorded in ``defaults_applied``.
    raw : RawFinding
        The raw finding, possibly carrying an assessed exposure level.
    default_exposure : ExposureLevel
        Exposure used if the raw finding gives none.
    """
    if raw.exposure_level is not None:
        enriched.exposure_level = raw.exposure_level
        return
    enriched.exposure_level = default_exposure
    enriched.defaults_applied.append(f"exposure_level={default_exposure.value} (unbestimmt)")


def _apply_v2_dimensions(enriched: EnrichedFinding, raw: RawFinding) -> None:
    """Take over exploitation state and technical impact (method 2): analyst assessment, no default.

    Parameters
    ----------
    enriched : EnrichedFinding
        Finding to update in place.
    raw : RawFinding
        The raw finding carrying the assessed values, which may be None.
    """
    enriched.exploitation_state = raw.exploitation_state
    enriched.technical_impact = raw.technical_impact


def _apply_protection_level(enriched: EnrichedFinding, raw: RawFinding) -> None:
    """Set the protection need (method 2).

    Given directly (assessment file) or the maximum over the protection goals;
    undetermined -> very_high (AP-6).

    Parameters
    ----------
    enriched : EnrichedFinding
        Finding to update in place; a used default is recorded in ``defaults_applied``.
    raw : RawFinding
        The raw finding carrying the protection need or the damage extents.
    """
    if raw.protection_level is not None:
        enriched.impact.protection_level = raw.protection_level
        enriched.protection_level = raw.protection_level
        return
    combined = combined_business_impact_level(raw.business_impact_levels)
    enriched.impact.business_impact_level = combined
    level, is_default = derive_protection_level(combined)
    enriched.impact.protection_level = level
    enriched.protection_level = level
    if is_default:
        enriched.defaults_applied.append(f"protection_level={level.value} (unbestimmt)")


def _select_cvss(raw: RawFinding, cve: Optional[str], nvd_lookup, euvd_record) -> tuple:
    """Select the CVSS base score and vector, using the sources in a fixed order.

    1. explicitly supplied base score (raw.cvss_base_score),
    2. NVD data of the reference data store (selection rule of chapter 5),
    3. base score computed from the 3.x vector of the report (raw.cvss_vector),
    4. single EUVD lookup (only with euvd_live_lookup).

    Parameters
    ----------
    raw : RawFinding
        The raw finding.
    cve : str or None
        CVE ID of the finding.
    nvd_lookup : NvdLookup
        Lookup on the NVD data.
    euvd_record : dict or None
        EUVD record of the finding, if looked up.

    Returns
    -------
    tuple
        ``(vector, base_score, source)``; the base score and source are None if
        no source provides a score.
    """
    vector = raw.raw.get("cvss_vector")
    explicit = raw.raw.get("cvss_base_score")
    if explicit not in (None, ""):
        return vector, float(explicit), "Eingabe"
    if cve:
        record = nvd_lookup.cvss(cve)
        if record is not None:
            return record.vector or vector, record.base_score, f"NVD {record.rating_type} {record.version}"
    computed = cvss.base_score_v3(vector)
    if computed is not None:
        version = cvss.parse_vector(vector)["version"]
        return vector, computed, f"Bericht (Vektor {version})"
    if euvd_record and euvd_record.get("baseScore") is not None:
        return euvd_record.get("baseScoreVector") or vector, float(euvd_record["baseScore"]), "EUVD"
    return vector, None, None


def _build_impact(vector, base_score, gitlab_severity, settings) -> ImpactSignals:
    """Build the impact signals from the CVSS data.

    Parameters
    ----------
    vector : str or None
        CVSS vector string.
    base_score : float or None
        CVSS base score. Without one, the severity falls back to the GitLab
        severity and no CVSS range is set.
    gitlab_severity : str or None
        Severity label assigned by GitLab.
    settings : Settings
        Application settings providing the CVSS range limits.

    Returns
    -------
    ImpactSignals
        Vector, version, metrics, severity band and CVSS range, as far as known.
    """
    impact = ImpactSignals()
    if vector:
        parsed = cvss.parse_vector(vector)
        impact.cvss_vector = vector
        impact.cvss_version = parsed.get("version")
        impact.cvss_metrics = parsed.get("metrics", {})
    if base_score is not None:
        impact.cvss_base_score = float(base_score)
        impact.cvss_severity = cvss.severity_band(float(base_score))
        impact.cvss_band = cvss.cvss_band(
            float(base_score), high=settings.cvss_band_high, critical=settings.cvss_band_critical
        )
    elif gitlab_severity:
        impact.cvss_severity = cvss.severity_from_gitlab(gitlab_severity)
        # no CVSS base score -> impact.cvss_band stays None (special case, see decide/priority.py).
    return impact
