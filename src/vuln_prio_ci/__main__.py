"""Command line for the pipeline.

    python -m vuln_prio_ci run --report-dir . --assessments security/prioritization-assessments.yaml \\
        --output prioritization.json --codequality gl-code-quality-report.json
                                        Operating mode 1: findings of the pipeline run (report artifacts)
    python -m vuln_prio_ci run --gitlab-csv inventory.csv --cve-only --output prioritization.json
                                        Operating mode 2: inventory of the main branch (export), method 1 only
    python -m vuln_prio_ci run --cve CVE-2021-44228 [--cve ...]
                                        prioritise single CVEs, output only in the terminal
    python -m vuln_prio_ci run --cve CVE-2021-44228 [--cve ...] --cvss-method
                                        the same by the CVSS base score alone (rules/decision_table_cvss.csv)
    python -m vuln_prio_ci fetch-bundle --project gruppe/vuln-prio-ci
                                        load the latest signal bundle into CACHE_DIR
    python -m vuln_prio_ci publish-bundle --project $CI_PROJECT_ID
                                        publish the signal bundle from CACHE_DIR (daily run)
    python -m vuln_prio_ci export-inventory --project $CI_PROJECT_ID --output inventory.csv
                                        export the vulnerability inventory (GITLAB_API_TOKEN needed)

Exit codes of `run`: 0, 3, 4, 5 see ci/run.py; 1 = technical error.
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import date
from pathlib import Path

from .ci import gitlab_api, run
from .config import get_settings
from .models import ExposureLevel
from .tls import CaBundleOutdated, check_ca_bundle


def _cmd_run(args) -> int:
    """Run the ``run`` command: prioritise findings and write the outputs.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed command-line arguments.

    Returns
    -------
    int
        Exit code of the run, or 1 on a technical error.
    """
    opts = run.RunOptions(
        reports=[Path(p) for p in args.report],
        report_dir=Path(args.report_dir) if args.report_dir else None,
        gitlab_csv=Path(args.gitlab_csv) if args.gitlab_csv else None,
        assessments=Path(args.assessments) if args.assessments else None,
        output=Path(args.output) if args.output else None,
        codequality=Path(args.codequality) if args.codequality else None,
        max_age_days=args.max_age_days,
        cve_only=args.cve_only,
        default_exposure=ExposureLevel(args.default_exposure),
        image_path=args.image_path,
        offline=not args.online,
        today=args.today,
        cves=args.cve,
        cvss_method=args.cvss_method,
    )
    try:
        outcome = run.execute(opts)
    except run.RunError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return run.EXIT_ERROR
    if opts.cves:
        # Single CVEs: result only in the terminal, no files
        print(run.render_cves(outcome))
        return outcome.exit_code
    run.write_outputs(outcome, opts)
    print(run.render_log(outcome, opts.assessments))
    return outcome.exit_code


def _cmd_fetch(args) -> int:
    """Run the ``fetch-bundle`` command: download the signal bundle.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed command-line arguments.

    Returns
    -------
    int
        0 on success, 1 on an API error.
    """
    dest = Path(args.dest or get_settings().cache_dir)
    try:
        version, names = gitlab_api.fetch_bundle(args.project, dest, args.version)
    except gitlab_api.ApiError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return run.EXIT_ERROR
    print(f"Signalpaket {version} geladen nach {dest}: {', '.join(names)}")
    return 0


def _cmd_publish(args) -> int:
    """Run the ``publish-bundle`` command: write the manifest and upload the signal bundle.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed command-line arguments.

    Returns
    -------
    int
        0 on success, 1 on an API error.
    """
    from .sources import manifest
    cache_dir = Path(args.cache_dir or get_settings().cache_dir)
    manifest.write(cache_dir)
    try:
        version = gitlab_api.publish_bundle(cache_dir, args.project, args.version)
    except gitlab_api.ApiError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return run.EXIT_ERROR
    print(f"Signalpaket {version} veröffentlicht ({gitlab_api.PACKAGE_NAME})")
    return 0


def _cmd_export(args) -> int:
    """Run the ``export-inventory`` command: export the vulnerability inventory.

    Parameters
    ----------
    args : argparse.Namespace
        Parsed command-line arguments.

    Returns
    -------
    int
        0 on success, 1 on an API error.
    """
    try:
        path = gitlab_api.export_inventory(args.project, args.output, timeout_s=args.timeout)
    except gitlab_api.ApiError as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return run.EXIT_ERROR
    print(f"Schwachstellenbestand exportiert: {path}")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the command line of the pipeline.

    Parameters
    ----------
    argv : list[str], optional
        Command-line arguments. Defaults to ``sys.argv[1:]``.

    Returns
    -------
    int
        Exit code of the chosen command; 1 if the CA bundle is outdated.
    """
    parser = argparse.ArgumentParser(prog="python -m vuln_prio_ci")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("run", help="Befunde priorisieren (Exit-Code 0/3/4/5, 1 bei Fehler)")
    p.add_argument("--report", action="append", default=[], help="GitLab-Sicherheitsbericht (mehrfach)")
    p.add_argument("--report-dir", help="Verzeichnis mit gl-sast/-dependency-scanning/-container-scanning-report.json")
    p.add_argument("--gitlab-csv", help="CSV-Export des Vulnerability Reports (Betriebsart 2)")
    p.add_argument("--cve", action="append", default=[],
                   help="CVE-Kennung priorisieren, Ausgabe nur im Terminal (mehrfach)")
    p.add_argument("--cvss-method", action="store_true",
                   help="mit --cve: nur nach CVSS-Basiswert entscheiden (rules/decision_table_cvss.csv)")
    p.add_argument("--assessments", help="Einschätzungsdatei (YAML) im Repository")
    p.add_argument("--output", help="Ergebnisdatei (JSON)")
    p.add_argument("--codequality", help="Code-Quality-Bericht (JSON) für artifacts:reports:codequality")
    p.add_argument("--max-age-days", type=int, default=2, help="Höchstalter des Signalpakets in Tagen")
    p.add_argument("--cve-only", action="store_true", help="nur Befunde mit CVE (Verfahren 1)")
    p.add_argument("--default-exposure", choices=[e.value for e in ExposureLevel], default="remote")
    p.add_argument("--image-path", default="Dockerfile",
                   help="Pfad im Repository für Container-Scanning-Befunde im Code-Quality-Bericht")
    p.add_argument("--online", action="store_true", help="EUVD-Einzelabruf erlauben (Standard: aus)")
    p.add_argument("--today", type=date.fromisoformat, help=argparse.SUPPRESS)
    p.set_defaults(func=_cmd_run)

    p = sub.add_parser("fetch-bundle", help="jüngstes Signalpaket laden")
    p.add_argument("--project", required=True, help="ID oder Pfad des Projekts vuln-prio-ci")
    p.add_argument("--version", help="bestimmte Paketversion statt der jüngsten")
    p.add_argument("--dest", help="Zielverzeichnis (Standard: CACHE_DIR)")
    p.set_defaults(func=_cmd_fetch)

    p = sub.add_parser("publish-bundle", help="Signalpaket aus CACHE_DIR veröffentlichen")
    p.add_argument("--project", required=True, help="ID oder Pfad des Projekts vuln-prio-ci")
    p.add_argument("--version", help="Paketversion (Standard: Zeitstempel UTC)")
    p.add_argument("--cache-dir", help="Verzeichnis der Referenzdaten (Standard: CACHE_DIR)")
    p.set_defaults(func=_cmd_publish)

    p = sub.add_parser("export-inventory", help="Schwachstellenbestand des Hauptzweigs exportieren")
    p.add_argument("--project", required=True, help="ID oder Pfad des Produktprojekts")
    p.add_argument("--output", required=True)
    p.add_argument("--timeout", type=int, default=600, help="Wartezeit auf den Export in Sekunden")
    p.set_defaults(func=_cmd_export)

    args = parser.parse_args(argv)
    if args.command == "run" and args.cvss_method and not args.cve:
        parser.error("--cvss-method nur zusammen mit --cve (Ausgabe nur im Terminal)")
    if args.command == "run" and args.cve:
        conflicting = [name for name, value in (("--report", args.report), ("--report-dir", args.report_dir),
                                                ("--gitlab-csv", args.gitlab_csv), ("--output", args.output),
                                                ("--codequality", args.codequality)) if value]
        if conflicting:
            parser.error(f"--cve nicht zusammen mit {', '.join(conflicting)} (Ausgabe nur im Terminal)")
    logging.basicConfig(level=logging.WARNING, format="%(levelname)s %(name)s: %(message)s")
    if args.command != "run" or args.online:
        # Network access only with a cleaned-up CA bundle (vuln_prio_ci/tls.py)
        try:
            check_ca_bundle()
        except CaBundleOutdated as exc:
            print(f"FEHLER: {exc}", file=sys.stderr)
            return run.EXIT_ERROR
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
