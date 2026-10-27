"""Command line for fetching external reference data.

    python -m vuln_prio_ci.sources epss                    latest daily EPSS file
    python -m vuln_prio_ci.sources epss --date 2026-09-01  daily file of a reference date (pinned)
    python -m vuln_prio_ci.sources exploitdb [--ref SHA]   Exploit-DB, branch main or commit (pinned)
    python -m vuln_prio_ci.sources metasploit [--ref SHA]  Metasploit, branch master or commit (pinned)
    python -m vuln_prio_ci.sources metasploit --as-of 2025-07-01
                                                  last commit up to the end of the reference date (pinned,
                                                  for the evaluation at observation time T)
    python -m vuln_prio_ci.sources kev                     KEV dump (cumulative, no snapshot/pinning needed)
    python -m vuln_prio_ci.sources nvd [--full]            CVSS base scores from the NVD (incremental or full)
    python -m vuln_prio_ci.sources all                     all sources, latest state each (for the schedule)
    python -m vuln_prio_ci.sources manifest                write bundle-manifest.json to CACHE_DIR
    python -m vuln_prio_ci.sources unpin epss 2026-09-01   remove a pin (also: unpin exploitdb|metasploit SHA),
                                                  then apply retention
"""

from __future__ import annotations

import argparse
import logging
import sys
from contextlib import closing
from datetime import date

from pathlib import Path

from .. import store
from ..config import get_settings
from ..enrich import kev
from ..store import epss as epss_store
from ..store import exploits as exploit_store
from ..tls import CaBundleOutdated, check_ca_bundle
from . import common, epss, exploitdb, manifest, metasploit, nvd


def _run_kev() -> None:
    """Refresh the KEV dump and report the result.

    Raises
    ------
    common.SourceError
        If the KEV dump could not be fetched.
    """
    if kev.refresh():
        print("KEV-Dump gespeichert")
    else:
        raise common.SourceError("KEV-Dump-Abruf fehlgeschlagen")


def _run_epss(day: date | None) -> None:
    """Fetch an EPSS daily file and print a summary.

    Parameters
    ----------
    day : date or None
        Score date to fetch, or None for the latest daily file.
    """
    result = epss.sync(day)
    s = result.snapshot
    status = "gespeichert" if result.stored else "unverändert (bereits vorhanden)"
    print(f"EPSS {s.score_date} Modell {s.model_version or 'unbekannt'}: {s.row_count} CVEs, {status}")
    if result.pruned:
        print("  entfernte Snapshots: " + ", ".join(d.isoformat() for d in result.pruned))


def _run_git_source(label: str, module, ref: str | None, as_of: date | None = None) -> None:
    """Fetch a Git-based source and print a summary.

    Parameters
    ----------
    label : str
        Display name of the source used in the output.
    module : module
        Source module providing ``commit_before`` and ``sync``.
    ref : str or None
        Commit SHA to fetch, or None for the latest state.
    as_of : date, optional
        Reference date; the last commit up to the end of that day is fetched.
        Mutually exclusive with `ref`.

    Raises
    ------
    common.SourceError
        If both `ref` and `as_of` are given, or the fetch fails.
    """
    if as_of is not None:
        if ref is not None:
            raise common.SourceError("--ref und --as-of schließen einander aus")
        ref = module.commit_before(as_of)
        print(f"{label}: letzter Commit bis {as_of.isoformat()} = {ref[:8]}")
    result = module.sync(ref)
    s = result.snapshot
    status = "gespeichert" if result.stored else "unverändert (bereits vorhanden)"
    print(f"{label} {s.commit_sha[:8]} vom {s.committed_at}: {s.ref_count} CVE-Referenzen, "
          f"{s.skipped_count} unlesbare übersprungen, {status}")
    if result.pruned:
        print("  entfernte Snapshots: " + ", ".join(sha[:8] for sha in result.pruned))


def _run_nvd(full: bool) -> None:
    """Reconcile the NVD CVSS scores and print a summary.

    Parameters
    ----------
    full : bool
        Load the complete data set instead of only the changes.
    """
    result = nvd.sync(full=full)
    kind = "vollständig" if result.full_load else "inkrementell"
    print(f"NVD ({kind}) bis {result.synced_until}: {result.updated} Bewertungen übernommen, "
          f"{result.removed} ohne verwendbare Bewertung")


def _run_manifest() -> None:
    """Write the bundle manifest to the cache directory and print its path."""
    path = manifest.write(Path(get_settings().cache_dir))
    print(f"Manifest geschrieben: {path}")


def _run_unpin(source: str, snapshot: str) -> int:
    """Remove the pin of a snapshot, apply retention and print the result.

    Parameters
    ----------
    source : str
        ``'epss'``, ``'exploitdb'`` or ``'metasploit'``.
    snapshot : str
        EPSS: score date ``YYYY-MM-DD``; Exploit-DB/Metasploit: commit SHA, possibly abbreviated.

    Returns
    -------
    int
        Exit code: 0 on success, 1 if the snapshot is unknown or the SHA is ambiguous.
    """
    settings = get_settings()
    with closing(store.connect()) as conn:
        if source == "epss":
            try:
                day = date.fromisoformat(snapshot)
            except ValueError:
                print(f"unpin: ungültiges Bezugsdatum {snapshot!r} (erwartet YYYY-MM-DD)", file=sys.stderr)
                return 1
            if not epss_store.unpin(conn, day):
                print(f"unpin: kein EPSS-Snapshot vom {day.isoformat()}", file=sys.stderr)
                return 1
            print(f"EPSS {day.isoformat()}: Anheftung aufgehoben")
            pruned = [d.isoformat() for d in epss_store.prune(conn, settings.epss_keep_snapshots)]
        else:
            matches = exploit_store.unpin(conn, source, snapshot)
            if not matches:
                print(f"unpin: kein {source}-Snapshot zum Commit {snapshot!r}", file=sys.stderr)
                return 1
            if len(matches) > 1:
                print(f"unpin: Commit {snapshot!r} ist mehrdeutig: " + ", ".join(m[:12] for m in matches),
                      file=sys.stderr)
                return 1
            print(f"{source} {matches[0][:8]}: Anheftung aufgehoben")
            pruned = [sha[:8] for sha in exploit_store.prune(conn, source, settings.exploit_keep_snapshots)]
    if pruned:
        print("  entfernte Snapshots: " + ", ".join(pruned))
    return 0


def main(argv: list[str] | None = None) -> int:
    """Run the command line for fetching reference data.

    Parameters
    ----------
    argv : list[str], optional
        Command-line arguments. Defaults to ``sys.argv[1:]``.

    Returns
    -------
    int
        Exit code: 0 on success, 1 if the CA bundle is outdated or at least one
        source failed to fetch.
    """
    parser = argparse.ArgumentParser(prog="python -m vuln_prio_ci.sources")
    sub = parser.add_subparsers(dest="source", required=True)
    p_epss = sub.add_parser("epss", help="EPSS-Tagesdatei beziehen")
    p_epss.add_argument("--date", type=date.fromisoformat, help="Bezugsdatum YYYY-MM-DD (Standard: jüngste Datei)")
    for name in ("exploitdb", "metasploit"):
        p = sub.add_parser(name, help=f"{name}-Snapshot beziehen")
        group = p.add_mutually_exclusive_group()
        group.add_argument("--ref", help="Commit-SHA (Standard: jüngster Stand des Hauptbranches)")
        group.add_argument("--as-of", type=date.fromisoformat,
                           help="Stichtag YYYY-MM-DD: letzter Commit bis Ende dieses Tages (wird angeheftet)")
    sub.add_parser("kev", help="KEV-Dump beziehen")
    p_nvd = sub.add_parser("nvd", help="CVSS-Basiswerte der NVD beziehen")
    p_nvd.add_argument("--full", action="store_true", help="vollständigen Bestand statt Änderungen laden")
    sub.add_parser("all", help="alle Quellen beziehen")
    sub.add_parser("manifest", help="Manifest des Signalpakets schreiben")
    p_unpin = sub.add_parser("unpin", help="Anheftung eines Snapshots aufheben (danach greift die Aufbewahrung)")
    p_unpin.add_argument("target", choices=("epss", "exploitdb", "metasploit"), help="Quelle des Snapshots")
    p_unpin.add_argument("snapshot", help="EPSS: Bezugsdatum YYYY-MM-DD; exploitdb/metasploit: Commit-SHA (auch gekürzt)")
    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

    if args.source == "unpin":
        return _run_unpin(args.target, args.snapshot)

    jobs = {
        "epss": lambda: _run_epss(getattr(args, "date", None)),
        "exploitdb": lambda: _run_git_source("Exploit-DB", exploitdb, getattr(args, "ref", None), getattr(args, "as_of", None)),
        "metasploit": lambda: _run_git_source("Metasploit", metasploit, getattr(args, "ref", None), getattr(args, "as_of", None)),
        "kev": _run_kev,
        "nvd": lambda: _run_nvd(getattr(args, "full", False)),
    }
    if args.source == "manifest":
        _run_manifest()
        return 0
    try:
        check_ca_bundle()
    except CaBundleOutdated as exc:
        print(f"FEHLER: {exc}", file=sys.stderr)
        return 1
    selected = list(jobs) if args.source == "all" else [args.source]

    failed = False
    for name in selected:
        try:
            jobs[name]()
        except common.SourceError as exc:
            print(f"{name}: Bezug fehlgeschlagen: {exc}", file=sys.stderr)
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
