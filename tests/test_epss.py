import gzip
from contextlib import closing
from datetime import date

import pytest

from vuln_prio_ci.config import get_settings
from vuln_prio_ci.enrich import epss as epss_enrich
from vuln_prio_ci.sources import __main__ as sources_cli
from vuln_prio_ci.sources import common
from vuln_prio_ci.sources import epss as epss_source
from vuln_prio_ci.store import connect
from vuln_prio_ci.store import epss as epss_store

CURRENT = (
    "#model_version:v2026.06.15,score_date:2026-09-12T12:00:22Z\n"
    "cve,epss,percentile\n"
    "CVE-1999-0001,0.03351,0.87994\n"
    "CVE-2021-44228,0.99999,1.0\n"
)


def _snapshot(day: str, pinned: bool = False) -> epss_store.Snapshot:
    return epss_store.Snapshot(
        score_date=date.fromisoformat(day),
        model_version="v2026.06.15",
        score_timestamp=None,
        source_url=f"https://example.test/epss_scores-{day}.csv.gz",
        sha256=day,
        row_count=1,
        fetched_at="2026-09-13T00:00:00+00:00",
        pinned=pinned,
    )


# --- Parser -----------------------------------------------------------------

def test_parse_current_format():
    parsed = epss_source.parse(CURRENT)
    assert parsed.model_version == "v2026.06.15"
    assert parsed.score_date == date(2026, 9, 12)
    assert parsed.rows == [("CVE-1999-0001", 0.03351, 0.87994), ("CVE-2021-44228", 0.99999, 1.0)]


def test_parse_older_formats_without_comment_line():
    with_percentile = epss_source.parse("cve,epss,percentile\nCVE-2021-46080,0.02742,0.6287\n")
    assert with_percentile.model_version is None and with_percentile.score_date is None
    assert with_percentile.rows == [("CVE-2021-46080", 0.02742, 0.6287)]

    without_percentile = epss_source.parse("cve,epss\nCVE-2018-4878,0.53929\n")
    assert without_percentile.rows == [("CVE-2018-4878", 0.53929, None)]


@pytest.mark.parametrize(
    "text",
    [
        "cve,score\nCVE-2021-1,0.1\n",                   # unbekannte Kopfzeile
        "cve,epss,percentile\nGHSA-xxxx,0.1,0.2\n",       # keine CVE-Kennung
        "cve,epss,percentile\nCVE-2021-44228,1.5,0.2\n",  # außerhalb [0, 1]
        "cve,epss,percentile\nCVE-2021-44228,nan,0.2\n",
        "cve,epss,percentile\nCVE-2021-44228,0.1\n",      # fehlende Spalte
        "cve,epss,percentile\n",                          # leer
    ],
)
def test_parse_rejects_invalid_files(text):
    with pytest.raises(epss_source.EpssSourceError):
        epss_source.parse(text)


# --- Speicher -----------------------------------------------------------------

def test_store_resolves_latest_and_as_of(conn):
    epss_store.save_snapshot(conn, _snapshot("2026-09-10"), [("CVE-2021-44228", 0.5, 0.9)])
    epss_store.save_snapshot(conn, _snapshot("2026-09-12"), [("CVE-2021-44228", 0.9, 0.99)])

    assert epss_store.get_snapshot(conn).score_date == date(2026, 9, 12)
    assert epss_store.get_snapshot(conn, as_of=date(2026, 9, 11)).score_date == date(2026, 9, 10)
    assert epss_store.get_snapshot(conn, as_of=date(2026, 9, 1)) is None
    assert epss_store.get_score(conn, date(2026, 9, 10), "cve-2021-44228") == (0.5, 0.9)
    assert epss_store.get_score(conn, date(2026, 9, 12), "CVE-1999-0001") is None


def test_store_replaces_snapshot_of_same_day(conn):
    epss_store.save_snapshot(conn, _snapshot("2026-09-12"), [("CVE-2021-44228", 0.5, 0.9), ("CVE-1999-0001", 0.1, 0.2)])
    epss_store.save_snapshot(conn, _snapshot("2026-09-12"), [("CVE-2021-44228", 0.6, 0.9)])
    assert epss_store.get_score(conn, date(2026, 9, 12), "CVE-1999-0001") is None
    assert epss_store.get_score(conn, date(2026, 9, 12), "CVE-2021-44228") == (0.6, 0.9)


def test_store_normalizes_cve_case(conn):
    epss_store.save_snapshot(conn, _snapshot("2026-09-12"), [("cve-2021-44228", 0.5, 0.9)])
    assert epss_store.get_score(conn, date(2026, 9, 12), "CVE-2021-44228") == (0.5, 0.9)
    assert epss_store.get_score(conn, date(2026, 9, 12), "cve-2021-44228") == (0.5, 0.9)


def test_store_rolls_back_on_duplicate_cve(conn):
    epss_store.save_snapshot(conn, _snapshot("2026-09-12"), [("CVE-2021-44228", 0.5, 0.9)])
    with pytest.raises(Exception):
        epss_store.save_snapshot(conn, _snapshot("2026-09-12"), [("CVE-1999-0001", 0.1, 0.2), ("CVE-1999-0001", 0.1, 0.2)])
    assert epss_store.get_score(conn, date(2026, 9, 12), "CVE-2021-44228") == (0.5, 0.9)


def test_prune_keeps_newest_and_pinned(conn):
    for day in ("2026-09-09", "2026-09-10", "2026-09-11", "2026-09-12"):
        epss_store.save_snapshot(conn, _snapshot(day, pinned=day == "2026-09-09"), [("CVE-2021-44228", 0.5, 0.9)])

    assert epss_store.prune(conn, keep=2) == [date(2026, 9, 10)]
    remaining = [r[0] for r in conn.execute("SELECT score_date FROM epss_snapshot ORDER BY score_date")]
    assert remaining == ["2026-09-09", "2026-09-11", "2026-09-12"]
    assert conn.execute("SELECT COUNT(*) FROM epss_score WHERE score_date = '2026-09-10'").fetchone()[0] == 0
    assert epss_store.prune(conn, keep=0) == []


def test_unpin_makes_snapshot_prunable(conn):
    for day in ("2026-09-09", "2026-09-10", "2026-09-11"):
        epss_store.save_snapshot(conn, _snapshot(day, pinned=day == "2026-09-09"), [("CVE-2021-44228", 0.5, 0.9)])

    assert epss_store.unpin(conn, date(2026, 9, 9))
    assert not epss_store.get_snapshot_for_date(conn, date(2026, 9, 9)).pinned
    assert epss_store.prune(conn, keep=2) == [date(2026, 9, 9)]
    assert not epss_store.unpin(conn, date(2026, 9, 9))


def test_cli_unpin_epss(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("CACHE_DIR", str(tmp_path))
    get_settings.cache_clear()
    try:
        with closing(connect()) as conn:
            for day in ("2026-09-09", "2026-09-10"):
                epss_store.save_snapshot(conn, _snapshot(day, pinned=True), [("CVE-2021-44228", 0.5, 0.9)])
        assert sources_cli.main(["unpin", "epss", "2026-09-09"]) == 0
        assert sources_cli.main(["unpin", "epss", "2026-09-01"]) == 1
        assert sources_cli.main(["unpin", "epss", "gestern"]) == 1
        with closing(connect()) as conn:
            assert not epss_store.get_snapshot_for_date(conn, date(2026, 9, 9)).pinned
            assert epss_store.get_snapshot_for_date(conn, date(2026, 9, 10)).pinned
    finally:
        get_settings.cache_clear()
    out, err = capsys.readouterr()
    assert "2026-09-09: Anheftung aufgehoben" in out
    assert "kein EPSS-Snapshot vom 2026-09-01" in err


# --- Bezug ----------------------------------------------------------------------

def _fake_download(text: str, url: str):
    def download(_requested_url):
        return gzip.compress(text.encode("utf-8")), url
    return download


def test_sync_stores_snapshot_and_skips_identical_file(tmp_path, monkeypatch):
    url = "https://epss.example/epss_scores-2026-09-12.csv.gz"
    monkeypatch.setattr(common, "download",_fake_download(CURRENT, url))
    db = tmp_path / "ref.sqlite"

    first = epss_source.sync(db_path=db, keep=0)
    assert first.stored and not first.snapshot.pinned
    assert first.snapshot.row_count == 2 and first.snapshot.source_url == url

    second = epss_source.sync(db_path=db, keep=0)
    assert not second.stored

    with epss_enrich.open_lookup(db_path=db) as lookup:
        assert lookup.snapshot.model_version == "v2026.06.15"
        assert lookup.score("CVE-2021-44228") == (0.99999, 1.0)
        assert lookup.score("CVE-2000-0001") is None


def test_sync_with_date_pins_existing_snapshot(tmp_path, monkeypatch):
    url = "https://epss.example/epss_scores-2026-09-12.csv.gz"
    monkeypatch.setattr(common, "download",_fake_download(CURRENT, url))
    db = tmp_path / "ref.sqlite"
    epss_source.sync(db_path=db, keep=0)
    epss_source.sync(date(2026, 9, 12), db_path=db, keep=0)
    with closing(connect(db)) as conn:
        assert epss_store.get_snapshot_for_date(conn, date(2026, 9, 12)).pinned


def test_sync_takes_date_from_file_name_for_old_format(tmp_path, monkeypatch):
    url = "https://epss.example/epss_scores-2021-05-01.csv.gz"
    monkeypatch.setattr(common, "download",_fake_download("cve,epss\nCVE-2018-4878,0.53929\n", url))
    result = epss_source.sync(date(2021, 5, 1), db_path=tmp_path / "ref.sqlite", keep=0)
    assert result.snapshot.score_date == date(2021, 5, 1)
    assert result.snapshot.model_version is None


def test_sync_rejects_date_mismatch(tmp_path, monkeypatch):
    url = "https://epss.example/epss_scores-2026-09-11.csv.gz"
    monkeypatch.setattr(common, "download",_fake_download(CURRENT, url))
    with pytest.raises(epss_source.EpssSourceError):
        epss_source.sync(db_path=tmp_path / "ref.sqlite", keep=0)


def test_lookup_without_snapshot_returns_unknown(tmp_path):
    with epss_enrich.open_lookup(db_path=tmp_path / "ref.sqlite") as lookup:
        assert lookup.snapshot is None
        assert lookup.score("CVE-2021-44228") is None
