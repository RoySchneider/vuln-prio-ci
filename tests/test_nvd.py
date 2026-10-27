"""NVD-Bezug: Auswahlregel (3.x vor 4.0, Primär vor Zweit), Speicher, voller und inkrementeller Abgleich."""

from datetime import datetime, timezone

import pytest

from vuln_prio_ci import store
from vuln_prio_ci.enrich import nvd as nvd_enrich
from vuln_prio_ci.sources import nvd
from vuln_prio_ci.store import nvd as nvd_store


def _metric(version, score, rating_type, vector=None):
    return {"source": "nvd@nist.gov" if rating_type == "Primary" else "cna@example.org", "type": rating_type,
            "cvssData": {"version": version, "baseScore": score, "vectorString": vector or f"CVSS:{version}/X"}}


def _cve(cve_id, **metrics):
    return {"cve": {"id": cve_id, "lastModified": "2026-10-01T10:00:00.000", "metrics": metrics}}


def test_select_prefers_3x_over_4_0_and_primary_over_secondary():
    item = {"metrics": {
        "cvssMetricV40": [_metric("4.0", 9.3, "Primary")],
        "cvssMetricV31": [_metric("3.1", 7.5, "Secondary"), _metric("3.1", 9.8, "Primary")],
    }}
    score, _, version, rating_type, _ = nvd.select_metric(item)
    assert (score, version, rating_type) == (9.8, "3.1", "Primary")


def test_select_falls_back_to_4_0_and_ignores_2_0():
    assert nvd.select_metric({"metrics": {"cvssMetricV40": [_metric("4.0", 8.7, "Secondary")]}})[0] == 8.7
    assert nvd.select_metric({"metrics": {"cvssMetricV2": [_metric("2.0", 10.0, "Primary")]}}) is None
    assert nvd.select_metric({"metrics": {}}) is None


def test_full_then_incremental_sync(tmp_path):
    db = tmp_path / "reference.sqlite"
    pages = {
        0: {"totalResults": 3, "resultsPerPage": 2, "vulnerabilities": [
            _cve("CVE-2021-44228", cvssMetricV31=[_metric("3.1", 10.0, "Primary")]),
            _cve("CVE-2020-0001", cvssMetricV2=[_metric("2.0", 5.0, "Primary")])]},
        2: {"totalResults": 3, "resultsPerPage": 2, "vulnerabilities": [
            _cve("CVE-2025-30208", cvssMetricV31=[_metric("3.1", 5.3, "Secondary")])]},
    }
    calls = []

    def fetch(params):
        calls.append(params)
        return pages[params["startIndex"]]

    now = datetime(2026, 10, 14, 6, 0, tzinfo=timezone.utc)
    result = nvd.sync(fetch=fetch, now=now, db_path=db)
    assert result.full_load and result.updated == 2 and result.removed == 1
    assert "lastModStartDate" not in calls[0]          # Vollbezug ohne Zeitfenster

    conn = store.connect(db)
    assert nvd_store.get(conn, "CVE-2021-44228").base_score == 10.0
    assert nvd_store.get(conn, "CVE-2020-0001") is None   # nur CVSS 2.0
    conn.close()

    calls.clear()
    update = {"totalResults": 1, "resultsPerPage": 1, "vulnerabilities": [
        _cve("CVE-2025-30208", cvssMetricV31=[_metric("3.1", 7.5, "Primary")])]}
    later = datetime(2026, 10, 15, 6, 0, tzinfo=timezone.utc)
    result = nvd.sync(fetch=lambda p: (calls.append(p), update)[1], now=later, db_path=db)
    assert not result.full_load
    assert calls[0]["lastModStartDate"].startswith("2026-10-14T05:00:00")   # 1 h Überlappung
    assert calls[0]["lastModEndDate"].startswith("2026-10-15T06:00:00")
    with nvd_enrich.open_lookup(db) as lookup:
        record = lookup.cvss("cve-2025-30208")
        assert (record.base_score, record.rating_type) == (7.5, "Primary")
        assert lookup.sync_state.synced_until.startswith("2026-10-15T06:00:00")


def test_incremental_sync_splits_windows_of_120_days(tmp_path):
    db = tmp_path / "reference.sqlite"
    conn = store.connect(db)
    nvd_store.set_sync(conn, "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00", True)
    conn.close()
    calls = []
    nvd.sync(fetch=lambda p: (calls.append(p), {"totalResults": 0, "vulnerabilities": []})[1],
             now=datetime(2026, 10, 1, tzinfo=timezone.utc), db_path=db)
    assert len(calls) == 3                               # 273 Tage -> drei Fenster
