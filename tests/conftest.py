"""Gemeinsame Pipeline-Stubs: Tests laufen hermetisch, ohne Netz-/Cache-Abhängigkeit auf
EPSS/Exploit-DB/Metasploit/KEV/EUVD/NVD (app.pipeline ruft diese Module direkt auf).

Nicht `autouse` auf Paketebene: test_epss.py/test_exploits.py testen dieselben Module (epss.py,
exploits.py) direkt gegen eine echte SQLite-Referenzdatenbank und dürfen nicht gestubbt werden.
Dateien, die die Pipeline end-to-end laufen lassen, aktivieren den Stub gezielt über
`pytestmark = pytest.mark.usefixtures("stub_external_sources")`.
"""

from __future__ import annotations

from contextlib import closing

import pytest

from vuln_prio_ci import pipeline, store


@pytest.fixture
def conn(tmp_path):
    """Reference data store in tmp_path/ref.sqlite; closed after the test (unclosed connections
    raise a ResourceWarning on finalisation, which fails the run under -W error)."""
    with closing(store.connect(tmp_path / "ref.sqlite")) as connection:
        yield connection


class NullEpssLookup:
    snapshot = None

    def score(self, cve_id):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class NullNvdLookup:
    sync_state = None

    def cvss(self, cve_id):
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class NullExploitLookup:
    exploitdb = None
    metasploit = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


@pytest.fixture
def stub_external_sources(monkeypatch):
    monkeypatch.setattr(pipeline.epss, "open_lookup", lambda *a, **k: NullEpssLookup())
    monkeypatch.setattr(pipeline.exploits, "open_lookup", lambda *a, **k: NullExploitLookup())
    monkeypatch.setattr(pipeline.nvd, "open_lookup", lambda *a, **k: NullNvdLookup())
    monkeypatch.setattr(pipeline.kev, "load_index", lambda: {})
    monkeypatch.setattr(pipeline.euvd, "lookup", lambda identifier: None)
    monkeypatch.setattr(pipeline.euvd, "cve_for_euvd", lambda euvd_id: None)
