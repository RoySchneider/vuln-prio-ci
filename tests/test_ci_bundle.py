"""Signalpaket: Packen/Entpacken, Veröffentlichen und Laden über die Package Registry (HTTP gestubbt)."""

from __future__ import annotations

import io
import json
import tarfile

import httpx
import pytest

from vuln_prio_ci.ci import gitlab_api
from vuln_prio_ci.ci import freshness
from vuln_prio_ci.sources import manifest


def _cache(tmp_path):
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "kev-dump.json").write_text(json.dumps([{"cveId": "CVE-2021-44228", "dateAdded": "2021-12-10"}]))
    manifest.write(cache)
    return cache


def test_bundle_roundtrip(tmp_path):
    content = gitlab_api.build_bundle(_cache(tmp_path))
    names = gitlab_api.extract_bundle(content, tmp_path / "out")
    assert sorted(names) == ["bundle-manifest.json", "kev-dump.json"]
    assert freshness.check(tmp_path / "out", max_age_days=2).age_days == 0


def test_extract_ignores_unexpected_members(tmp_path):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        data = b"x"
        for name in ("../boese.txt", "kev-dump.json"):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    assert gitlab_api.extract_bundle(buffer.getvalue(), tmp_path / "out") == ["kev-dump.json"]
    assert not (tmp_path / "boese.txt").exists()


def test_publish_and_fetch(tmp_path, monkeypatch):
    monkeypatch.setenv("CI_API_V4_URL", "https://gitlab.example/api/v4")
    monkeypatch.setenv("CI_JOB_TOKEN", "job-token")
    monkeypatch.delenv("GITLAB_API_TOKEN", raising=False)
    uploaded = {}

    def fake_put(url, content, headers, timeout):
        uploaded["url"], uploaded["content"], uploaded["headers"] = url, content, headers
        return httpx.Response(201, request=httpx.Request("PUT", url))

    def fake_get(url, params=None, headers=None, timeout=None, follow_redirects=False):
        if url.endswith("/packages"):
            return httpx.Response(200, json=[{"name": "reference-bundle", "version": "2026.10.14-030000"}],
                                  request=httpx.Request("GET", url))
        assert "/reference-bundle/2026.10.14-030000/reference-bundle.tar.gz" in url
        return httpx.Response(200, content=uploaded["content"], request=httpx.Request("GET", url))

    monkeypatch.setattr(gitlab_api.httpx, "put", fake_put)
    monkeypatch.setattr(gitlab_api.httpx, "get", fake_get)

    version = gitlab_api.publish_bundle(_cache(tmp_path), "gruppe/vuln-prio", version="2026.10.14-030000")
    assert version == "2026.10.14-030000"
    assert "/projects/gruppe%2Fvuln-prio/packages/generic/reference-bundle/2026.10.14-030000/" in uploaded["url"]
    assert uploaded["headers"] == {"JOB-TOKEN": "job-token"}

    fetched_version, names = gitlab_api.fetch_bundle("gruppe/vuln-prio", tmp_path / "dest")
    assert fetched_version == "2026.10.14-030000"
    assert "bundle-manifest.json" in names


def test_export_requires_private_token(monkeypatch):
    monkeypatch.setenv("CI_API_V4_URL", "https://gitlab.example/api/v4")
    monkeypatch.delenv("GITLAB_API_TOKEN", raising=False)
    monkeypatch.setenv("CI_JOB_TOKEN", "job-token")
    with pytest.raises(gitlab_api.ApiError, match="GITLAB_API_TOKEN"):
        gitlab_api.export_inventory("1", "out.csv")


def test_export_inventory(monkeypatch, tmp_path):
    monkeypatch.setenv("CI_API_V4_URL", "https://gitlab.example/api/v4")
    monkeypatch.setenv("GITLAB_API_TOKEN", "pat")
    calls = []

    def fake_post(url, data, headers, timeout):
        calls.append(("POST", url, data))
        return httpx.Response(201, json={"id": 7, "status": "created"}, request=httpx.Request("POST", url))

    states = iter([202, 200])

    def fake_get(url, headers=None, timeout=None, follow_redirects=False):
        calls.append(("GET", url, headers))
        if url.endswith("/download"):
            return httpx.Response(200, content=b"Tool,CVE\n", request=httpx.Request("GET", url))
        code = next(states)
        return httpx.Response(code, json={"id": 7, "status": "finished" if code == 200 else "running"},
                              request=httpx.Request("GET", url))

    monkeypatch.setattr(gitlab_api.httpx, "post", fake_post)
    monkeypatch.setattr(gitlab_api.httpx, "get", fake_get)
    monkeypatch.setattr(gitlab_api.time, "sleep", lambda s: None)
    path = gitlab_api.export_inventory("42", tmp_path / "inventory.csv")
    assert path.read_bytes() == b"Tool,CVE\n"
    assert calls[0] == ("POST", "https://gitlab.example/api/v4/security/projects/42/vulnerability_exports",
                        {"export_format": "csv"})
    assert calls[1][2] == {"PRIVATE-TOKEN": "pat"}
