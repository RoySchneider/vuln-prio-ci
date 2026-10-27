import pytest

from vuln_prio_ci import __main__ as ci_cli
from vuln_prio_ci import tls


@pytest.mark.parametrize("version", ["2026.10.19", "2026.11.01", "2027.01.05"])
def test_fixed_certifi_accepted(version):
    tls.check_ca_bundle(version)


@pytest.mark.parametrize("version", ["2026.10.18", "2026.07.22", "2025.12.31", "unbekannt"])
def test_outdated_certifi_rejected(version):
    with pytest.raises(tls.CaBundleOutdated):
        tls.check_ca_bundle(version)


def test_network_commands_stop_on_outdated_bundle(monkeypatch, capsys):
    import certifi
    monkeypatch.setattr(certifi, "__version__", "2026.07.22")
    assert ci_cli.main(["fetch-bundle", "--project", "gruppe/vuln-prio-ci"]) == 1
    assert "emSign" in capsys.readouterr().err
