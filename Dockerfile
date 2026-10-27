FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

# eMudhra/emSign-Vorfall (Oktober 2026): Systemzertifikate auf den bereinigten Stand bringen.
# Das Image ohne Layer-Cache bauen (docker build --pull --no-cache), sonst bleibt der alte Stand.
RUN apt-get update \
 && apt-get install -y --no-install-recommends --only-upgrade ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# pip vor jeder weiteren Installation auf 26.2.2 heben: ältere Versionen vertrauen über ihr
# mitgeliefertes certifi den kompromittierten Zwischenzertifikaten. Der Hash sichert den Abruf ab.
ARG PIP_WHEEL="https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
RUN python -m pip install "pip @ ${PIP_WHEEL}"

WORKDIR /opt/vuln-prio-ci
# feste Versionen mit Hashes (scripts/lock.py); ein Paket ohne passenden Hash bricht den Bau ab
COPY requirements.lock .
RUN python -m pip install --require-hashes -r requirements.lock

COPY src/vuln_prio_ci/ /opt/vuln-prio-ci/vuln_prio_ci/
# "python -m vuln_prio_ci" aus einem beliebigen Arbeitsverzeichnis (Pipeline-Jobs)
ENV PYTHONPATH=/opt/vuln-prio-ci

# Bau abbrechen, falls doch ein certifi mit emSign-Wurzel oder ein pip vor 26.2.2 im Image liegt
RUN python -c "from vuln_prio_ci.tls import check_ca_bundle; check_ca_bundle()" \
 && python -c "import sys, importlib.metadata as m; sys.exit(tuple(map(int, m.version('pip').split('.')[:3])) < (26, 2, 2))"

CMD ["python", "-m", "vuln_prio_ci", "--help"]
