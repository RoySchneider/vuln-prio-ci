FROM python:3.15.2-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /opt/vuln-prio-ci
# Lower bounds from requirements.txt
COPY requirements.txt .
RUN python -m pip install -r requirements.txt

COPY src/vuln_prio_ci/ /opt/vuln-prio-ci/vuln_prio_ci/
# "python -m vuln_prio_ci" from any working directory
ENV PYTHONPATH=/opt/vuln-prio-ci

# interrupt build, if outdated certifi or pip is used in the image
RUN python -c "from vuln_prio_ci.tls import check_ca_bundle; check_ca_bundle()" \
 && python -c "import sys, importlib.metadata as m; sys.exit(tuple(map(int, m.version('pip').split('.')[:3])) < (26, 2, 2))"

CMD ["python", "-m", "vuln_prio_ci", "--help"]
