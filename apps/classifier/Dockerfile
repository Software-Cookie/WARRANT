# syntax=docker/dockerfile:1.7
FROM python:3.12.11-slim-bookworm AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY requirements.txt .
RUN python -m venv /opt/venv && /opt/venv/bin/pip install --require-virtualenv -r requirements.txt

FROM python:3.12.11-slim-bookworm
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PORT=8090
RUN groupadd --system --gid 10001 warrant && useradd --system --uid 10001 --gid warrant --no-create-home warrant
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
COPY --chown=root:root serve ./serve
COPY --chown=root:root prompts ./prompts
COPY --chown=root:root eval ./eval
USER 10001:10001
EXPOSE 8090
HEALTHCHECK --interval=10s --timeout=3s --retries=5 \
  CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"PORT\"]}/health', timeout=2)"
CMD ["sh", "-c", "exec uvicorn serve.app:app --host 0.0.0.0 --port ${PORT} --workers ${WARRANT_CLASSIFIER_WORKERS:-2} --no-server-header --proxy-headers --forwarded-allow-ips=127.0.0.1"]
