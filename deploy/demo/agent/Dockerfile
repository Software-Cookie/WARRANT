# syntax=docker/dockerfile:1.7
FROM python:3.12.11-slim-bookworm
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --system --gid 10001 agent && useradd --system --uid 10001 --gid agent --no-create-home agent \
 && mkdir -p /agent-keys && chown agent:agent /agent-keys
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY warrant_client.py vendor_hygiene.py demo.py tools.json ./
USER 10001:10001
ENTRYPOINT ["python", "demo.py"]
