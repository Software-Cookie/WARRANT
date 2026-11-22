# syntax=docker/dockerfile:1.7
FROM python:3.12.11-slim-bookworm
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN groupadd --system --gid 10001 acme && useradd --system --uid 10001 --gid acme --no-create-home acme
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .
USER 10001:10001
EXPOSE 8095
HEALTHCHECK --interval=5s --timeout=3s --retries=10 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8095/health', timeout=2)"
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8095", "--no-server-header"]
