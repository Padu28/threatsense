# ---- ThreatSense: API (8001) + dashboard (8502) in one image ----
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    APP_ENV=development

WORKDIR /app
RUN useradd --create-home --uid 1000 app

COPY requirements.txt pyproject.toml README.md ./
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY src ./src
COPY configs ./configs
COPY api ./api
COPY dashboard ./dashboard
COPY .streamlit ./.streamlit
COPY data/sample ./data/sample
RUN pip install --no-deps -e . && mkdir -p data/processed models reports/figures && chown -R app:app /app

USER app
# Build the experiment database at image build time so the container starts instantly
RUN python -m threatsense.cli pipeline

EXPOSE 8001 8502
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8001/health')"

CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port 8001 & streamlit run dashboard/app.py --server.port 8502 --server.address 0.0.0.0"]
