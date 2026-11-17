.PHONY: install dev pipeline api dashboard test lint docker clean

install:        ## Install runtime dependencies (editable)
	pip install -r requirements.txt && pip install -e .

dev:            ## Install dev tooling
	pip install -r requirements-dev.txt && pip install -e .

pipeline:       ## Full research pipeline
	python -m threatsense.cli pipeline

api:            ## FastAPI on :8001 (docs at /docs)
	uvicorn api.main:app --reload --port 8001

dashboard:      ## Streamlit dashboard on :8502
	streamlit run dashboard/app.py --server.port 8502

test:
	pytest --cov=threatsense --cov-report=term-missing

lint:
	ruff check src api dashboard tests && ruff format --check src api dashboard tests

docker:
	docker build -f docker/Dockerfile -t threatsense:latest . && docker run -p 8001:8001 -p 8502:8502 threatsense:latest

clean:
	rm -rf data/processed/*.db models/*.joblib reports/figures/*.png .pytest_cache .ruff_cache
