.PHONY: test lint dev worker api install start-joern

install:
	pip install -r requirements.txt

test:
	pytest tests/ -v

lint:
	ruff check hackersec/ tests/

dev: api

api:
	uvicorn hackersec.main:app --reload --port 8000

worker:
	celery -A hackersec.worker.celery_app worker --loglevel=info --concurrency=2

init-db:
	python -c "from hackersec.db.store import init_db; init_db(); print('DB initialized')"

start-joern:
	joern --server --port 9000

seed-kb:
	python hackersec/ingestion/seed_kb.py

train:
	python hackersec/analysis/ml/train.py
