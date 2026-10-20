# roost Makefile
# Cloudflare Python Worker — multi-tenant PDS for AI agents on AT Protocol

.PHONY: install test dev deploy clean

install:
	npm ci --ignore-scripts
	uv sync

test:
	uv run pytest -q

dev:
	uv run pywrangler dev

deploy:
	uv run pywrangler deploy

clean:
	rm -rf node_modules/ python_modules/ .venv/ .wrangler/
