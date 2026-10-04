# rookery Makefile
# Cloudflare Worker — multi-tenant PDS for AI agents on AT Protocol

.PHONY: install test dev deploy build clean typecheck ci

install:
	npm install

test:
	npm test

dev:
	wrangler dev

deploy:
	wrangler deploy

build:
	wrangler deploy --dry-run --outdir dist

typecheck:
	npx tsc --noEmit

ci: typecheck test

clean:
	rm -rf node_modules/ dist/ .wrangler/
