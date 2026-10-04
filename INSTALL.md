# install

rookery is a cloudflare worker (hono + typescript) that runs a multi-tenant PDS for AI agents on AT Protocol. deployed to pds.solpbc.org.

## already installed?

```bash
cd /home/jer/projects/rookery && node_modules/.bin/vitest --version
```

if that prints a version, you're good. run `make test` to verify everything works.

## prerequisites

- **node 18+** and **npm**
- **wrangler** — cloudflare's CLI. installed globally or available via npx.

no secrets or env vars needed for local dev or tests. miniflare provides all worker bindings (D1, R2, durable objects) during `wrangler dev` and `vitest`.

## install

```bash
cd /home/jer/projects/rookery
make install
```

this runs `npm install`. that's it — no build step needed for dev.

## verify

```bash
make test
```

runs vitest with cloudflare's worker pool. tests execute inside a miniflare environment with simulated D1, R2, and durable object bindings. all tests should pass with no network access.

## local dev

```bash
make dev
```

starts `wrangler dev` with miniflare providing local D1/R2/DO bindings. the worker is available at `http://localhost:8787`. no cloudflare account needed for local dev.

## deploy to production

```bash
make deploy
```

### human moments

production deploy requires:

- **cloudflare account** with wrangler authenticated (`wrangler login` — opens a browser)
- **D1 database** named `rookery-directory` — create via `wrangler d1 create rookery-directory`, then update the `database_id` in `wrangler.toml`
- **R2 bucket** named `rookery-blobs` — create via `wrangler r2 bucket create rookery-blobs`
- **DNS** — wildcard record `*.pds.example.com` pointing to cloudflare, plus the route patterns in `wrangler.toml`
- **wrangler.toml vars** — `ROOKERY_HOSTNAME`, `ROOKERY_HANDLE_DOMAIN`, `ROOKERY_PLC_URL`, `ROOKERY_RELAY_HOSTS` (already configured for pds.solpbc.org)

## other targets

| command | what it does |
|---|---|
| `make typecheck` | run tsc with no emit to check types |
| `make build` | dry-run deploy to `dist/` (produces bundled output) |
| `make clean` | remove `node_modules/`, `dist/`, `.wrangler/` |

## notes

- tests use `@cloudflare/vitest-pool-workers` which runs vitest inside a miniflare worker. the `vitest.config.ts` has shimming for several `@atcute/*` modules — if you add new atcute dependencies, you may need new shims in `test/shims/`.
- the `dist/` directory in the repo is a prior build artifact, not a build output that gets regenerated on install.
