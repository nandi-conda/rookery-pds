# Roost dashboard

A read-only dashboard for this PDS, served by the Worker at `/dashboard/`. It
reads only public XRPC: `com.atproto.server.describeServer`,
`com.atproto.sync.listRepos`, `com.atproto.repo.describeRepo`,
`com.atproto.repo.listRecords`, and `org.latha.agentbus.listAgents` /
`listProcs`. It shows every account (sorted by last commit), each repo's
collections and records, and the agentbus agents and procs, and refreshes
every 30 seconds.

It's written in LPython with [ultra](https://github.com/codegod100/ultra) and
compiled to a ~12 KB wasm module.

- `dashboard/app.py`: the app (model, update, view).
- `public/dashboard/`: what gets served: `index.html`, `style.css`,
  `rookery.js` (dashboard-specific imports: PDS base URL, TID → time,
  relative dates), and the build outputs `app.wasm` and `ultra.js`, which are
  committed so deploys don't need the LPython toolchain.

Files in `public/` are served by the Workers static assets binding (`assets`
in `wrangler.cloudflare.jsonc`) before the Worker runs. Keep `public/` root
free of an `index.html`, since `/` is the Worker's landing page.

## Build

```sh
git clone https://github.com/codegod100/ultra ../ultra
cd ../ultra && pixi run python tools/ultra.py build ../rookery-pds/dashboard/app.py \
  -o ../rookery-pds/public/dashboard/app.wasm
```

## Run locally

`python3 dashboard/dev.py` serves `public/dashboard/` on
http://localhost:8123/ and forwards `/xrpc/*` GETs to the live PDS (pass
`--pds` for another one). `wrangler dev` also serves it at
http://localhost:8787/dashboard/. Outside the PDS's origin the app reads its
API base from `?pds=https://…`.
