# CLAUDE.md

Development guidelines for rookery, an open-source multi-tenant PDS for AI agents on AT Protocol.

## Project Overview

rookery is a Cloudflare Python Worker (Pyodide) that gives AI agents their own identity and data repository on the atproto network. Agents enroll via the WelcomeMat protocol, then read and write arbitrary lexicon records through standard XRPC endpoints.

Source layout:
- `src/entry.py` - Worker entry: the `Default` WorkerEntrypoint, both Durable Object classes, and adapters from the runtime bindings (D1, R2, DO SQL, fetch) to what `rookery` expects
- `src/rookery/app.py` - the HTTP app (`handle(request, env)`) and every route
- `src/rookery/account.py` - per-agent Account Durable Object logic (SQLite-backed repo)
- `src/rookery/sequencer.py` - firehose sequencing
- `src/rookery/auth.py` - DPoP/WelcomeMat authentication; `src/rookery/oauth/` the OAuth server
- `src/rookery/identity.py` - did:plc creation and updates
- `src/rookery/directory.py` - D1 account directory
- `src/rookery/storage.py`, `repo.py`, `mst.py`, `cbor.py`, `car.py` - repo storage and atproto encodings
- `src/rookery/rpc.py` - the string RPC boundary between the Worker and Durable Objects
- `tests/` - pytest suite; `tests/fakes.py` stands in for D1, R2, DOs, PLC and outbound HTTP

## Commands

```bash
make install           # npm ci (wrangler) + uv sync (Python deps)
uv run pytest -q       # Run tests
uv run pywrangler dev  # Local development (needs uv >= 0.12.3)
pixi run cf-deploy     # Production deploy (operator only, see docs/cloudflare.md)
```

## Development Principles

sol pbc's coding standards, distilled. They live inline here because a coding
agent working in this repo can't read the private org engineering standards —
this section is the source of truth a lode sees.

- **Simple code.** Prefer plain functions. Keep modules self-contained. KISS/YAGNI — don't add abstraction, config, or fallbacks for cases that don't exist today. No backwards-compatibility shims; update call sites directly.
- **DRY.** Extract common logic; reference the source of truth instead of duplicating it.
- **Fail fast, fail clearly, never silently.** Validate inputs and external state at the boundary; raise/return clear, specific errors. Don't swallow an exception and return a success-looking result on a degraded path — a silent failure in an auth/repo layer is an invisible outage.
- **Verify before you claim.** Recall is a hypothesis, not evidence. Any claim about atproto/XRPC behavior, a lexicon shape, DPoP/JWT semantics, or a Cloudflare runtime API gets verified against the live source before it lands in code — and contract tests round-trip the real serialization boundary, not a mock of both sides.

## Security — this is an identity provider; treat it accordingly

rookery hands AI agents their own atproto identity and data repository. Auth,
DID/handle resolution, and DPoP are the trust boundary.

- **Validate and sanitize all external input.** Every XRPC request body, header, DPoP proof, and lexicon record arrives from outside the trust boundary — assume it's hostile and validate it. Don't reason on a malformed record as if it were valid.
- **Identity is resolved at the boundary, never client-supplied.** Derive the actor from the authenticated DPoP/WelcomeMat credential, not from an id named in the request body or path. Treat any account/DID in the URL as an assertion to check against the authenticated record, not as input.
- **Never expose secrets.** Signing keys, tokens, and credentials come from Worker secrets (`wrangler secret put`) / env bindings — never in source, never in a commit, never in a log line, an error message, or a response body.
- **Privacy is architecture.** Per-agent data isolation is a structural choice (the Account Durable Object boundary), not a feature. No analytics, no behavioral tracking — Article 8 covenant.

## XRPC / HTTP API design

- **Status is the success signal; the body is the resource.** Don't add a `{"success": true}` flag that duplicates the status. Collections return an envelope (`{records, cursor}`), never a bare top-level array.
- **One error envelope with a machine-readable code**, the HTTP status carried by a central registry — not a status literal sprinkled at each call site, never raw exception text in the body.
- **Bounded reads.** A list/repo endpoint never returns an unbounded collection — one shared pagination primitive (cursor or offset/limit with a hard max); a missing clamp is a denial-of-service vector.

## Verification

- Always run `uv run pytest -q` before committing — all tests must pass.
- **No GitHub CI/CD — operator-driven only.** Every `wrangler deploy` is run by an authenticated operator from a local machine; credentials never live in GitHub Actions. Don't add a `.github/workflows/` deploy or test job.

## File Headers

All Python source files must include this header:

```
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc
```

Python Workers forbid randomness at import time: import `cryptography` lazily through `rookery.crypto.lib()` and never call `random`/`secrets` at module level.

## Dogfooding

Ship meaningful work as caps. Use `vit ship` after completing a feature, fix, or improvement — not for typos or formatting.

```
vit ship --title "Short Title" --description "One sentence of value." --ref "three-word-slug" --kind feat <<'EOF'
Body paragraph explaining what the cap does and how it works.
EOF
```

Flags:
- `--title`: concise noun phrase (2-5 words)
- `--description`: one sentence explaining the value
- `--ref`: three lowercase hyphenated words — a memorable discovery slug
- `--kind`: one of `feat`, `fix`, `test`, `docs`, `refactor`, `chore`, `perf`, `style`
- `--recap <ref>`: link to a prior cap this one derives from (e.g. after `vit remix`)
- Body (stdin): short paragraph for another developer or agent who might adopt it

## Modal: always scale to zero

Modal services must always scale to zero. Never set `min_containers`, `keep_warm`, or anything else that leaves containers running when idle. Handle cold starts with timeouts and faster startup instead.
