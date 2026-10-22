# Production deploy (operator only, see docs/cloudflare.md): pull main, deploy
# the Worker, then repoint any DID not yet on the host (sync-identities skips
# DIDs already there, so it is safe on every deploy).
deploy:
    git pull --ff-only
    pixi run cf-deploy
    pixi run sync-identities
