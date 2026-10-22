# Production deploy (operator only, see docs/cloudflare.md): pull main, deploy
# the Worker, then repoint any DID not yet on the host (sync-identities skips
# DIDs already there, so it is safe on every deploy). The operator token is
# checked before the Worker ships, so a missing one stops the deploy up front.
deploy:
    git pull --ff-only
    pixi run check-operator-token
    pixi run cf-deploy
    pixi run sync-identities
