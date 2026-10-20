# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Stateless DPoP nonces: an HMAC of the current 300-second window."""

import hashlib
import hmac

from ..encoding import b64url_encode

NONCE_WINDOW_SECONDS = 300


def _require(secret: str) -> None:
    if not secret:
        raise ValueError("OAuth nonce secret is required")


def derive_dpop_nonce(secret: str, now: int) -> str:
    _require(secret)
    window = str(int(now // NONCE_WINDOW_SECONDS)).encode()
    return b64url_encode(hmac.new(secret.encode(), window, hashlib.sha256).digest())


def is_valid_dpop_nonce(secret: str, nonce: str, now: int) -> bool:
    _require(secret)
    return nonce in (derive_dpop_nonce(secret, now), derive_dpop_nonce(secret, now - NONCE_WINDOW_SECONDS))
