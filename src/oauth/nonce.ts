// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { base64urlEncode } from "../auth";

const NONCE_WINDOW_SECONDS = 300;

function assertNonceSecret(secret: string): void {
  if (!secret) {
    throw new Error("OAuth nonce secret is required");
  }
}

// `now` is epoch seconds.
export async function deriveDpopNonce(secret: string, now: number): Promise<string> {
  assertNonceSecret(secret);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const window = Math.floor(now / NONCE_WINDOW_SECONDS);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(String(window)),
  );
  return base64urlEncode(signature);
}

export async function isValidDpopNonce(
  secret: string,
  nonce: string,
  now: number,
): Promise<boolean> {
  assertNonceSecret(secret);
  const current = await deriveDpopNonce(secret, now);
  if (nonce === current) return true;
  const previous = await deriveDpopNonce(secret, now - NONCE_WINDOW_SECONDS);
  return nonce === previous;
}
