// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { base64urlDecode, parseJwt, type JwtPayload } from "./auth";
import type { Env } from "./types";

const ACCESS_JWKS_TTL_MS = 10 * 60 * 1000;

type AccessJwksCache = {
  keys: Map<string, CryptoKey>;
  fetchedAt: number;
};

type AccessJwk = {
  kid: string;
  kty: "RSA";
  alg?: string;
  n: string;
  e: string;
  use?: string;
};

export type AccessJwtClaims = JwtPayload & {
  iss: string;
  aud: string | string[];
  exp: number;
  iat: number;
};

export class AccessJwtError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AccessJwtError";
  }
}

let jwksCache: AccessJwksCache | null = null;

export function __resetAccessJwksCache(): void {
  jwksCache = null;
}

function isAccessJwk(value: unknown): value is AccessJwk {
  if (!value || typeof value !== "object") return false;
  const jwk = value as Record<string, unknown>;
  return (
    typeof jwk.kid === "string" &&
    jwk.kty === "RSA" &&
    typeof jwk.n === "string" &&
    typeof jwk.e === "string"
  );
}

async function importAccessJwk(jwk: AccessJwk): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
  } catch {
    throw new AccessJwtError("invalid Access public key");
  }
}

async function fetchAccessKeys(env: Env): Promise<AccessJwksCache> {
  if (!env.CF_ACCESS_TEAM_DOMAIN) {
    throw new AccessJwtError("Access team domain is not configured");
  }

  const response = await fetch(`https://${env.CF_ACCESS_TEAM_DOMAIN}/cdn-cgi/access/certs`);
  if (!response.ok) {
    throw new AccessJwtError("Access JWKS fetch failed");
  }

  let body: unknown;
  try {
    body = await response.json();
  } catch {
    throw new AccessJwtError("Access JWKS response is invalid JSON");
  }

  const keys = (body as { keys?: unknown }).keys;
  if (!Array.isArray(keys)) {
    throw new AccessJwtError("Access JWKS response missing keys");
  }

  const imported = new Map<string, CryptoKey>();
  for (const key of keys) {
    if (!isAccessJwk(key)) {
      throw new AccessJwtError("Access JWKS contains an invalid key");
    }
    imported.set(key.kid, await importAccessJwk(key));
  }

  if (imported.size === 0) {
    throw new AccessJwtError("Access JWKS contains no keys");
  }

  jwksCache = { keys: imported, fetchedAt: Date.now() };
  return jwksCache;
}

async function getAccessKeys(env: Env): Promise<AccessJwksCache> {
  if (jwksCache && Date.now() - jwksCache.fetchedAt < ACCESS_JWKS_TTL_MS) {
    return jwksCache;
  }
  return fetchAccessKeys(env);
}

function assertAccessClaims(payload: JwtPayload, env: Env): AccessJwtClaims {
  if (!env.CF_ACCESS_TEAM_DOMAIN || !env.CF_ACCESS_AUD) {
    throw new AccessJwtError("Access is not configured");
  }

  const expectedIssuer = `https://${env.CF_ACCESS_TEAM_DOMAIN}`;
  if (payload.iss !== expectedIssuer) {
    throw new AccessJwtError("Access JWT issuer mismatch");
  }
  const audiences = typeof payload.aud === "string" ? [payload.aud] : payload.aud;
  if (
    !Array.isArray(audiences) ||
    !audiences.every((aud) => typeof aud === "string") ||
    !audiences.includes(env.CF_ACCESS_AUD)
  ) {
    throw new AccessJwtError("Access JWT audience mismatch");
  }
  if (typeof payload.exp !== "number") {
    throw new AccessJwtError("Access JWT missing exp");
  }
  if (typeof payload.iat !== "number") {
    throw new AccessJwtError("Access JWT missing iat");
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp <= now) {
    throw new AccessJwtError("Access JWT expired");
  }
  if (payload.iat > now + 60) {
    throw new AccessJwtError("Access JWT iat is in the future");
  }

  return payload as AccessJwtClaims;
}

export async function verifyAccessJwt(token: string, env: Env): Promise<AccessJwtClaims> {
  let jwt;
  try {
    jwt = parseJwt(token);
  } catch {
    throw new AccessJwtError("Access JWT is malformed");
  }

  const { header, payload, signingInput, signature } = jwt;
  if (header.alg !== "RS256") {
    throw new AccessJwtError("Access JWT alg must be RS256");
  }
  if (typeof header.kid !== "string") {
    throw new AccessJwtError("Access JWT missing kid");
  }

  let cache = await getAccessKeys(env);
  let key = cache.keys.get(header.kid);
  if (!key) {
    cache = await fetchAccessKeys(env);
    key = cache.keys.get(header.kid);
  }
  if (!key) {
    throw new AccessJwtError("Access JWT kid is unknown");
  }

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    base64urlDecode(signature),
    new TextEncoder().encode(signingInput),
  );
  if (!valid) {
    throw new AccessJwtError("Access JWT signature verification failed");
  }

  return assertAccessClaims(payload, env);
}
