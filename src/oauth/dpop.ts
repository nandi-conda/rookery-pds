// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { base64urlDecode, parseJwt, sha256Base64url } from "../auth";
import { insertOAuthDpopJti } from "./store";
import { deriveDpopNonce, isValidDpopNonce } from "./nonce";

export interface EcPublicJwk {
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  d?: never;
  [key: string]: unknown;
}

export interface OAuthDpopPayload {
  jti: string;
  htm: string;
  htu: string;
  iat: number;
  ath?: string;
  nonce?: string;
  [key: string]: unknown;
}

export interface OAuthDpopProof {
  jwk: EcPublicJwk;
  thumbprint: string;
  payload: OAuthDpopPayload;
}

export interface ValidateOauthDpopProofOptions {
  db: D1Database;
  nonceSecret: string;
  now: number;
  requireNonce?: boolean;
}

type ParsedOAuthDpopPayload = {
  jti: string;
  htm: string;
  htu: string;
  iat: number;
  ath?: unknown;
  nonce?: unknown;
  [key: string]: unknown;
};

export class UseDpopNonceError extends Error {
  readonly nonce: string;

  constructor(nonce: string, message = "DPoP nonce required") {
    super(message);
    this.name = "UseDpopNonceError";
    this.nonce = nonce;
  }
}

export async function ecJwkThumbprint(jwk: EcPublicJwk): Promise<string> {
  const canonical = JSON.stringify({ crv: "P-256", kty: "EC", x: jwk.x, y: jwk.y });
  return sha256Base64url(canonical);
}

function isEcPublicJwk(value: unknown): value is EcPublicJwk {
  if (!value || typeof value !== "object") return false;
  const jwk = value as Record<string, unknown>;
  return (
    jwk.kty === "EC" &&
    jwk.crv === "P-256" &&
    typeof jwk.x === "string" &&
    typeof jwk.y === "string" &&
    !("d" in jwk)
  );
}

async function importEcVerifyKey(jwk: EcPublicJwk): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey(
      "jwk",
      { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    throw new Error("invalid DPoP proof: invalid EC public key");
  }
}

function assertDpopPayload(payload: Record<string, unknown>): ParsedOAuthDpopPayload {
  if (typeof payload.jti !== "string" || payload.jti.length === 0) {
    throw new Error("invalid DPoP proof: missing jti");
  }
  if (typeof payload.htm !== "string") {
    throw new Error("invalid DPoP proof: missing htm");
  }
  if (typeof payload.htu !== "string") {
    throw new Error("invalid DPoP proof: missing htu");
  }
  if (typeof payload.iat !== "number") {
    throw new Error("invalid DPoP proof: missing or invalid iat");
  }
  return payload as ParsedOAuthDpopPayload;
}

export async function validateOauthDpopProof(
  dpopJwt: string,
  method: string,
  url: string,
  accessToken: string | null,
  options: ValidateOauthDpopProofOptions,
): Promise<OAuthDpopProof> {
  let jwt;
  try {
    jwt = parseJwt(dpopJwt);
  } catch {
    throw new Error("invalid DPoP proof: malformed JWT");
  }

  const { header, payload, signingInput, signature } = jwt;
  if (header.typ !== "dpop+jwt") {
    throw new Error("invalid DPoP proof: typ must be dpop+jwt");
  }
  if (header.alg !== "ES256") {
    throw new Error("invalid DPoP proof: alg must be ES256");
  }
  if (!isEcPublicJwk(header.jwk)) {
    throw new Error("invalid DPoP proof: missing or invalid EC public jwk");
  }

  const dpopPayload = assertDpopPayload(payload);
  if (options.requireNonce !== false) {
    if (typeof dpopPayload.nonce !== "string" || dpopPayload.nonce.length === 0) {
      throw new UseDpopNonceError(await deriveDpopNonce(options.nonceSecret, options.now));
    }
    const nonceValid = await isValidDpopNonce(
      options.nonceSecret,
      dpopPayload.nonce,
      options.now,
    );
    if (!nonceValid) {
      throw new UseDpopNonceError(await deriveDpopNonce(options.nonceSecret, options.now));
    }
  }

  const key = await importEcVerifyKey(header.jwk);
  const valid = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    base64urlDecode(signature),
    new TextEncoder().encode(signingInput),
  );
  if (!valid) {
    throw new Error("invalid DPoP proof: signature verification failed");
  }

  if (dpopPayload.htm !== method) {
    throw new Error(`invalid DPoP proof: htm must be ${method}`);
  }

  let htuUrl: URL;
  try {
    htuUrl = new URL(dpopPayload.htu);
  } catch {
    throw new Error("invalid DPoP proof: htu must be a URL");
  }
  if (htuUrl.search || htuUrl.hash) {
    throw new Error("invalid DPoP proof: htu must not include query or fragment");
  }
  const reqUrl = new URL(url);
  const expectedHtu = reqUrl.origin + reqUrl.pathname;
  if (dpopPayload.htu !== expectedHtu) {
    throw new Error("invalid DPoP proof: htu does not match request URL");
  }

  if (Math.abs(options.now - dpopPayload.iat) > 300) {
    throw new Error("invalid DPoP proof: iat too far from current time");
  }

  if (accessToken !== null) {
    if (typeof dpopPayload.ath !== "string") {
      throw new Error("invalid DPoP proof: missing ath");
    }
    const expectedAth = await sha256Base64url(accessToken);
    if (dpopPayload.ath !== expectedAth) {
      throw new Error("invalid DPoP proof: ath does not match access token");
    }
  }

  const jtiHash = await sha256Base64url(`dpop:${dpopPayload.jti}`);
  const inserted = await insertOAuthDpopJti(options.db, jtiHash, options.now + 600, options.now);
  if (!inserted) {
    throw new Error("invalid DPoP proof: replayed jti");
  }

  return {
    jwk: header.jwk,
    thumbprint: await ecJwkThumbprint(header.jwk),
    payload: dpopPayload as OAuthDpopPayload,
  };
}
