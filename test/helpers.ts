import { env as _env, SELF } from "cloudflare:test";
export { runInDurableObject } from "cloudflare:test";
import type { Env } from "../src/types";
import { base64urlEncode, jwkThumbprint, sha256Base64url } from "../src/auth";

export const env = _env as Env;
export const worker = SELF;

export async function signJwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
): Promise<string> {
  const encode = (obj: Record<string, unknown>) =>
    base64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
  const headerStr = encode(header);
  const payloadStr = encode(payload);
  const signingInput = `${headerStr}.${payloadStr}`;
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64urlEncode(signature)}`;
}

export async function generateAuthKeys(): Promise<{
  authKeys: CryptoKeyPair;
  publicJwk: JsonWebKey;
  thumbprint: string;
}> {
  const authKeys = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 4096,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", authKeys.publicKey);
  const thumbprint = await jwkThumbprint(publicJwk as { kty: string; n: string; e: string });
  return { authKeys, publicJwk, thumbprint };
}

async function signEs256Jwt(
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
  privateKey: CryptoKey,
): Promise<string> {
  const encode = (obj: Record<string, unknown>) =>
    base64urlEncode(new TextEncoder().encode(JSON.stringify(obj)));
  const headerStr = encode(header);
  const payloadStr = encode(payload);
  const signingInput = `${headerStr}.${payloadStr}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(signingInput),
  );
  return `${signingInput}.${base64urlEncode(signature)}`;
}

export async function independentEcThumbprint(jwk: JsonWebKey): Promise<string> {
  if (
    jwk.crv !== "P-256" ||
    jwk.kty !== "EC" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string"
  ) {
    throw new Error("invalid EC public JWK");
  }
  const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return base64urlEncode(hash);
}

export async function generateEcKeys(): Promise<{
  ecKeys: CryptoKeyPair;
  publicJwk: JsonWebKey;
  thumbprint: string;
}> {
  const ecKeys = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const publicJwk = await crypto.subtle.exportKey("jwk", ecKeys.publicKey);
  const thumbprint = await independentEcThumbprint(publicJwk);
  return { ecKeys, publicJwk, thumbprint };
}

export async function createPkcePair(): Promise<{ verifier: string; challenge: string }> {
  const verifier = base64urlEncode(crypto.getRandomValues(new Uint8Array(32)));
  return { verifier, challenge: await sha256Base64url(verifier) };
}

export async function createOauthDpopJwt(
  ecKeys: CryptoKeyPair,
  publicJwk: JsonWebKey,
  htm: string,
  htu: string,
  accessToken: string | null,
  nonce?: string,
  payloadOverrides: Record<string, unknown> = {},
  headerOverrides: Record<string, unknown> = {},
): Promise<string> {
  const payload: Record<string, unknown> = {
    jti: crypto.randomUUID(),
    htm,
    htu,
    iat: Math.floor(Date.now() / 1000),
  };
  if (accessToken !== null) {
    payload.ath = await sha256Base64url(accessToken);
  }
  if (nonce !== undefined) {
    payload.nonce = nonce;
  }
  Object.assign(payload, payloadOverrides);
  return signEs256Jwt(
    {
      typ: "dpop+jwt",
      alg: "ES256",
      jwk: publicJwk,
      ...headerOverrides,
    },
    payload,
    ecKeys.privateKey,
  );
}

export async function createDpopJwt(
  authKeys: CryptoKeyPair,
  publicJwk: JsonWebKey,
  htu: string,
  accessToken: string | null,
  htm = "POST",
): Promise<string> {
  const payload: Record<string, unknown> = {
    jti: `jti-${Date.now().toString(36)}`,
    htm,
    htu,
    iat: Math.floor(Date.now() / 1000),
  };
  if (accessToken !== null) {
    payload.ath = await sha256Base64url(accessToken);
  }
  return signJwt(
    {
      typ: "dpop+jwt",
      alg: "RS256",
      jwk: publicJwk,
    },
    payload,
    authKeys.privateKey,
  );
}

export async function buildAccessToken(
  authKeys: CryptoKeyPair,
  thumbprint: string,
  tosText: string,
  serviceOrigin: string,
): Promise<string> {
  return signJwt(
    { typ: "wm+jwt", alg: "RS256" },
    {
      tos_hash: await sha256Base64url(tosText),
      aud: serviceOrigin,
      cnf: { jkt: thumbprint },
      iat: Math.floor(Date.now() / 1000),
    },
    authKeys.privateKey,
  );
}

export async function signTos(
  privateKey: CryptoKey,
  tosText: string,
): Promise<string> {
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(tosText),
  );
  return base64urlEncode(signature);
}
