export interface RsaPublicJwk {
  kty: string;
  n: string;
  e: string;
  [key: string]: unknown;
}

export interface JwtHeader {
  typ?: string;
  alg?: string;
  jwk?: RsaPublicJwk;
  [key: string]: unknown;
}

export interface JwtPayload {
  [key: string]: unknown;
}

export interface AccountRow {
  id: number;
  did: string;
  handle: string | null;
  jwk_thumbprint: string | null;
  [key: string]: unknown;
}

export type AuthEnv = {
  Variables: {
    account: AccountRow;
  };
};

export function base64urlEncode(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64urlDecode(str: string): Uint8Array<ArrayBuffer> {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes: Uint8Array<ArrayBuffer> = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export async function sha256Base64url(data: string | Uint8Array<ArrayBuffer>): Promise<string> {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    typeof data === "string" ? new TextEncoder().encode(data) : data,
  );
  return base64urlEncode(hash);
}

export function parseJwt(token: string): {
  header: JwtHeader;
  payload: JwtPayload;
  signingInput: string;
  signature: string;
} {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("invalid JWT: expected 3 parts");
  }

  const header = JSON.parse(
    new TextDecoder().decode(base64urlDecode(parts[0])),
  ) as JwtHeader;
  const payload = JSON.parse(
    new TextDecoder().decode(base64urlDecode(parts[1])),
  ) as JwtPayload;

  return {
    header,
    payload,
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: parts[2],
  };
}

export async function jwkThumbprint(jwk: RsaPublicJwk): Promise<string> {
  const canonical = JSON.stringify({ e: jwk.e, kty: "RSA", n: jwk.n });
  return sha256Base64url(canonical);
}

export async function validateAndImportKey(jwk: RsaPublicJwk): Promise<CryptoKey> {
  if (jwk.kty !== "RSA") {
    throw new Error("key must be RSA");
  }
  if (!jwk.n || !jwk.e) {
    throw new Error("invalid RSA key: missing n or e");
  }

  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "jwk",
      { kty: jwk.kty, n: jwk.n, e: jwk.e },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      true,
      ["verify"],
    );
  } catch {
    throw new Error("invalid RSA public key");
  }

  const exported = await crypto.subtle.exportKey("jwk", key);
  if (
    !("n" in exported) ||
    typeof exported.n !== "string" ||
    !("e" in exported) ||
    typeof exported.e !== "string"
  ) {
    throw new Error("invalid RSA public key");
  }

  const nBase64 = exported.n.replace(/-/g, "+").replace(/_/g, "/");
  const padded = nBase64 + "=".repeat((4 - (nBase64.length % 4)) % 4);
  const modulusBits = atob(padded).length * 8;
  if (modulusBits !== 4096) {
    throw new Error(`key must be 4096-bit RSA (got ${modulusBits}-bit)`);
  }

  return key;
}

export async function validateDpopProof(
  dpopJwt: string,
  method: string,
  url: string,
  accessToken: string | null,
): Promise<{ jwk: RsaPublicJwk; key: CryptoKey; thumbprint: string }> {
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
  if (header.alg !== "RS256") {
    throw new Error("invalid DPoP proof: alg must be RS256");
  }
  if (!header.jwk) {
    throw new Error("invalid DPoP proof: missing jwk");
  }

  const key = await validateAndImportKey(header.jwk);

  if (!payload.jti) {
    throw new Error("invalid DPoP proof: missing jti");
  }
  if (payload.htm !== method) {
    throw new Error(`invalid DPoP proof: htm must be ${method}`);
  }

  const reqUrl = new URL(url);
  const expectedHtu = reqUrl.origin + reqUrl.pathname;
  if (payload.htu !== expectedHtu) {
    throw new Error("invalid DPoP proof: htu does not match request URL");
  }

  if (!payload.iat || typeof payload.iat !== "number") {
    throw new Error("invalid DPoP proof: missing or invalid iat");
  }

  const now = Math.floor(Date.now() / 1000);
  if (Math.abs(now - payload.iat) > 300) {
    throw new Error("invalid DPoP proof: iat too far from current time");
  }

  if (accessToken) {
    if (typeof payload.ath !== "string") {
      throw new Error("invalid DPoP proof: missing ath");
    }
    const expectedAth = await sha256Base64url(accessToken);
    if (payload.ath !== expectedAth) {
      throw new Error("invalid DPoP proof: ath does not match access token");
    }
  }

  const sigBytes = base64urlDecode(signature);
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    sigBytes,
    new TextEncoder().encode(signingInput),
  );
  if (!valid) {
    throw new Error("invalid DPoP proof: signature verification failed");
  }

  return { jwk: header.jwk, key, thumbprint: await jwkThumbprint(header.jwk) };
}

export async function validateAccessToken(
  accessTokenStr: string,
  dpopKey: CryptoKey,
  serviceOrigin: string,
  dpopThumbprint: string,
  tosText: string,
): Promise<JwtPayload> {
  let jwt;
  try {
    jwt = parseJwt(accessTokenStr);
  } catch {
    throw new Error("invalid access token: malformed JWT");
  }

  const { header, payload, signingInput, signature } = jwt;

  if (header.typ !== "wm+jwt") {
    throw new Error("invalid access token: typ must be wm+jwt");
  }
  if (header.alg !== "RS256") {
    throw new Error("invalid access token: alg must be RS256");
  }
  if (!payload.tos_hash) {
    throw new Error("invalid access token: missing tos_hash");
  }
  if (payload.aud !== serviceOrigin) {
    throw new Error("invalid access token: aud does not match service origin");
  }

  const cnf = payload.cnf;
  if (!cnf || typeof cnf !== "object" || !("jkt" in cnf) || typeof cnf.jkt !== "string") {
    throw new Error("invalid access token: missing cnf.jkt");
  }
  if (cnf.jkt !== dpopThumbprint) {
    throw new Error("invalid access token: cnf.jkt does not match DPoP key");
  }

  const expectedTosHash = await sha256Base64url(tosText);
  if (payload.tos_hash !== expectedTosHash) {
    throw new Error("invalid access token: tos_hash does not match current terms");
  }

  const sigBytes = base64urlDecode(signature);
  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    dpopKey,
    sigBytes,
    new TextEncoder().encode(signingInput),
  );
  if (!valid) {
    throw new Error("invalid access token: signature verification failed");
  }

  return payload;
}

export function isValidHandle(handle: string): boolean {
  return /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/.test(handle) && handle.length <= 64;
}

export function extractBearerToken(authHeader: string | null): string | null {
  if (!authHeader) {
    return null;
  }
  const match = authHeader.match(/^DPoP\s+(.+)$/i);
  return match ? match[1] : null;
}
