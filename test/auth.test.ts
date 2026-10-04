import { beforeAll, describe, expect, it } from "vitest";
import { signJwt } from "./helpers";
import {
  base64urlDecode,
  base64urlEncode,
  jwkThumbprint,
  parseJwt,
  sha256Base64url,
  validateAccessToken,
  validateAndImportKey,
  validateDpopProof,
} from "../src/auth";

async function generateRsaKeyPair(modulusLength: number) {
  return crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
}

function tamperJwtSignature(jwt: string): string {
  const parts = jwt.split(".");
  const firstChar = parts[2][0] === "A" ? "B" : "A";
  parts[2] = `${firstChar}${parts[2].slice(1)}`;
  return parts.join(".");
}

describe("base64url", () => {
  it("round-trips binary data", () => {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    const encoded = base64urlEncode(bytes);
    const decoded = base64urlDecode(encoded);

    expect(Array.from(decoded)).toEqual(Array.from(bytes));
  });

  it("round-trips a string via TextEncoder", () => {
    const text = "rookery auth";
    const encoded = base64urlEncode(new TextEncoder().encode(text));
    const decoded = new TextDecoder().decode(base64urlDecode(encoded));

    expect(decoded).toBe(text);
  });
});

describe("sha256Base64url", () => {
  it("hashes a known string correctly", async () => {
    await expect(sha256Base64url("")).resolves.toBe(
      "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
    );
  });
});

describe("parseJwt", () => {
  it("parses a valid 3-part JWT", () => {
    const header = { typ: "wm+jwt", alg: "RS256" };
    const payload = { sub: "did:plc:test" };
    const headerStr = base64urlEncode(new TextEncoder().encode(JSON.stringify(header)));
    const payloadStr = base64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
    const signature = "test-signature";
    const jwt = `${headerStr}.${payloadStr}.${signature}`;

    expect(parseJwt(jwt)).toEqual({
      header,
      payload,
      signingInput: `${headerStr}.${payloadStr}`,
      signature,
    });
  });

  it("rejects a 2-part string", () => {
    expect(() => parseJwt("one.two")).toThrow("expected 3 parts");
  });
});

describe("jwkThumbprint", () => {
  let publicJwk: JsonWebKey;

  beforeAll(async () => {
    const keyPair = await generateRsaKeyPair(4096);
    publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  });

  it("computes RFC 7638 thumbprint", async () => {
    const thumbprint1 = await jwkThumbprint(publicJwk as { kty: string; n: string; e: string });
    const thumbprint2 = await jwkThumbprint(publicJwk as { kty: string; n: string; e: string });

    expect(thumbprint1).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(thumbprint1.length).toBeGreaterThan(0);
    expect(thumbprint2).toBe(thumbprint1);
  });
});

describe("validateAndImportKey", () => {
  let public4096: JsonWebKey;
  let public2048: JsonWebKey;

  beforeAll(async () => {
    const key4096 = await generateRsaKeyPair(4096);
    const key2048 = await generateRsaKeyPair(2048);
    public4096 = await crypto.subtle.exportKey("jwk", key4096.publicKey);
    public2048 = await crypto.subtle.exportKey("jwk", key2048.publicKey);
  });

  it("accepts RSA-4096", async () => {
    const key = await validateAndImportKey(public4096 as { kty: string; n: string; e: string });

    expect(key).toBeInstanceOf(CryptoKey);
    expect(key.type).toBe("public");
  });

  it("rejects RSA-2048", async () => {
    await expect(
      validateAndImportKey(public2048 as { kty: string; n: string; e: string }),
    ).rejects.toThrow("4096-bit");
  });

  it("rejects missing n", async () => {
    const { n: _n, ...missingN } = public4096;
    await expect(
      validateAndImportKey(missingN as { kty: string; n: string; e: string }),
    ).rejects.toThrow("missing n or e");
  });
});

describe("validateDpopProof", () => {
  let privateKey: CryptoKey;
  let publicJwk: { kty: string; n: string; e: string };

  beforeAll(async () => {
    const keyPair = await generateRsaKeyPair(4096);
    privateKey = keyPair.privateKey;
    publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
  });

  async function buildDpopJwt(payloadOverrides: Record<string, unknown> = {}) {
    return signJwt(
      { typ: "dpop+jwt", alg: "RS256", jwk: publicJwk },
      {
        jti: "test-jti-123",
        htm: "POST",
        htu: "https://example.com/path",
        iat: Math.floor(Date.now() / 1000),
        ...payloadOverrides,
      },
      privateKey,
    );
  }

  it("validates a correct DPoP proof", async () => {
    const jwt = await buildDpopJwt();
    const result = await validateDpopProof(jwt, "POST", "https://example.com/path", null);

    expect(result.jwk).toEqual(publicJwk);
    expect(result.key).toBeInstanceOf(CryptoKey);
    expect(result.thumbprint).toBe(await jwkThumbprint(publicJwk));
  });

  it("validates DPoP with access token hash", async () => {
    const accessToken = "access-token";
    const jwt = await buildDpopJwt({ ath: await sha256Base64url(accessToken) });

    await expect(
      validateDpopProof(jwt, "POST", "https://example.com/path", accessToken),
    ).resolves.toMatchObject({ jwk: publicJwk });
  });

  it("rejects invalid signature", async () => {
    const jwt = tamperJwtSignature(await buildDpopJwt());

    await expect(
      validateDpopProof(jwt, "POST", "https://example.com/path", null),
    ).rejects.toThrow("signature verification failed");
  });

  it("rejects expired iat", async () => {
    const jwt = await buildDpopJwt({ iat: Math.floor(Date.now() / 1000) - 600 });

    await expect(
      validateDpopProof(jwt, "POST", "https://example.com/path", null),
    ).rejects.toThrow("iat too far");
  });

  it("rejects wrong ath", async () => {
    const jwt = await buildDpopJwt({ ath: "wrong" });

    await expect(
      validateDpopProof(jwt, "POST", "https://example.com/path", "access-token"),
    ).rejects.toThrow("ath does not match");
  });
});

describe("validateAccessToken", () => {
  let privateKey: CryptoKey;
  let dpopKey: CryptoKey;
  let publicJwk: { kty: string; n: string; e: string };
  let thumbprint: string;

  beforeAll(async () => {
    const keyPair = await generateRsaKeyPair(4096);
    privateKey = keyPair.privateKey;
    publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    dpopKey = await validateAndImportKey(publicJwk);
    thumbprint = await jwkThumbprint(publicJwk);
  });

  async function buildAccessToken(payloadOverrides: Record<string, unknown> = {}) {
    return signJwt(
      { typ: "wm+jwt", alg: "RS256" },
      {
        tos_hash: await sha256Base64url("test-tos"),
        aud: "https://example.com",
        cnf: { jkt: thumbprint },
        ...payloadOverrides,
      },
      privateKey,
    );
  }

  it("validates a correct access token", async () => {
    const jwt = await buildAccessToken();

    await expect(
      validateAccessToken(jwt, dpopKey, "https://example.com", thumbprint, "test-tos"),
    ).resolves.toMatchObject({
      aud: "https://example.com",
      cnf: { jkt: thumbprint },
    });
  });

  it("rejects invalid signature", async () => {
    const jwt = tamperJwtSignature(await buildAccessToken());

    await expect(
      validateAccessToken(jwt, dpopKey, "https://example.com", thumbprint, "test-tos"),
    ).rejects.toThrow("signature verification failed");
  });
});
