import {
  createOauthDpopJwt,
  env,
  generateEcKeys,
  independentEcThumbprint,
} from "./helpers";
import { deriveDpopNonce } from "../src/oauth/nonce";
import {
  ecJwkThumbprint,
  UseDpopNonceError,
  validateOauthDpopProof,
} from "../src/oauth/dpop";
import { initOAuth } from "../src/oauth/store";

describe("OAuth DPoP proof validation", () => {
  beforeEach(async () => {
    await initOAuth(env.DIRECTORY);
  });

  async function buildValidProof(accessToken: string | null = null) {
    const now = Math.floor(Date.now() / 1000);
    const nonce = await deriveDpopNonce(env.OAUTH_NONCE_SECRET ?? "", now);
    const { ecKeys, publicJwk } = await generateEcKeys();
    const htu = "https://server.example/oauth/token";
    const jwt = await createOauthDpopJwt(ecKeys, publicJwk, "POST", htu, accessToken, nonce);
    return { now, nonce, ecKeys, publicJwk, htu, jwt };
  }

  it("accepts a valid ES256 proof and computes the RFC 7638 EC thumbprint", async () => {
    const { now, publicJwk, htu, jwt } = await buildValidProof();

    const result = await validateOauthDpopProof(jwt, "POST", htu, null, {
      db: env.DIRECTORY,
      nonceSecret: env.OAUTH_NONCE_SECRET ?? "",
      now,
    });

    expect(result.jwk.x).toBe(publicJwk.x);
    await expect(ecJwkThumbprint(result.jwk)).resolves.toBe(
      await independentEcThumbprint(publicJwk),
    );
    expect(result.thumbprint).toBe(await independentEcThumbprint(publicJwk));
  });

  it("rejects RS256 alg", async () => {
    const { now, ecKeys, publicJwk, htu, nonce } = await buildValidProof();
    const jwt = await createOauthDpopJwt(
      ecKeys,
      publicJwk,
      "POST",
      htu,
      null,
      nonce,
      {},
      { alg: "RS256" },
    );

    await expect(
      validateOauthDpopProof(jwt, "POST", htu, null, {
        db: env.DIRECTORY,
        nonceSecret: env.OAUTH_NONCE_SECRET ?? "",
        now,
      }),
    ).rejects.toThrow("alg must be ES256");
  });

  it("rejects htu with query but accepts origin plus path for a request with query", async () => {
    const { ecKeys, publicJwk } = await generateEcKeys();
    const now = Math.floor(Date.now() / 1000);
    const nonce = await deriveDpopNonce(env.OAUTH_NONCE_SECRET ?? "", now);
    const requestUrl = "https://server.example/oauth/token?foo=bar";
    const validHtu = "https://server.example/oauth/token";
    const validJwt = await createOauthDpopJwt(
      ecKeys,
      publicJwk,
      "POST",
      validHtu,
      null,
      nonce,
    );

    await expect(
      validateOauthDpopProof(validJwt, "POST", requestUrl, null, {
        db: env.DIRECTORY,
        nonceSecret: env.OAUTH_NONCE_SECRET ?? "",
        now,
      }),
    ).resolves.toMatchObject({ payload: { htu: validHtu } });

    const queryJwt = await createOauthDpopJwt(
      ecKeys,
      publicJwk,
      "POST",
      requestUrl,
      null,
      nonce,
    );
    await expect(
      validateOauthDpopProof(queryJwt, "POST", requestUrl, null, {
        db: env.DIRECTORY,
        nonceSecret: env.OAUTH_NONCE_SECRET ?? "",
        now,
      }),
    ).rejects.toThrow("htu must not include query or fragment");
  });

  it("rejects stale iat", async () => {
    const { now, ecKeys, publicJwk, htu, nonce } = await buildValidProof();
    const jwt = await createOauthDpopJwt(
      ecKeys,
      publicJwk,
      "POST",
      htu,
      null,
      nonce,
      { iat: now - 301 },
    );

    await expect(
      validateOauthDpopProof(jwt, "POST", htu, null, {
        db: env.DIRECTORY,
        nonceSecret: env.OAUTH_NONCE_SECRET ?? "",
        now,
      }),
    ).rejects.toThrow("iat too far");
  });

  it("rejects wrong ath", async () => {
    const accessToken = "access-token";
    const { now, ecKeys, publicJwk, htu, nonce } = await buildValidProof(accessToken);
    const jwt = await createOauthDpopJwt(
      ecKeys,
      publicJwk,
      "POST",
      htu,
      accessToken,
      nonce,
      { ath: "wrong" },
    );

    await expect(
      validateOauthDpopProof(jwt, "POST", htu, accessToken, {
        db: env.DIRECTORY,
        nonceSecret: env.OAUTH_NONCE_SECRET ?? "",
        now,
      }),
    ).rejects.toThrow("ath does not match");
  });

  it("rejects replayed jti", async () => {
    const { now, htu, jwt } = await buildValidProof();
    const options = {
      db: env.DIRECTORY,
      nonceSecret: env.OAUTH_NONCE_SECRET ?? "",
      now,
    };

    await expect(validateOauthDpopProof(jwt, "POST", htu, null, options)).resolves.toBeTruthy();
    await expect(validateOauthDpopProof(jwt, "POST", htu, null, options)).rejects.toThrow(
      "replayed jti",
    );
  });

  it("throws UseDpopNonceError for absent nonce", async () => {
    const { now, ecKeys, publicJwk, htu } = await buildValidProof();
    const jwt = await createOauthDpopJwt(ecKeys, publicJwk, "POST", htu, null);

    await expect(
      validateOauthDpopProof(jwt, "POST", htu, null, {
        db: env.DIRECTORY,
        nonceSecret: env.OAUTH_NONCE_SECRET ?? "",
        now,
      }),
    ).rejects.toBeInstanceOf(UseDpopNonceError);
  });

  it("accepts absent nonce when nonce is not required and still checks ath", async () => {
    const accessToken = "resource-access-token";
    const { ecKeys, publicJwk } = await generateEcKeys();
    const now = Math.floor(Date.now() / 1000);
    const htu = "https://server.example/xrpc/com.atproto.repo.createRecord";
    const jwt = await createOauthDpopJwt(ecKeys, publicJwk, "POST", htu, accessToken);

    await expect(
      validateOauthDpopProof(jwt, "POST", htu, accessToken, {
        db: env.DIRECTORY,
        nonceSecret: env.OAUTH_NONCE_SECRET ?? "",
        now,
        requireNonce: false,
      }),
    ).resolves.toBeTruthy();
  });

  it("rejects wrong ath even when nonce is not required", async () => {
    const { ecKeys, publicJwk } = await generateEcKeys();
    const now = Math.floor(Date.now() / 1000);
    const htu = "https://server.example/xrpc/com.atproto.repo.createRecord";
    const jwt = await createOauthDpopJwt(ecKeys, publicJwk, "POST", htu, "resource-access-token");

    await expect(
      validateOauthDpopProof(jwt, "POST", htu, "other-access-token", {
        db: env.DIRECTORY,
        nonceSecret: env.OAUTH_NONCE_SECRET ?? "",
        now,
        requireNonce: false,
      }),
    ).rejects.toThrow("ath does not match");
  });

  it("rejects replayed jti even when nonce is not required", async () => {
    const { ecKeys, publicJwk } = await generateEcKeys();
    const now = Math.floor(Date.now() / 1000);
    const htu = "https://server.example/xrpc/com.atproto.repo.createRecord";
    const jwt = await createOauthDpopJwt(ecKeys, publicJwk, "POST", htu, "resource-access-token");
    const options = {
      db: env.DIRECTORY,
      nonceSecret: env.OAUTH_NONCE_SECRET ?? "",
      now,
      requireNonce: false,
    };

    await expect(validateOauthDpopProof(jwt, "POST", htu, "resource-access-token", options)).resolves.toBeTruthy();
    await expect(validateOauthDpopProof(jwt, "POST", htu, "resource-access-token", options)).rejects.toThrow(
      "replayed jti",
    );
  });

  it("throws UseDpopNonceError for fabricated nonce", async () => {
    const { now, ecKeys, publicJwk, htu } = await buildValidProof();
    const jwt = await createOauthDpopJwt(ecKeys, publicJwk, "POST", htu, null, "fabricated");

    await expect(
      validateOauthDpopProof(jwt, "POST", htu, null, {
        db: env.DIRECTORY,
        nonceSecret: env.OAUTH_NONCE_SECRET ?? "",
        now,
      }),
    ).rejects.toBeInstanceOf(UseDpopNonceError);
  });
});
