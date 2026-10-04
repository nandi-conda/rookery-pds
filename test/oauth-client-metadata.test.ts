import { base64urlEncode } from "../src/auth";
import {
  __resetClientMetadataCache,
  ClientAuthError,
  ClientMetadataError,
  fetchClientMetadata,
  matchRedirectUri,
  verifyClientAuth,
  type ClientMetadata,
} from "../src/oauth/client-metadata";
import { initOAuth } from "../src/oauth/store";
import { env, generateEcKeys } from "./helpers";

const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

function validMetadata(
  clientId = "https://client.example/oauth-client.json",
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    client_id: clientId,
    redirect_uris: ["https://client.example/callback"],
    response_types: ["code"],
    grant_types: ["authorization_code"],
    scope: "atproto",
    dpop_bound_access_tokens: true,
    ...overrides,
  };
}

async function signClientAssertion(
  privateKey: CryptoKey,
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
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

describe("client metadata", () => {
  beforeEach(async () => {
    __resetClientMetadataCache();
    await initOAuth(env.DIRECTORY);
  });

  it("fetches and validates client metadata with manual redirect handling", async () => {
    const clientId = "https://client.example/oauth-client.json";
    let redirectMode: RequestRedirect | undefined;
    const fetchImpl = (async (_input: RequestInfo | URL, init?: RequestInit) => {
      redirectMode = init?.redirect;
      return jsonResponse(validMetadata(clientId));
    }) as typeof fetch;

    await expect(fetchClientMetadata(clientId, env, { fetch: fetchImpl })).resolves.toMatchObject({
      client_id: clientId,
      dpop_bound_access_tokens: true,
    });
    expect(redirectMode).toBe("manual");
  });

  it("rejects invalid metadata documents", async () => {
    const clientId = "https://client.example/oauth-client.json";
    const cases: Array<[string, unknown]> = [
      ["mismatched client_id", validMetadata("https://other.example/client.json")],
      ["dpop false", validMetadata(clientId, { dpop_bound_access_tokens: false })],
      ["missing atproto scope", validMetadata(clientId, { scope: "transition:generic" })],
      ["missing authorization_code", validMetadata(clientId, { grant_types: ["refresh_token"] })],
      ["missing code", validMetadata(clientId, { response_types: ["token"] })],
      ["private_key_jwt without inline jwks", validMetadata(clientId, {
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "https://client.example/jwks.json",
      })],
    ];

    for (const [name, body] of cases) {
      const fetchImpl = (async () => jsonResponse(body)) as typeof fetch;
      await expect(fetchClientMetadata(clientId, env, { fetch: fetchImpl }))
        .rejects.toThrow(ClientMetadataError);
      __resetClientMetadataCache();
      expect(name).toBeTruthy();
    }
  });

  it("rejects invalid client_id URLs before fetch", async () => {
    const fetchImpl = (async () => {
      throw new Error("should not fetch");
    }) as typeof fetch;

    await expect(fetchClientMetadata("http://client.example/client.json", env, { fetch: fetchImpl }))
      .rejects.toThrow("https");
    await expect(
      fetchClientMetadata("https://client.example/client.json#fragment", env, { fetch: fetchImpl }),
    ).rejects.toThrow("fragment");
    await expect(
      fetchClientMetadata("https://rookery.test/client.json", env, { fetch: fetchImpl }),
    ).rejects.toThrow("rookery origin");
  });

  it("resolves only the built-in CLI metadata path locally on the rookery origin", async () => {
    const clientId = "https://rookery.test/client-metadata.json";
    const fetchImpl = (async () => {
      throw new Error("the built-in metadata must not self-fetch");
    }) as typeof fetch;

    await expect(
      fetchClientMetadata("https://rook.host/client-metadata.json", {
        ROOKERY_HOSTNAME: "rook.host",
      }, { fetch: fetchImpl }),
    ).resolves.toMatchObject({ client_id: "https://rook.host/client-metadata.json" });

    __resetClientMetadataCache();
    await expect(
      fetchClientMetadata("https://rookery.test/client-metadata.json?alternate=1", env, {
        fetch: fetchImpl,
      }),
    ).rejects.toThrow("rookery origin");
  });

  it("rejects bad fetch responses", async () => {
    const clientId = "https://client.example/oauth-client.json";
    const responseCases: Response[] = [
      jsonResponse(validMetadata(clientId), 302),
      jsonResponse(validMetadata(clientId), 500),
      new Response("plain", { status: 200, headers: { "content-type": "text/plain" } }),
      new Response("[1,2,3]", { status: 200, headers: { "content-type": "application/json" } }),
      new Response("x".repeat(64 * 1024 + 1), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    ];

    for (const response of responseCases) {
      const fetchImpl = (async () => response.clone()) as typeof fetch;
      await expect(fetchClientMetadata(clientId, env, { fetch: fetchImpl }))
        .rejects.toThrow(ClientMetadataError);
      __resetClientMetadataCache();
    }
  });

  it("clears the metadata cache for tests", async () => {
    const clientId = "https://client.example/oauth-client.json";
    const successFetch = (async () => jsonResponse(validMetadata(clientId))) as typeof fetch;

    await expect(fetchClientMetadata(clientId, env, { fetch: successFetch })).resolves.toBeTruthy();
    __resetClientMetadataCache();

    const failingFetch = (async () => jsonResponse(validMetadata(clientId), 500)) as typeof fetch;
    await expect(fetchClientMetadata(clientId, env, { fetch: failingFetch }))
      .rejects.toThrow(ClientMetadataError);
  });

  it("matches redirect URIs with RFC 8252 loopback port variance only", () => {
    expect(matchRedirectUri("https://client.example/cb", "https://client.example/cb")).toBe(true);
    expect(matchRedirectUri("https://client.example/cb", "https://client.example/other")).toBe(
      false,
    );
    expect(matchRedirectUri("http://127.0.0.1:123/cb", "http://127.0.0.1:456/cb")).toBe(true);
    expect(matchRedirectUri("http://[::1]:123/cb", "http://[::1]:456/cb")).toBe(true);
    expect(matchRedirectUri("http://127.0.0.1:123/cb", "https://127.0.0.1:456/cb")).toBe(false);
    expect(matchRedirectUri("http://127.0.0.1:123/cb", "http://127.0.0.1:456/other")).toBe(
      false,
    );
    expect(matchRedirectUri("http://127.0.0.1:123/cb?a=1", "http://127.0.0.1:456/cb?a=2"))
      .toBe(false);
    expect(matchRedirectUri("http://localhost:123/cb", "http://localhost:456/cb")).toBe(false);
  });
});

describe("private_key_jwt client authentication", () => {
  const clientId = "https://client.example/oauth-client.json";
  const issuer = "https://rookery.test";
  const now = 1_700_000_000;

  beforeEach(async () => {
    await initOAuth(env.DIRECTORY);
  });

  async function buildMetadataAndAssertion(
    payloadOverrides: Record<string, unknown> = {},
    keyOverride?: CryptoKeyPair,
  ): Promise<{ metadata: ClientMetadata; assertion: string }> {
    const { ecKeys, publicJwk } = await generateEcKeys();
    const signingKeys = keyOverride ?? ecKeys;
    const metadata = validMetadata(clientId, {
      token_endpoint_auth_method: "private_key_jwt",
      token_endpoint_auth_signing_alg: "ES256",
      jwks: { keys: [{ ...publicJwk, kid: "client-key" }] },
    }) as ClientMetadata;
    const assertion = await signClientAssertion(
      signingKeys.privateKey,
      { alg: "ES256", kid: "client-key" },
      {
        iss: clientId,
        sub: clientId,
        aud: issuer,
        exp: now + 300,
        iat: now,
        jti: crypto.randomUUID(),
        ...payloadOverrides,
      },
    );
    return { metadata, assertion };
  }

  it("accepts a valid private_key_jwt assertion", async () => {
    const { metadata, assertion } = await buildMetadataAndAssertion();

    await expect(
      verifyClientAuth(
        metadata,
        { clientAssertionType: CLIENT_ASSERTION_TYPE, clientAssertion: assertion },
        issuer,
        env.DIRECTORY,
        now,
      ),
    ).resolves.toEqual({ method: "private_key_jwt", clientId });
  });

  it("rejects wrong audience", async () => {
    const { metadata, assertion } = await buildMetadataAndAssertion({ aud: "https://wrong.test" });

    await expect(
      verifyClientAuth(
        metadata,
        { clientAssertionType: CLIENT_ASSERTION_TYPE, clientAssertion: assertion },
        issuer,
        env.DIRECTORY,
        now,
      ),
    ).rejects.toThrow(ClientAuthError);
  });

  it("rejects a signature from a different key", async () => {
    const otherKeys = (await generateEcKeys()).ecKeys;
    const { metadata, assertion } = await buildMetadataAndAssertion({}, otherKeys);

    await expect(
      verifyClientAuth(
        metadata,
        { clientAssertionType: CLIENT_ASSERTION_TYPE, clientAssertion: assertion },
        issuer,
        env.DIRECTORY,
        now,
      ),
    ).rejects.toThrow(ClientAuthError);
  });

  it("rejects replayed assertion jti", async () => {
    const { metadata, assertion } = await buildMetadataAndAssertion();
    const request = { clientAssertionType: CLIENT_ASSERTION_TYPE, clientAssertion: assertion };

    await expect(verifyClientAuth(metadata, request, issuer, env.DIRECTORY, now)).resolves
      .toBeTruthy();
    await expect(verifyClientAuth(metadata, request, issuer, env.DIRECTORY, now))
      .rejects.toThrow(ClientAuthError);
  });
});
