import { env } from "./helpers";
import {
  consumeOAuthCode,
  getOAuthCode,
  getOAuthParRequest,
  getOAuthSessionByRefreshTokenHash,
  getOAuthTokenByAccessTokenHash,
  getOAuthTokenWithSession,
  initOAuth,
  insertOAuthCode,
  insertOAuthDpopJti,
  insertOAuthParRequest,
  insertOAuthSession,
  insertOAuthToken,
  rotateOAuthSessionRefresh,
} from "../src/oauth/store";

describe("oauth store", () => {
  beforeEach(async () => {
    await initOAuth(env.DIRECTORY);
  });

  it("initializes idempotently", async () => {
    await initOAuth(env.DIRECTORY);
    await initOAuth(env.DIRECTORY);
  });

  it("round-trips rows in all OAuth tables", async () => {
    const suffix = crypto.randomUUID();
    const now = 1_700_000_000;

    const parRequest = {
      requestUri: `urn:ietf:params:oauth:request_uri:${suffix}`,
      clientId: `https://client.example/${suffix}`,
      params: JSON.stringify({ response_type: "code", state: suffix }),
      codeChallenge: `challenge-${suffix}`,
      redirectUri: `https://client.example/cb/${suffix}`,
      scope: "atproto",
      dpopJkt: `jkt-${suffix}`,
      exp: now + 60,
    };
    await insertOAuthParRequest(env.DIRECTORY, parRequest, now);
    await expect(getOAuthParRequest(env.DIRECTORY, parRequest.requestUri)).resolves.toEqual(
      parRequest,
    );

    const code = {
      codeHash: `code-hash-${suffix}`,
      clientId: parRequest.clientId,
      redirectUri: parRequest.redirectUri,
      codeChallenge: parRequest.codeChallenge,
      scope: "atproto",
      did: `did:plc:${suffix.replace(/-/g, "")}`,
      dpopJkt: parRequest.dpopJkt,
      exp: now + 120,
    };
    await insertOAuthCode(env.DIRECTORY, code, now);
    await expect(getOAuthCode(env.DIRECTORY, code.codeHash)).resolves.toEqual(code);

    const session = {
      sessionId: `session-${suffix}`,
      refreshTokenHash: `refresh-hash-${suffix}`,
      clientId: parRequest.clientId,
      did: code.did,
      scope: "atproto",
      dpopJkt: parRequest.dpopJkt,
      exp: now + 3600,
    };
    await insertOAuthSession(env.DIRECTORY, session, now);
    await expect(
      getOAuthSessionByRefreshTokenHash(env.DIRECTORY, session.refreshTokenHash),
    ).resolves.toEqual(session);

    const token = {
      accessTokenHash: `access-hash-${suffix}`,
      sessionId: session.sessionId,
      clientId: parRequest.clientId,
      did: code.did,
      scope: "atproto",
      dpopJkt: parRequest.dpopJkt,
      exp: now + 300,
    };
    await insertOAuthToken(env.DIRECTORY, token, now);
    await expect(
      getOAuthTokenByAccessTokenHash(env.DIRECTORY, token.accessTokenHash),
    ).resolves.toEqual(token);

    await expect(insertOAuthDpopJti(env.DIRECTORY, `jti-hash-${suffix}`, now + 300, now))
      .resolves.toBe(true);
  });

  it("rejects duplicate refresh token hashes", async () => {
    const suffix = crypto.randomUUID();
    const now = 1_700_000_000;
    const session = {
      sessionId: `session-a-${suffix}`,
      refreshTokenHash: `refresh-hash-duplicate-${suffix}`,
      clientId: "https://client.example",
      did: "did:plc:duplicate",
      scope: "atproto",
      dpopJkt: "jkt",
      exp: now + 3600,
    };
    await insertOAuthSession(env.DIRECTORY, session, now);
    await expect(
      insertOAuthSession(
        env.DIRECTORY,
        { ...session, sessionId: `session-b-${suffix}` },
        now,
      ),
    ).rejects.toThrow();
  });

  it("detects DPoP JTI replay atomically", async () => {
    const now = 1_700_000_000;
    const jtiHash = `jti-replay-${crypto.randomUUID()}`;
    await expect(insertOAuthDpopJti(env.DIRECTORY, jtiHash, now + 300, now)).resolves.toBe(true);
    await expect(insertOAuthDpopJti(env.DIRECTORY, jtiHash, now + 300, now)).resolves.toBe(false);
  });

  it("consumes OAuth codes atomically", async () => {
    const suffix = crypto.randomUUID();
    const now = 1_700_000_000;
    const code = {
      codeHash: `consume-code-${suffix}`,
      clientId: `https://client.example/${suffix}`,
      redirectUri: `https://client.example/cb/${suffix}`,
      codeChallenge: `challenge-${suffix}`,
      scope: "atproto",
      did: `did:plc:${suffix.replace(/-/g, "")}`,
      dpopJkt: `jkt-${suffix}`,
      exp: now + 120,
    };
    await insertOAuthCode(env.DIRECTORY, code, now);

    await expect(consumeOAuthCode(env.DIRECTORY, code.codeHash)).resolves.toEqual(code);
    await expect(getOAuthCode(env.DIRECTORY, code.codeHash)).resolves.toBeNull();
    await expect(consumeOAuthCode(env.DIRECTORY, code.codeHash)).resolves.toBeNull();
  });

  it("rotates refresh token hashes with a guarded update", async () => {
    const suffix = crypto.randomUUID();
    const now = 1_700_000_000;
    const session = {
      sessionId: `session-rotate-${suffix}`,
      refreshTokenHash: `refresh-old-${suffix}`,
      clientId: "https://client.example",
      did: "did:plc:rotate",
      scope: "atproto",
      dpopJkt: "jkt",
      exp: now + 3600,
    };
    await insertOAuthSession(env.DIRECTORY, session, now);

    await expect(
      rotateOAuthSessionRefresh(
        env.DIRECTORY,
        session.sessionId,
        session.refreshTokenHash,
        `refresh-new-${suffix}`,
      ),
    ).resolves.toBe(true);
    await expect(
      rotateOAuthSessionRefresh(
        env.DIRECTORY,
        session.sessionId,
        session.refreshTokenHash,
        `refresh-never-${suffix}`,
      ),
    ).resolves.toBe(false);
  });

  it("reads OAuth tokens through their owning sessions", async () => {
    const suffix = crypto.randomUUID();
    const now = 1_700_000_000;
    const session = {
      sessionId: `session-join-${suffix}`,
      refreshTokenHash: `refresh-join-${suffix}`,
      clientId: "https://client.example",
      did: "did:plc:join",
      scope: "atproto repo:org.example.thing",
      dpopJkt: "jkt",
      exp: now + 3600,
    };
    await insertOAuthSession(env.DIRECTORY, session, now);
    const token = {
      accessTokenHash: `access-join-${suffix}`,
      sessionId: session.sessionId,
      clientId: session.clientId,
      did: session.did,
      scope: session.scope,
      dpopJkt: session.dpopJkt,
      exp: now + 300,
    };
    await insertOAuthToken(env.DIRECTORY, token, now);

    await expect(getOAuthTokenWithSession(env.DIRECTORY, token.accessTokenHash)).resolves.toEqual({
      token,
      sessionExp: session.exp,
    });
    await env.DIRECTORY.prepare("DELETE FROM oauth_sessions WHERE session_id = ?")
      .bind(session.sessionId)
      .run();
    await expect(getOAuthTokenWithSession(env.DIRECTORY, token.accessTokenHash)).resolves.toBeNull();
  });
});
