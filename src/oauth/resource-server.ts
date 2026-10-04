// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { initDirectory, RepoNotFoundError, resolveRepo } from "../directory";
import { sha256Base64url } from "../auth";
import type { Env } from "../types";
import { validateOauthDpopProof } from "./dpop";
import { parseOAuthScope } from "./scopes";
import { getOAuthTokenWithSession, initOAuth } from "./store";

const INVALID_OAUTH_TOKEN_MESSAGE = "Invalid OAuth access token";

export class InvalidOauthTokenError extends Error {
  constructor() {
    super(INVALID_OAUTH_TOKEN_MESSAGE);
    this.name = "InvalidOauthTokenError";
  }
}

export async function resolveOAuthAccessToken(
  accessToken: string,
  dpopJwt: string,
  method: string,
  url: string,
  env: Env,
  now: number,
): Promise<{ did: string; doId: string; scope: string }> {
  await initOAuth(env.DIRECTORY);
  await initDirectory(env.DIRECTORY);

  let proof;
  try {
    proof = await validateOauthDpopProof(dpopJwt, method, url, accessToken, {
      db: env.DIRECTORY,
      nonceSecret: env.OAUTH_NONCE_SECRET ?? "",
      now,
      requireNonce: false,
    });
  } catch {
    throw new InvalidOauthTokenError();
  }

  const accessTokenHash = await sha256Base64url(accessToken);
  const joined = await getOAuthTokenWithSession(env.DIRECTORY, accessTokenHash);
  if (!joined) {
    throw new InvalidOauthTokenError();
  }

  const { token, sessionExp } = joined;
  if (token.exp <= now || sessionExp <= now) {
    throw new InvalidOauthTokenError();
  }
  if (token.dpopJkt !== proof.thumbprint) {
    throw new InvalidOauthTokenError();
  }

  let resolved;
  try {
    resolved = await resolveRepo(token.did, env);
  } catch (err) {
    if (err instanceof RepoNotFoundError) {
      throw new InvalidOauthTokenError();
    }
    throw err;
  }

  return { did: token.did, doId: resolved.doId, scope: token.scope };
}

export function enforceOAuthScope(
  scope: string,
  op: "write" | "uploadBlob",
  collections: string[],
): string | null {
  const tokens = parseOAuthScope(scope);
  if (!tokens) {
    return "scope";
  }
  const hasTransition = tokens.some((token) => token.kind === "transition");
  const repoNsids = new Set(
    tokens
      .filter((token) => token.kind === "repo")
      .map((token) => token.collection),
  );
  const hasBlob = tokens.some((token) => token.kind === "blob" && token.mime === "*/*");

  if (op === "uploadBlob") {
    return hasTransition || hasBlob ? null : "blob";
  }

  for (const collection of collections) {
    if (!hasTransition && !repoNsids.has(collection)) {
      return collection;
    }
  }
  return null;
}

export function enforceOAuthRpcScope(scope: string, lxm: string, aud: string): string | null {
  const tokens = parseOAuthScope(scope);
  if (!tokens) {
    return "scope";
  }
  const permitted = tokens.some((token) =>
    token.kind === "rpc" &&
    (token.lxm === "*" || token.lxm === lxm) &&
    (token.aud === "*" || token.aud === aud),
  );
  return permitted ? null : `${lxm}?aud=${aud}`;
}
