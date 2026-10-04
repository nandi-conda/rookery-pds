// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { isValidDid, NSID } from "@atproto/syntax";

export type OAuthScopeToken =
  | { kind: "atproto" }
  | { kind: "transition" }
  | { kind: "repo"; collection: string }
  | { kind: "blob"; mime: string }
  | { kind: "rpc"; lxm: string; aud: string };

function isValidAudience(aud: string): boolean {
  return aud === "*" || isValidDid(aud);
}

function parseRpcScope(token: string): OAuthScopeToken | null {
  const body = token.slice("rpc:".length);
  const queryStart = body.indexOf("?");
  if (queryStart <= 0) {
    return null;
  }

  const lxm = body.slice(0, queryStart);
  if (lxm !== "*" && !NSID.isValid(lxm)) {
    return null;
  }

  const params = new URLSearchParams(body.slice(queryStart + 1));
  const aud = params.get("aud");
  if (!aud || !isValidAudience(aud)) {
    return null;
  }
  for (const key of params.keys()) {
    if (key !== "aud") {
      return null;
    }
  }

  return { kind: "rpc", lxm, aud };
}

export function parseOAuthScopeToken(token: string): OAuthScopeToken | null {
  if (token === "atproto") {
    return { kind: "atproto" };
  }
  if (token === "transition:generic") {
    return { kind: "transition" };
  }
  if (token.startsWith("repo:")) {
    const collection = token.slice("repo:".length);
    return NSID.isValid(collection) ? { kind: "repo", collection } : null;
  }
  if (token.startsWith("blob:")) {
    const mime = token.slice("blob:".length);
    return mime === "*/*" ? { kind: "blob", mime } : null;
  }
  if (token.startsWith("rpc:")) {
    return parseRpcScope(token);
  }
  return null;
}

export function parseOAuthScope(scope: string): OAuthScopeToken[] | null {
  const rawTokens = scope.split(/\s+/).filter(Boolean);
  if (rawTokens.length === 0 || !rawTokens.includes("atproto")) {
    return null;
  }

  const tokens: OAuthScopeToken[] = [];
  for (const raw of rawTokens) {
    const parsed = parseOAuthScopeToken(raw);
    if (!parsed) {
      return null;
    }
    tokens.push(parsed);
  }
  return tokens;
}

export function isValidOAuthScopeString(scope: string): boolean {
  return parseOAuthScope(scope) !== null;
}

export function isValidServiceAuthAudience(aud: string): boolean {
  return isValidDid(aud);
}

export function isValidServiceAuthLxm(lxm: string): boolean {
  return NSID.isValid(lxm);
}
