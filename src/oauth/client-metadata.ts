// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

import { base64urlDecode, parseJwt, sha256Base64url } from "../auth";
import type { Env } from "../types";
import type { EcPublicJwk } from "./dpop";
import { insertOAuthDpopJti } from "./store";

const CLIENT_METADATA_CACHE_TTL_MS = 10 * 60 * 1000;
const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_CLIENT_METADATA_BYTES = 64 * 1024;
const CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

export interface JsonWebKeySet {
  keys: EcPublicJwk[];
}

export interface ClientMetadata {
  client_id: string;
  redirect_uris: string[];
  response_types: string[];
  grant_types: string[];
  scope: string;
  dpop_bound_access_tokens: true;
  token_endpoint_auth_method?: "none" | "private_key_jwt";
  token_endpoint_auth_signing_alg?: "ES256";
  jwks?: JsonWebKeySet;
  application_type?: "web" | "native";
  [key: string]: unknown;
}

export function buildRookCliClientMetadata(hostname: string): ClientMetadata {
  const origin = `https://${hostname}`;
  return {
    client_id: `${origin}/client-metadata.json`,
    client_name: "rook cli",
    application_type: "native",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    redirect_uris: ["http://127.0.0.1/callback"],
    // Knot RPC scopes still name the commons knot; login works without knot membership.
    scope: "atproto",
    token_endpoint_auth_method: "none",
    dpop_bound_access_tokens: true,
    client_uri: origin,
  };
}

/** Commons / rook.host built-in id (legacy constant for direct equality checks). */
export const ROOK_CLI_CLIENT_METADATA: ClientMetadata = buildRookCliClientMetadata("rook.host");

export interface FetchClientMetadataOptions {
  fetch?: typeof fetch;
  timeoutMs?: number;
}

export interface VerifyClientAuthRequest {
  clientAssertionType?: string | null;
  clientAssertion?: string | null;
}

export interface VerifyClientAuthResult {
  method: "none" | "private_key_jwt";
  clientId: string;
}

type ClientMetadataCacheEntry = {
  metadata: ClientMetadata;
  fetchedAt: number;
};

export class ClientMetadataError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClientMetadataError";
  }
}

export class ClientAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ClientAuthError";
  }
}

const clientMetadataCache = new Map<string, ClientMetadataCacheEntry>();

export function __resetClientMetadataCache(): void {
  clientMetadataCache.clear();
}

function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function hasScope(scope: string, wanted: string): boolean {
  return scope.split(/\s+/).filter(Boolean).includes(wanted);
}

function isEcPublicJwk(value: unknown): value is EcPublicJwk {
  if (!isObject(value)) return false;
  return (
    value.kty === "EC" &&
    value.crv === "P-256" &&
    typeof value.x === "string" &&
    typeof value.y === "string" &&
    !("d" in value)
  );
}

function isAtprotoLoopbackClientId(url: URL): boolean {
  return url.protocol === "http:" && url.hostname === "localhost" && !url.hash;
}

/** Infer client metadata from AT Protocol loopback client_id query params. */
export function loopbackClientMetadata(clientId: string): ClientMetadata {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    throw new ClientMetadataError("client_id must be a URL");
  }
  if (!isAtprotoLoopbackClientId(url)) {
    throw new ClientMetadataError("not an AT Protocol loopback client_id");
  }
  const redirectUri = url.searchParams.get("redirect_uri");
  const scope = url.searchParams.get("scope") ?? "atproto";
  if (!redirectUri) {
    throw new ClientMetadataError("loopback client_id requires redirect_uri");
  }
  let redirect: URL;
  try {
    redirect = new URL(redirectUri);
  } catch {
    throw new ClientMetadataError("loopback redirect_uri is invalid");
  }
  if (
    redirect.protocol !== "http:" ||
    (redirect.hostname !== "127.0.0.1" &&
      redirect.hostname !== "localhost" &&
      redirect.hostname !== "[::1]")
  ) {
    throw new ClientMetadataError("loopback redirect_uri must be loopback http");
  }
  if (!scope.split(/\s+/).filter(Boolean).includes("atproto")) {
    throw new ClientMetadataError("loopback scope must include atproto");
  }
  return {
    client_id: clientId,
    client_name: "loopback oauth client",
    application_type: "native",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
    redirect_uris: [redirectUri],
    scope,
    token_endpoint_auth_method: "none",
    dpop_bound_access_tokens: true,
  };
}

function validateClientId(clientId: string, env: Pick<Env, "ROOKERY_HOSTNAME">): URL {
  let url: URL;
  try {
    url = new URL(clientId);
  } catch {
    throw new ClientMetadataError("client_id must be a URL");
  }
  if (url.hash) {
    throw new ClientMetadataError("client_id must not include a fragment");
  }
  // AT Protocol native/loopback clients (freeq-tui, etc.)
  if (isAtprotoLoopbackClientId(url)) {
    return url;
  }
  if (url.protocol !== "https:") {
    throw new ClientMetadataError("client_id must use https");
  }
  const builtInClientId = `https://${env.ROOKERY_HOSTNAME}/client-metadata.json`;
  if (url.hostname === env.ROOKERY_HOSTNAME && url.href !== builtInClientId) {
    throw new ClientMetadataError("client_id must not use the rookery origin");
  }
  return url;
}

function validateClientMetadata(clientId: string, body: unknown): ClientMetadata {
  if (!isObject(body)) {
    throw new ClientMetadataError("client metadata must be a JSON object");
  }
  if (body.client_id !== clientId) {
    throw new ClientMetadataError("client metadata client_id mismatch");
  }
  if (body.dpop_bound_access_tokens !== true) {
    throw new ClientMetadataError("client metadata must require DPoP-bound access tokens");
  }
  if (typeof body.scope !== "string" || !hasScope(body.scope, "atproto")) {
    throw new ClientMetadataError("client metadata scope must include atproto");
  }
  if (!isStringArray(body.response_types) || !body.response_types.includes("code")) {
    throw new ClientMetadataError("client metadata response_types must include code");
  }
  if (!isStringArray(body.grant_types) || !body.grant_types.includes("authorization_code")) {
    throw new ClientMetadataError("client metadata grant_types must include authorization_code");
  }
  if (!isStringArray(body.redirect_uris) || body.redirect_uris.length === 0) {
    throw new ClientMetadataError("client metadata redirect_uris must be a non-empty string array");
  }

  const authMethod = body.token_endpoint_auth_method;
  if (
    authMethod !== undefined &&
    authMethod !== "none" &&
    authMethod !== "private_key_jwt"
  ) {
    throw new ClientMetadataError("unsupported token_endpoint_auth_method");
  }
  if (
    body.token_endpoint_auth_signing_alg !== undefined &&
    body.token_endpoint_auth_signing_alg !== "ES256"
  ) {
    throw new ClientMetadataError("unsupported token_endpoint_auth_signing_alg");
  }

  if (authMethod === "private_key_jwt") {
    if (!isObject(body.jwks) || !Array.isArray(body.jwks.keys)) {
      throw new ClientMetadataError("private_key_jwt requires inline jwks");
    }
    if (!body.jwks.keys.every(isEcPublicJwk) || body.jwks.keys.length === 0) {
      throw new ClientMetadataError("private_key_jwt jwks must contain EC P-256 public keys");
    }
  }

  return body as unknown as ClientMetadata;
}

async function readBoundedJson(response: Response): Promise<unknown> {
  const contentLength = response.headers.get("content-length");
  if (contentLength !== null && Number(contentLength) > MAX_CLIENT_METADATA_BYTES) {
    throw new ClientMetadataError("client metadata response body is too large");
  }
  const body = await response.arrayBuffer();
  if (body.byteLength > MAX_CLIENT_METADATA_BYTES) {
    throw new ClientMetadataError("client metadata response body is too large");
  }
  try {
    return JSON.parse(new TextDecoder().decode(body));
  } catch {
    throw new ClientMetadataError("client metadata response is invalid JSON");
  }
}

export async function fetchClientMetadata(
  clientId: string,
  env: Pick<Env, "ROOKERY_HOSTNAME">,
  opts: FetchClientMetadataOptions = {},
): Promise<ClientMetadata> {
  validateClientId(clientId, env);

  const builtInClientId = `https://${env.ROOKERY_HOSTNAME}/client-metadata.json`;
  if (clientId === ROOK_CLI_CLIENT_METADATA.client_id) {
    return validateClientMetadata(clientId, ROOK_CLI_CLIENT_METADATA);
  }
  if (clientId === builtInClientId) {
    return validateClientMetadata(clientId, buildRookCliClientMetadata(env.ROOKERY_HOSTNAME));
  }
  try {
    if (new URL(clientId).hostname === "localhost" && new URL(clientId).protocol === "http:") {
      return validateClientMetadata(clientId, loopbackClientMetadata(clientId));
    }
  } catch {
    /* fall through */
  }

  const cached = clientMetadataCache.get(clientId);
  if (cached && Date.now() - cached.fetchedAt < CLIENT_METADATA_CACHE_TTL_MS) {
    return cached.metadata;
  }

  const fetchImpl = opts.fetch ?? fetch;
  const timeoutMs = opts.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  let response: Response;
  try {
    response = await fetchImpl(clientId, {
      redirect: "manual",
      signal: controller.signal,
    });
  } catch (err) {
    throw new ClientMetadataError(`client metadata fetch failed: ${(err as Error).message}`);
  } finally {
    clearTimeout(timeout);
  }

  if (response.status >= 300 && response.status < 400) {
    throw new ClientMetadataError("client metadata redirects are not allowed");
  }
  if (response.status !== 200) {
    throw new ClientMetadataError("client metadata fetch returned non-200 status");
  }
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.split(";")[0].trim().toLowerCase() !== "application/json") {
    throw new ClientMetadataError("client metadata content-type must be application/json");
  }

  const body = await readBoundedJson(response);
  const metadata = validateClientMetadata(clientId, body);
  clientMetadataCache.set(clientId, { metadata, fetchedAt: Date.now() });
  return metadata;
}

function isLoopbackRedirect(url: URL): boolean {
  return (
    url.protocol === "http:" &&
    (url.hostname === "127.0.0.1" || url.hostname === "[::1]" || url.hostname === "::1")
  );
}

export function matchRedirectUri(registered: string, presented: string): boolean {
  let registeredUrl: URL;
  let presentedUrl: URL;
  try {
    registeredUrl = new URL(registered);
    presentedUrl = new URL(presented);
  } catch {
    return false;
  }
  if (registeredUrl.hash || presentedUrl.hash) return false;
  if (isLoopbackRedirect(registeredUrl)) {
    return (
      presentedUrl.protocol === "http:" &&
      presentedUrl.hostname === registeredUrl.hostname &&
      presentedUrl.pathname === registeredUrl.pathname &&
      presentedUrl.search === registeredUrl.search
    );
  }
  return registered === presented;
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
    throw new ClientAuthError("invalid client public key");
  }
}

async function verifyAssertionWithJwks(
  metadata: ClientMetadata,
  signingInput: string,
  signature: string,
  kid: unknown,
): Promise<boolean> {
  const keys = metadata.jwks?.keys ?? [];
  const candidates = typeof kid === "string"
    ? keys.filter((key) => key.kid === kid)
    : keys;
  if (candidates.length === 0) {
    throw new ClientAuthError("client assertion key not found");
  }

  const signatureBytes = base64urlDecode(signature);
  const data = new TextEncoder().encode(signingInput);
  for (const jwk of candidates) {
    const key = await importEcVerifyKey(jwk);
    if (await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signatureBytes, data)) {
      return true;
    }
  }
  return false;
}

export async function verifyClientAuth(
  metadata: ClientMetadata,
  request: VerifyClientAuthRequest,
  issuer: string,
  db: D1Database,
  now: number,
): Promise<VerifyClientAuthResult> {
  const authMethod = metadata.token_endpoint_auth_method ?? "none";
  if (authMethod === "none") {
    if (request.clientAssertion || request.clientAssertionType) {
      throw new ClientAuthError("public clients must not send client assertions");
    }
    return { method: "none", clientId: metadata.client_id };
  }

  if (request.clientAssertionType !== CLIENT_ASSERTION_TYPE) {
    throw new ClientAuthError("invalid client_assertion_type");
  }
  if (!request.clientAssertion) {
    throw new ClientAuthError("missing client_assertion");
  }

  let jwt;
  try {
    jwt = parseJwt(request.clientAssertion);
  } catch {
    throw new ClientAuthError("client assertion is malformed");
  }

  const { header, payload, signingInput, signature } = jwt;
  if (header.alg !== "ES256") {
    throw new ClientAuthError("client assertion alg must be ES256");
  }
  if (header.jwk) {
    throw new ClientAuthError("client assertion must use metadata jwks");
  }
  const valid = await verifyAssertionWithJwks(metadata, signingInput, signature, header.kid);
  if (!valid) {
    throw new ClientAuthError("client assertion signature verification failed");
  }

  if (payload.iss !== metadata.client_id || payload.sub !== metadata.client_id) {
    throw new ClientAuthError("client assertion subject mismatch");
  }
  if (payload.aud !== issuer) {
    throw new ClientAuthError("client assertion audience mismatch");
  }
  if (typeof payload.exp !== "number" || payload.exp <= now) {
    throw new ClientAuthError("client assertion expired");
  }
  if (typeof payload.iat !== "number") {
    throw new ClientAuthError("client assertion missing iat");
  }
  if (payload.iat > now + 60) {
    throw new ClientAuthError("client assertion iat is in the future");
  }
  if (typeof payload.jti !== "string" || payload.jti.length === 0) {
    throw new ClientAuthError("client assertion missing jti");
  }

  const jtiHash = await sha256Base64url(
    `client_assertion:${metadata.client_id}:${payload.jti}`,
  );
  const inserted = await insertOAuthDpopJti(db, jtiHash, payload.exp, now);
  if (!inserted) {
    throw new ClientAuthError("client assertion replayed jti");
  }

  return { method: "private_key_jwt", clientId: metadata.client_id };
}
