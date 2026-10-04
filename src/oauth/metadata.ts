// SPDX-License-Identifier: MIT
// Copyright (c) 2026 sol pbc

export const OAUTH_PAR_PATH = "/oauth/par";
export const OAUTH_AUTHORIZE_PATH = "/oauth/authorize";
export const OAUTH_TOKEN_PATH = "/oauth/token";
export const OAUTH_REVOKE_PATH = "/oauth/revoke";

export interface AuthorizationServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  pushed_authorization_request_endpoint: string;
  require_pushed_authorization_requests: true;
  response_types_supported: ["code"];
  grant_types_supported: ["authorization_code", "refresh_token"];
  code_challenge_methods_supported: ["S256"];
  token_endpoint_auth_methods_supported: ["none", "private_key_jwt"];
  token_endpoint_auth_signing_alg_values_supported: ["ES256"];
  scopes_supported: ["atproto"];
  dpop_signing_alg_values_supported: ["ES256"];
  authorization_response_iss_parameter_supported: true;
  client_id_metadata_document_supported: true;
  revocation_endpoint: string;
  revocation_endpoint_auth_methods_supported: ["none", "private_key_jwt"];
  revocation_endpoint_auth_signing_alg_values_supported: ["ES256"];
}

export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: [string];
}

export function buildAuthorizationServerMetadata(
  issuer: string,
): AuthorizationServerMetadata {
  return {
    issuer,
    authorization_endpoint: `${issuer}${OAUTH_AUTHORIZE_PATH}`,
    token_endpoint: `${issuer}${OAUTH_TOKEN_PATH}`,
    pushed_authorization_request_endpoint: `${issuer}${OAUTH_PAR_PATH}`,
    require_pushed_authorization_requests: true,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
    token_endpoint_auth_signing_alg_values_supported: ["ES256"],
    scopes_supported: ["atproto"],
    dpop_signing_alg_values_supported: ["ES256"],
    authorization_response_iss_parameter_supported: true,
    client_id_metadata_document_supported: true,
    revocation_endpoint: `${issuer}${OAUTH_REVOKE_PATH}`,
    revocation_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
    revocation_endpoint_auth_signing_alg_values_supported: ["ES256"],
  };
}

export function buildProtectedResourceMetadata(issuer: string): ProtectedResourceMetadata {
  return {
    resource: issuer,
    authorization_servers: [issuer],
  };
}
