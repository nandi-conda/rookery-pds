# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

PAR_PATH = "/oauth/par"
AUTHORIZE_PATH = "/oauth/authorize"
TOKEN_PATH = "/oauth/token"
REVOKE_PATH = "/oauth/revoke"


def authorization_server_metadata(issuer: str) -> dict:
    return {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}{AUTHORIZE_PATH}",
        "token_endpoint": f"{issuer}{TOKEN_PATH}",
        "pushed_authorization_request_endpoint": f"{issuer}{PAR_PATH}",
        "require_pushed_authorization_requests": True,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        "scopes_supported": ["atproto"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "authorization_response_iss_parameter_supported": True,
        "client_id_metadata_document_supported": True,
        "revocation_endpoint": f"{issuer}{REVOKE_PATH}",
        "revocation_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "revocation_endpoint_auth_signing_alg_values_supported": ["ES256"],
    }


def protected_resource_metadata(issuer: str) -> dict:
    return {"resource": issuer, "authorization_servers": [issuer]}
