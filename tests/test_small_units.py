# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Small units: DPoP nonces, OAuth discovery metadata, handle DNS publishing."""

import json

import pytest

from fakes import Env
from rookery.handle_dns import HandleDnsError, publish_handle_dns
from rookery.net import HttpResponse
from rookery.oauth.nonce import derive_dpop_nonce, is_valid_dpop_nonce

SECRET = "nonce-secret"
NOW = 300 * 10_000 + 42
ISSUER = "https://rookery.test"


# DPoP nonce

def test_nonce_is_stable_inside_one_window():
    assert derive_dpop_nonce(SECRET, NOW + 1) == derive_dpop_nonce(SECRET, NOW + 100)


def test_nonce_accepts_current_and_previous_windows():
    assert is_valid_dpop_nonce(SECRET, derive_dpop_nonce(SECRET, NOW), NOW)
    assert is_valid_dpop_nonce(SECRET, derive_dpop_nonce(SECRET, NOW - 300), NOW)


def test_nonce_rejects_two_windows_old():
    stale = derive_dpop_nonce(SECRET, NOW - 600)
    assert stale != derive_dpop_nonce(SECRET, NOW)
    assert not is_valid_dpop_nonce(SECRET, stale, NOW)


def test_nonce_requires_a_secret():
    with pytest.raises(ValueError, match="OAuth nonce secret is required"):
        derive_dpop_nonce("", NOW)
    with pytest.raises(ValueError, match="OAuth nonce secret is required"):
        is_valid_dpop_nonce("", "nonce", NOW)


# OAuth discovery metadata

async def test_authorization_server_metadata(client):
    response = await client.get("/.well-known/oauth-authorization-server")
    assert response.status == 200
    assert response.json() == {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/oauth/authorize",
        "token_endpoint": f"{ISSUER}/oauth/token",
        "pushed_authorization_request_endpoint": f"{ISSUER}/oauth/par",
        "require_pushed_authorization_requests": True,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        "scopes_supported": ["atproto"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "authorization_response_iss_parameter_supported": True,
        "client_id_metadata_document_supported": True,
        "revocation_endpoint": f"{ISSUER}/oauth/revoke",
        "revocation_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "revocation_endpoint_auth_signing_alg_values_supported": ["ES256"],
    }


async def test_protected_resource_metadata(client):
    response = await client.get("/.well-known/oauth-protected-resource")
    assert response.status == 200
    assert response.json() == {"resource": ISSUER, "authorization_servers": [ISSUER]}


# Handle DNS

def dns_env(handler) -> Env:
    env = Env(CLOUDFLARE_DNS_TOKEN="token", CLOUDFLARE_ZONE_ID="zone")
    env.http.routes["https://api.cloudflare.com/"] = handler
    return env


async def test_creates_the_atproto_txt_record_when_none_exists():
    env = dns_env(lambda *_: HttpResponse(200, json.dumps({"success": True, "result": []}).encode()))
    await publish_handle_dns(env, "weather.agent.latha.org", "did:plc:x")
    assert [call["method"] for call in env.http.calls] == ["GET", "POST"]


async def test_reports_cloudflare_status_and_error_text():
    body = {"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]}
    env = dns_env(lambda *_: HttpResponse(403, json.dumps(body).encode()))
    with pytest.raises(HandleDnsError) as raised:
        await publish_handle_dns(env, "weather.agent.latha.org", "did:plc:x")
    assert str(raised.value) == (
        "Cloudflare DNS lookup for _atproto.weather.agent.latha.org failed (403): 10000 Authentication error")
