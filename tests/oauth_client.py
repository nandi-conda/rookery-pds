# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""An OAuth client for tests: a P-256 DPoP key, PAR with the server nonce
dance, consent through a WelcomeMat agent, and the token endpoint."""

import json
import secrets
import time
import uuid

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from conftest import ORIGIN, unique
from rookery.encoding import b64url_encode, sha256_b64url
from rookery.net import HttpResponse

PAR_PATH = "/oauth/par"
AUTHORIZE_PATH = "/oauth/authorize"
TOKEN_PATH = "/oauth/token"
REVOKE_PATH = "/oauth/revoke"
AUTHORIZE_URL = ORIGIN + AUTHORIZE_PATH
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


def _coordinate(value: int) -> str:
    return b64url_encode(value.to_bytes(32, "big"))


class EcKey:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        numbers = self.key.public_key().public_numbers()
        self.jwk = {"kty": "EC", "crv": "P-256", "x": _coordinate(numbers.x), "y": _coordinate(numbers.y)}
        canonical = json.dumps({"crv": "P-256", "kty": "EC", "x": self.jwk["x"], "y": self.jwk["y"]}, separators=(",", ":"))
        self.thumbprint = sha256_b64url(canonical)

    def jwt(self, header: dict, payload: dict) -> str:
        signing_input = ".".join(
            b64url_encode(json.dumps(part, separators=(",", ":")).encode()) for part in (header, payload)
        )
        r, s = decode_dss_signature(self.key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256())))
        return f"{signing_input}.{b64url_encode(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"

    def dpop(self, method: str, url: str, access_token: str | None = None, nonce: str | None = None) -> str:
        payload = {"jti": str(uuid.uuid4()), "htm": method, "htu": url, "iat": int(time.time())}
        if access_token is not None:
            payload["ath"] = sha256_b64url(access_token)
        if nonce is not None:
            payload["nonce"] = nonce
        return self.jwt({"typ": "dpop+jwt", "alg": "ES256", "jwk": self.jwk}, payload)


def client_metadata(client_id: str, **overrides) -> dict:
    return dict({
        "client_id": client_id,
        "redirect_uris": ["http://127.0.0.1/callback"],
        "response_types": ["code"],
        "grant_types": ["authorization_code"],
        "scope": "atproto",
        "dpop_bound_access_tokens": True,
        "token_endpoint_auth_method": "none",
        "client_name": "Test Client",
        "client_uri": "https://client.example",
    }, **overrides)


def serve_metadata(env, client_id: str, metadata: dict) -> None:
    body = json.dumps(metadata).encode()
    env.http.routes[client_id] = lambda *_: HttpResponse(200, body, {"content-type": "application/json"})


def new_client_id(prefix: str = "client") -> str:
    return f"https://client.example/{unique(prefix)}.json"


def pkce_pair() -> tuple[str, str]:
    verifier = b64url_encode(secrets.token_bytes(32))
    return verifier, sha256_b64url(verifier)


def par_form(client_id: str, **overrides) -> tuple[dict, str]:
    verifier, challenge = pkce_pair()
    values = {
        "client_id": client_id,
        "response_type": "code",
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "redirect_uri": "http://127.0.0.1/callback",
        "scope": "atproto",
        "state": f"state-{uuid.uuid4()}",
    }
    for key, value in overrides.items():
        if value is None:
            values.pop(key, None)
        else:
            values[key] = value
    return values, verifier


async def post_with_nonce(client, path: str, form: dict, key: EcKey):
    """POST a form with a DPoP proof, first without a nonce (expecting the
    use_dpop_nonce challenge), then with the nonce the server handed out."""
    url = ORIGIN + path
    challenged = await client.post(path, form=form, headers={"dpop": key.dpop("POST", url)})
    assert challenged.status == 400
    assert challenged.json()["error"] == "use_dpop_nonce"
    nonce = challenged.headers["dpop-nonce"]
    response = await client.post(path, form=form, headers={"dpop": key.dpop("POST", url, nonce=nonce)})
    assert response.headers.get("dpop-nonce")
    return response


class Par:
    def __init__(self, request_uri, key, client_id, redirect_uri, verifier, state):
        self.request_uri = request_uri
        self.key = key
        self.client_id = client_id
        self.redirect_uri = redirect_uri
        self.verifier = verifier
        self.state = state

    def authorize_path(self, deny: bool = False) -> str:
        from urllib.parse import urlencode
        query = {"request_uri": self.request_uri, "client_id": self.client_id}
        if deny:
            query["deny"] = "1"
        return f"{AUTHORIZE_PATH}?{urlencode(query)}"


async def do_par(client, client_id: str | None = None, redirect_uri: str = "http://127.0.0.1/callback", **form_overrides) -> Par:
    client_id = client_id or new_client_id()
    form, verifier = par_form(client_id, redirect_uri=redirect_uri, **form_overrides)
    key = EcKey()
    response = await post_with_nonce(client, PAR_PATH, form, key)
    assert response.status == 201, response.text
    body = response.json()
    assert body["request_uri"].startswith("urn:ietf:params:oauth:request_uri:")
    assert body["expires_in"] == 300
    return Par(body["request_uri"], key, client_id, redirect_uri, verifier, form.get("state"))


def consent_headers(agent, access_token: str | None = None, htu: str | None = None) -> dict:
    token = access_token or agent.make_access_token()
    overrides = {"htu": htu} if htu else {}
    return {"authorization": f"DPoP {token}", "dpop": agent.dpop("GET", AUTHORIZE_PATH, token, **overrides)}


async def authorize_code(client, par: Par, agent) -> str:
    from fakes import query_of
    response = await client.get(par.authorize_path(), headers=consent_headers(agent))
    assert response.status == 302, response.text
    code = query_of(response.headers["location"]).get("code")
    assert code
    return code


def code_form(par: Par, code: str, **overrides) -> dict:
    values = {
        "grant_type": "authorization_code",
        "client_id": par.client_id,
        "code": code,
        "redirect_uri": par.redirect_uri,
        "code_verifier": par.verifier,
    }
    for key, value in overrides.items():
        if value is None:
            values.pop(key, None)
        else:
            values[key] = value
    return values


async def exchange_code(client, par: Par, code: str, key: EcKey | None = None, **overrides):
    return await post_with_nonce(client, TOKEN_PATH, code_form(par, code, **overrides), key or par.key)


async def refresh(client, par: Par, refresh_token: str, key: EcKey | None = None):
    form = {"grant_type": "refresh_token", "client_id": par.client_id, "refresh_token": refresh_token}
    return await post_with_nonce(client, TOKEN_PATH, form, key or par.key)


def token_success(response) -> dict:
    assert response.status == 200, response.text
    body = response.json()
    assert sorted(body) == ["access_token", "expires_in", "refresh_token", "scope", "sub", "token_type"]
    assert body["access_token"].startswith("rkat_")
    assert body["refresh_token"].startswith("rkrt_")
    assert body["token_type"] == "DPoP"
    return body


def oauth_headers(key: EcKey, method: str, path: str, access_token: str) -> dict:
    return {"authorization": f"DPoP {access_token}", "dpop": key.dpop(method, ORIGIN + path, access_token)}
