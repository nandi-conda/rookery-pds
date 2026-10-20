# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Routes for human accounts: com.atproto.server.createAccount/createSession/
refreshSession/deleteSession, the /join page, and password sign-in on the OAuth
consent page. Agents keep enrolling through WelcomeMat; both kinds of account
live in the same directory and Account DOs."""

import json
import re

from .. import directory
from ..app import (
    AuthFailure,
    _extract_invite_token,
    _requested_name,
    check_handle_name,
    finish_consent,
    is_commons,
    now_s,
    provision_account,
    read_json,
    router,
)
from ..errors import XrpcError
from ..oauth import store as oauth_store
from ..oauth.metadata import AUTHORIZE_PATH
from ..web import Response, html_response, json_response
from . import store
from .pages import render_consent_page, render_join_page, render_joined_page

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
FRAME_HEADERS = {"X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'"}


def page(markup: str, status: int = 200) -> Response:
    response = html_response(markup, status)
    for key, value in FRAME_HEADERS.items():
        response.set_header(key, value)
    return response


def service_did(env) -> str:
    return f"did:web:{env.ROOKERY_HOSTNAME}"


def invite_token(value) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    value = value.strip()
    return _extract_invite_token(value) if "#" in value else value


async def create_human_account(env, name: str, password, email, invite_value) -> dict:
    """Validate and create a password account; returns {did, handle}. Raises XrpcError/AuthFailure."""
    problem = store.password_problem(password)
    if problem:
        raise XrpcError("InvalidPassword", problem)
    if email is not None and email != "":
        if not isinstance(email, str) or not EMAIL_RE.match(email) or len(email) > 254:
            raise XrpcError("InvalidEmail", "Invalid email address")
        email = email.lower()
    else:
        email = None
    await store.init_humans(env.db)
    invite = None
    if is_commons(env):
        invite = invite_token(invite_value)
        if not invite:
            raise XrpcError("InvalidInviteCode", "An invite code is required to join this host.")
        if not await directory.is_invite_available(env.db, invite):
            raise XrpcError("InvalidInviteCode", "Invite code is invalid or already spent.")
    if email and await store.email_taken(env.db, email):
        raise XrpcError("EmailTaken", "That email is already in use.")
    handle = await check_handle_name(env, name.lower())
    did = await provision_account(env, handle, invite, None)
    await store.set_password(env.db, did, password, email)
    return {"did": did, "handle": handle}


def failure_message(exc: Exception) -> tuple[str, str, int]:
    if isinstance(exc, XrpcError):
        return exc.name, exc.message, exc.status
    parsed = json.loads(exc.response.body)
    return parsed["error"], parsed["message"], exc.response.status


# XRPC

@router.post("/xrpc/com.atproto.server.createAccount")
async def create_account(request, env):
    body = await read_json(request)
    if body is None:
        raise XrpcError("InvalidRequest", "Invalid JSON body")
    handle = body.get("handle")
    if not isinstance(handle, str) or not handle:
        raise XrpcError("InvalidHandle", "Handle is required")
    if body.get("did") or body.get("plcOp"):
        raise XrpcError("InvalidRequest", "Bringing an existing DID is not supported here yet")
    name = _requested_name(env, handle) if "." in handle else handle
    account = await create_human_account(env, name, body.get("password"), body.get("email"), body.get("inviteCode"))
    tokens = await store.create_session(env.db, account["did"], service_did(env))
    return json_response({"did": account["did"], "handle": account["handle"], **tokens})


@router.post("/xrpc/com.atproto.server.createSession")
async def create_session(request, env):
    body = await read_json(request)
    if body is None:
        raise XrpcError("InvalidRequest", "Invalid JSON body")
    identifier, password = body.get("identifier"), body.get("password")
    if not isinstance(identifier, str) or not identifier or not isinstance(password, str):
        raise XrpcError("InvalidRequest", "identifier and password are required")
    login = await check_login(env, identifier, password)
    tokens = await store.create_session(env.db, login["did"], service_did(env))
    out = {"did": login["did"], "handle": login["handle"], "active": True, **tokens}
    if login["email"]:
        out.update(email=login["email"], emailConfirmed=False)
    return json_response(out)


async def check_login(env, identifier: str, password: str) -> dict:
    await store.init_humans(env.db)
    identifier = identifier.strip().lower().removeprefix("@")
    if identifier and not any(mark in identifier for mark in ".@:"):
        identifier += env.ROOKERY_HANDLE_DOMAIN  # a bare name means a handle on this host
    key = identifier
    if await store.too_many_failures(env.db, key):
        raise XrpcError("RateLimitExceeded", "Too many failed sign-in attempts. Try again in 15 minutes.", 429)
    login = await store.find_login(env.db, identifier)
    if not login or not store.verify_password(password, login["password_hash"]):
        await store.note_login_failure(env.db, key)
        raise XrpcError("AuthenticationRequired", "Invalid identifier or password", 401)
    return login


def bearer(request) -> str:
    header = request.header("authorization") or ""
    if header[:7].lower() != "bearer ":
        raise XrpcError("AuthenticationRequired", "Missing refresh token", 401)
    return header[7:].strip()


@router.post("/xrpc/com.atproto.server.refreshSession")
async def refresh_session(request, env):
    try:
        session = await store.rotate_session(env.db, bearer(request), service_did(env))
    except store.SessionError as exc:
        expired = "expired" in str(exc)
        raise XrpcError("ExpiredToken" if expired else "InvalidToken", str(exc), 400 if expired else 401) from exc
    return json_response({
        "did": session["did"], "handle": session["handle"], "active": True,
        "accessJwt": session["accessJwt"], "refreshJwt": session["refreshJwt"],
    })


@router.post("/xrpc/com.atproto.server.deleteSession")
async def delete_session(request, env):
    try:
        await store.delete_session(env.db, bearer(request))
    except store.SessionError as exc:
        raise XrpcError("InvalidToken", str(exc), 401) from exc
    return Response(200, b"", [])


# /join

@router.get("/join")
async def join_page(request, env):
    return page(render_join_page(env, {"invite": request.query("invite") or ""}))


@router.post("/join")
async def join_submit(request, env):
    form = await request.form()
    values = {key: form.get(key, "") for key in ("handle", "email", "invite")}
    if form.get("tos") != "1":
        return page(render_join_page(env, values, "Please agree to the rules of this host."), 400)
    try:
        account = await create_human_account(
            env, values["handle"].strip(), form.get("password"), values["email"].strip(), values["invite"],
        )
    except (XrpcError, AuthFailure) as exc:
        _, message, status = failure_message(exc)
        return page(render_join_page(env, values, message), status)
    return page(render_joined_page(env, account["did"], account["handle"]))


# OAuth: password sign-in for humans

@router.post(AUTHORIZE_PATH)
async def oauth_password_consent(request, env):
    form = await request.form()
    await oauth_store.init_oauth(env.db)
    request_uri = form.get("request_uri")
    par = await oauth_store.get_par_request(env.db, request_uri) if request_uri else None
    if not par or par["exp"] <= now_s() or par["client_id"] != form.get("client_id"):
        return page("<p>This sign-in request has expired. Go back to the app and try again.</p>", 400)
    params = json.loads(par["params"])
    if form.get("decision") == "deny":
        return await finish_consent(env, par, "", deny=True)
    identifier = form.get("identifier") or ""
    try:
        login = await check_login(env, identifier, form.get("password") or "")
    except XrpcError as exc:
        return page(render_consent_page(env, par, params, exc.message, identifier), exc.status)
    return await finish_consent(env, par, login["did"], deny=False)
