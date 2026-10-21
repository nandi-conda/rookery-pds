# SPDX-License-Identifier: MIT
# Copyright (c) 2026 sol pbc

"""Expanding include: permission sets into concrete scopes (atproto.com/specs/permission)."""

from roost.oauth.permission_sets import authority_domain, expand_permission_set
from roost.oauth.scopes import aud_matches, enforce_rpc_scope, enforce_scope, parse_scope

APPVIEW = "did:web:api.colibri.social#colibri_appview"

# social.colibri.permissionAccount as published, trimmed.
ACCOUNT_SET = {
    "type": "permission-set",
    "permissions": [
        {"type": "permission", "resource": "repo", "action": ["create", "update", "delete"],
         "collection": ["social.colibri.actor.data", "social.colibri.actor.profile"]},
        {"type": "permission", "resource": "rpc", "inheritAud": True,
         "lxm": ["social.colibri.actor.getData", "social.colibri.sync.subscribeEvents"]},
    ],
}


def test_authority_domain():
    assert authority_domain("social.colibri.permissionAccount") == "colibri.social"
    assert authority_domain("app.example.feed.authOnlyPost") == "feed.example.app"


def test_expands_repo_and_inherited_rpc_permissions():
    # Byte-for-byte what @atproto/oauth-scopes' IncludeScope.toScopes produces for this set.
    assert expand_permission_set("social.colibri.permissionAccount", ACCOUNT_SET, APPVIEW) == [
        "repo?collection=social.colibri.actor.data&collection=social.colibri.actor.profile",
        "rpc?lxm=social.colibri.actor.getData&lxm=social.colibri.sync.subscribeEvents"
        "&aud=did:web:api.colibri.social%23colibri_appview",
    ]


LICHEN_SET = {"type": "permission-set", "permissions": [{"type": "permission", "resource": "repo", "collection": [
    "wiki.lichen.wiki", "wiki.lichen.note", "wiki.lichen.noteRevision", "wiki.lichen.noteSnapshot",
    "wiki.lichen.membership"]}]}


async def test_token_scope_matches_the_reference_provider(env, monkeypatch):
    """reams.ink's broker rejects a token scope that differs from @atproto/oauth-provider's buildTokenScope."""
    from roost.oauth import permission_sets

    async def resolve(_env, nsid, _now=None):
        return LICHEN_SET
    monkeypatch.setattr(permission_sets, "resolve_permission_set", resolve)
    scope = await permission_sets.build_token_scope(
        env, "atproto repo:ink.reams.vaultAuthority include:wiki.lichen.permissions")
    assert scope == (
        "repo?collection=wiki.lichen.membership&collection=wiki.lichen.note&collection=wiki.lichen.noteRevision"
        "&collection=wiki.lichen.noteSnapshot&collection=wiki.lichen.wiki atproto repo:ink.reams.vaultAuthority")
    assert enforce_scope(scope, "write", [("wiki.lichen.note", "create"), ("ink.reams.vaultAuthority", "update")]) is None
    assert enforce_scope(scope, "write", [("wiki.lichen.other", "create")]) is not None


def test_ignores_permissions_it_cannot_honor_exactly():
    main = {"type": "permission-set", "permissions": [
        # outside the set's namespace
        {"type": "permission", "resource": "repo", "collection": ["app.bsky.feed.post"]},
        {"type": "permission", "resource": "rpc", "aud": "*", "lxm": ["com.atproto.server.createAccount"]},
        # unknown action
        {"type": "permission", "resource": "repo", "collection": ["social.colibri.a.b"], "action": ["read"]},
        # inheritAud with its own aud, or with no include aud given
        {"type": "permission", "resource": "rpc", "inheritAud": True, "aud": "*", "lxm": ["social.colibri.a.c"]},
        # a DID aud inside a set
        {"type": "permission", "resource": "rpc", "aud": APPVIEW, "lxm": ["social.colibri.a.d"]},
        # unknown parameter, unknown resource, wildcards
        {"type": "permission", "resource": "repo", "collection": ["social.colibri.a.e"], "where": "x"},
        {"type": "permission", "resource": "blob", "accept": ["*/*"]},
        {"type": "permission", "resource": "repo", "collection": ["*"]},
        # kept
        {"type": "permission", "resource": "rpc", "aud": "*", "lxm": ["social.colibri.a.f"]},
        {"type": "permission", "resource": "repo", "collection": ["social.colibri.deep.er.record"]},
        {"type": "permission", "resource": "repo", "collection": ["social.colibri.membership"],
         "action": ["delete", "create"]},
    ]}
    assert expand_permission_set("social.colibri.permissionX", main, None) == [
        "rpc:social.colibri.a.f?aud=*", "repo:social.colibri.deep.er.record",
        "repo:social.colibri.membership?action=create&action=delete",
    ]


def test_repo_actions_are_enforced():
    scope = "atproto repo:social.colibri.membership?action=create&action=delete repo:social.colibri.message"
    assert enforce_scope(scope, "write", [("social.colibri.membership", "create")]) is None
    assert enforce_scope(scope, "write", [("social.colibri.membership", "delete")]) is None
    assert enforce_scope(scope, "write", [("social.colibri.membership", "update")]) == \
        "repo:social.colibri.membership?action=update"
    assert enforce_scope(scope, "write", [("social.colibri.message", "update")]) is None
    assert enforce_scope("atproto transition:generic", "write", [("a.b.c", "delete")]) is None
    assert parse_scope("atproto repo:a.b.c?action=read") is None


def test_parses_include_and_fragment_auds():
    tokens = parse_scope(f"atproto include:social.colibri.permissionAccount?aud={APPVIEW} "
                         "rpc:app.bsky.actor.getProfile?aud=did:web:api.bsky.app%23bsky_appview")
    assert tokens[1] == {"kind": "include", "nsid": "social.colibri.permissionAccount", "aud": APPVIEW}
    assert tokens[2]["aud"] == "did:web:api.bsky.app#bsky_appview"
    assert parse_scope("atproto include:social.colibri.permissionAccount")[1]["aud"] is None
    for bad in ("include:social.colibri.permissionAccount?aud=did:web:x.example",
                "include:social.colibri.permissionAccount?aud=*",
                "include:social.colibri.permissionAccount?lxm=x",
                "rpc:a.b.c?aud=did:web:x.example%23"):
        assert parse_scope(f"atproto {bad}") is None, bad


def test_aud_matching():
    assert aud_matches("*", APPVIEW)
    assert aud_matches(APPVIEW, APPVIEW)
    assert aud_matches("did:web:api.colibri.social", APPVIEW)
    assert aud_matches("did:web:api.colibri.social", "did:web:api.colibri.social")
    assert not aud_matches(APPVIEW, "did:web:api.colibri.social#other")
    assert not aud_matches(APPVIEW, "did:web:api.colibri.social")


def test_expands_space_permissions():
    from roost.spaces.scopes import space_scope_denial
    me = "did:plc:me"
    main = {"type": "permission-set", "permissions": [
        # social.colibri.beta.permissionAccount, trimmed
        {"type": "permission", "resource": "space", "spaceType": "social.colibri.beta.actor.preferences",
         "authority": "self", "skey": "self", "collection": ["social.colibri.beta.actor.settings"],
         "action": ["read", "create", "update", "delete"], "manage": ["create", "update"]},
        {"type": "permission", "resource": "space", "spaceType": "social.colibri.beta.channel.text",
         "authority": "*", "action": ["read"]},
        # outside the namespace, or with an unknown key
        {"type": "permission", "resource": "space", "spaceType": "app.bsky.private", "action": ["read"]},
        {"type": "permission", "resource": "space", "spaceType": "social.colibri.beta.x.y",
         "collection": ["app.bsky.feed.post"], "action": ["create"]},
        {"type": "permission", "resource": "space", "spaceType": "social.colibri.beta.x.y", "where": "z"},
    ]}
    tokens = expand_permission_set("social.colibri.beta.permissionAccount", main, None)
    assert len(tokens) == 2
    scope = " ".join(["atproto", *tokens])
    prefs = {"type": "social.colibri.beta.actor.preferences", "authority": me, "skey": "self"}
    assert space_scope_denial(scope, me, prefs, action="read") is None
    assert space_scope_denial(scope, me, prefs, manage="create") is None
    assert space_scope_denial(scope, me, prefs, action="create", collection="social.colibri.beta.actor.settings") is None
    assert space_scope_denial(scope, me, prefs, manage="delete")
    assert space_scope_denial(scope, me, dict(prefs, authority="did:plc:other"), action="read")
    text = {"type": "social.colibri.beta.channel.text", "authority": "did:plc:other", "skey": "general"}
    assert space_scope_denial(scope, me, text, action="read") is None
    assert space_scope_denial(scope, me, text, action="create", collection="social.colibri.beta.channel.message")


def test_parses_the_multi_value_repo_and_rpc_forms():
    scope = ("atproto repo?collection=a.b.c&collection=a.b.d&action=create "
             "rpc?lxm=a.b.get&lxm=a.b.list&aud=did:web:x.test%23svc")
    assert enforce_scope(scope, "write", [("a.b.d", "create")]) is None
    assert enforce_scope(scope, "write", [("a.b.d", "delete")]) == "repo:a.b.d?action=delete"
    assert enforce_rpc_scope(scope, "a.b.list", "did:web:x.test#svc") is None
    assert enforce_rpc_scope(scope, "a.b.other", "did:web:x.test#svc") is not None
    for bad in ("repo?action=create", "repo?collection=a.b.c&collection=nope", "rpc?lxm=a.b.get",
                "rpc?lxm=a.b.get&aud=did:web:x.test&aud=did:web:y.test"):
        assert parse_scope(f"atproto {bad}") is None, bad
