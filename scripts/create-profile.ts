import crypto from "node:crypto";
import { readFileSync } from "node:fs";

const CREDS_PATH = "scripts/rookery-creds.json";
const creds = JSON.parse(readFileSync(CREDS_PATH, "utf-8")) as {
  did: string; handle: string; access_token: string;
  private_key_pem: string; public_jwk: { kty: string; n: string; e: string };
  pds_host: string; pds_origin: string;
};

function base64url(input: Buffer | Uint8Array): string {
  return Buffer.from(input).toString("base64url");
}

function createJwt(header: object, payload: object, privateKeyPem: string): string {
  const h = base64url(Buffer.from(JSON.stringify(header)));
  const p = base64url(Buffer.from(JSON.stringify(payload)));
  const sign = crypto.createSign("RSA-SHA256");
  sign.update(`${h}.${p}`);
  const sig = sign.sign(privateKeyPem, "base64url");
  return `${h}.${p}.${sig}`;
}

function createDpopProof(
  method: string, url: string, accessToken: string,
  pubJwk: { kty: string; n: string; e: string }, privateKeyPem: string,
): string {
  const ath = base64url(crypto.createHash("sha256").update(accessToken).digest());
  return createJwt(
    { typ: "dpop+jwt", alg: "RS256", jwk: pubJwk },
    { jti: crypto.randomUUID(), htm: method, htu: url, iat: Math.floor(Date.now() / 1000), ath },
    privateKeyPem,
  );
}

const url = `${creds.pds_origin}/xrpc/com.atproto.repo.createRecord`;
const dpop = createDpopProof("POST", url, creds.access_token, creds.public_jwk, creds.private_key_pem);

const record = {
  $type: "app.bsky.actor.profile",
  displayName: "coder",
  description: "Rookery bot on pds.latha.org",
};

const res = await fetch(url, {
  method: "POST",
  headers: {
    Authorization: `DPoP ${creds.access_token}`,
    DPoP: dpop,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    repo: creds.did,
    collection: "app.bsky.actor.profile",
    rkey: "self",
    record,
  }),
});

console.log(`Status: ${res.status}`);
console.log(await res.text());
