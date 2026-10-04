/**
 * Rookery PDS enrollment script.
 * Generates RSA-4096 keypair, enrolls on pds.latha.org, persists credentials.
 *
 * Usage: bun run scripts/freeq-enroll.ts [handle]
 *   handle defaults to "coder"
 */

import crypto from "node:crypto";
import { writeFileSync } from "node:fs";

const PDS_HOST = "pds.latha.org";
const PDS_ORIGIN = `https://${PDS_HOST}`;
const CREDS_PATH = "scripts/rookery-creds.json";

// ── Helpers ──

function base64url(input: Buffer | Uint8Array): string {
  return Buffer.from(input).toString("base64url");
}

function base64urlDecode(str: string): Buffer {
  return Buffer.from(str, "base64url");
}

function pemToJwk(pem: string) {
  const key = crypto.createPublicKey(pem);
  const jwk = key.export({ format: "jwk" });
  return { kty: jwk.kty as string, n: jwk.n as string, e: jwk.e as string };
}

function computeThumbprint(jwk: { kty: string; n: string; e: string }): string {
  return base64url(
    crypto.createHash("sha256")
      .update(JSON.stringify({ e: jwk.e, kty: "RSA", n: jwk.n }))
      .digest(),
  );
}

function createJwt(header: object, payload: object, privateKeyPem: string): string {
  const enc = (obj: object) => base64url(Buffer.from(JSON.stringify(obj)));
  const signingInput = `${enc(header)}.${enc(payload)}`;
  const sig = crypto.createSign("SHA256");
  sig.update(signingInput);
  return `${signingInput}.${base64url(sig.sign(privateKeyPem))}`;
}

// ── Main ──

async function main() {
  const handle = process.argv[2] || "coder";
  console.log(`Enrolling as ${handle} on ${PDS_ORIGIN}...`);

  // Step 1: Generate RSA-4096 keypair
  const keys = crypto.generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });

  const pubJwk = pemToJwk(keys.publicKey);
  const thumbprint = computeThumbprint(pubJwk);
  console.log(`JWK thumbprint: ${thumbprint}`);

  // Step 2: Fetch ToS
  const tosRes = await fetch(`${PDS_ORIGIN}/tos`);
  if (!tosRes.ok) {
    console.error(`Failed to fetch ToS: ${tosRes.status}`);
    process.exit(1);
  }
  const tosText = await tosRes.text();
  const tosHash = base64url(crypto.createHash("sha256").update(tosText).digest());

  // Step 3: Build wm+jwt access token
  const accessToken = createJwt(
    { typ: "wm+jwt", alg: "RS256" },
    {
      tos_hash: tosHash,
      aud: PDS_ORIGIN,
      cnf: { jkt: thumbprint },
      iat: Math.floor(Date.now() / 1000),
    },
    keys.privateKey,
  );

  // Step 4: Sign ToS
  const tosSignature = base64url(
    crypto.sign("sha256", Buffer.from(tosText), keys.privateKey),
  );

  // Step 5: Build enrollment DPoP proof (no ath for signup)
  const signupUrl = `${PDS_ORIGIN}/api/signup`;
  const signupDpop = createJwt(
    { typ: "dpop+jwt", alg: "RS256", jwk: pubJwk },
    {
      jti: crypto.randomUUID(),
      htm: "POST",
      htu: signupUrl,
      iat: Math.floor(Date.now() / 1000),
    },
    keys.privateKey,
  );

  // Step 6: Enroll
  const signupRes = await fetch(signupUrl, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      DPoP: signupDpop,
    },
    body: JSON.stringify({
      handle,
      tos_signature: tosSignature,
      access_token: accessToken,
    }),
  });

  if (!signupRes.ok) {
    const body = await signupRes.text();
    console.error(`Signup failed (${signupRes.status}): ${body}`);
    process.exit(1);
  }

  const { did, handle: fullHandle, access_token, token_type } = await signupRes.json() as {
    did: string;
    handle: string;
    access_token: string;
    token_type: string;
  };

  console.log(`Enrolled!`);
  console.log(`  DID:    ${did}`);
  console.log(`  Handle: ${fullHandle}`);

  // Step 7: Persist credentials
  const creds = {
    did,
    handle: fullHandle,
    access_token,
    token_type,
    private_key_pem: keys.privateKey,
    public_key_pem: keys.publicKey,
    public_jwk: pubJwk,
    thumbprint,
    pds_host: PDS_HOST,
    pds_origin: PDS_ORIGIN,
    enrolled_at: new Date().toISOString(),
  };

  writeFileSync(CREDS_PATH, JSON.stringify(creds, null, 2));
  console.log(`Credentials saved to ${CREDS_PATH}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
