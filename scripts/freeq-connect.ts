/**
 * Freeq IRC client with crypto SASL auth via Rookery PDS.
 *
 * Connects to irc.freeq.at, handles ATPROTO-CHALLENGE by calling
 * the PDS's /api/freeq/sign-challenge endpoint, then authenticates
 * with method: "crypto".
 *
 * Usage: bun run scripts/freeq-connect.ts
 */

import crypto from "node:crypto";
import { readFileSync } from "node:fs";
import { WebSocket } from "ws";

const FREEQ_URL = "wss://irc.freeq.at/irc";
const CREDS_PATH = "scripts/rookery-creds.json";

// ── Helpers ──

function base64url(input: Buffer | Uint8Array): string {
  return Buffer.from(input).toString("base64url");
}

function base64urlDecode(str: string): Buffer {
  return Buffer.from(str, "base64url");
}

function createJwt(header: object, payload: object, privateKeyPem: string): string {
  const enc = (obj: object) => base64url(Buffer.from(JSON.stringify(obj)));
  const signingInput = `${enc(header)}.${enc(payload)}`;
  const sig = crypto.createSign("SHA256");
  sig.update(signingInput);
  return `${signingInput}.${base64url(sig.sign(privateKeyPem))}`;
}

function createDpopProof(
  method: string,
  url: string,
  accessToken: string,
  pubJwk: { kty: string; n: string; e: string },
  privateKeyPem: string,
): string {
  const ath = base64url(crypto.createHash("sha256").update(accessToken).digest());
  return createJwt(
    { typ: "dpop+jwt", alg: "RS256", jwk: pubJwk },
    {
      jti: crypto.randomUUID(),
      htm: method,
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      ath,
    },
    privateKeyPem,
  );
}

// ── Load credentials ──

const creds = JSON.parse(readFileSync(CREDS_PATH, "utf-8")) as {
  did: string;
  handle: string;
  access_token: string;
  private_key_pem: string;
  public_jwk: { kty: string; n: string; e: string };
  thumbprint: string;
  pds_host: string;
  pds_origin: string;
};

console.log(`Loaded creds for ${creds.handle} (${creds.did})`);

// ── Create short session token ──

async function createSessionToken(): Promise<string> {
  const url = `${creds.pds_origin}/xrpc/com.atproto.server.createSession`;
  const dpop = createDpopProof(
    "POST",
    url,
    creds.access_token,
    creds.public_jwk,
    creds.private_key_pem,
  );

  const res = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `DPoP ${creds.access_token}`,
      DPoP: dpop,
    },
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`createSession failed (${res.status}): ${body}`);
  }

  const { accessJwt } = await res.json() as { did: string; handle: string; accessJwt: string };
  return accessJwt;
}

// ── PDS session token (created before connecting) ──

let sessionToken: string | null = null;

// ── PDS sign-challenge ──

function buildSaslResponse(challengeBase64url: string, sessionToken: string): string {
  // Decode challenge to extract nonce
  let challengeNonce: string | undefined;
  try {
    const challengeJson = Buffer.from(challengeBase64url, "base64url").toString("utf-8");
    const challenge = JSON.parse(challengeJson);
    challengeNonce = challenge.nonce;
  } catch { /* proceed without nonce */ }

  const response = {
    did: creds.did,
    method: "pds-session",
    signature: sessionToken,
    pds_url: creds.pds_origin,
    challenge_nonce: challengeNonce,
  };

  const encoded = Buffer.from(JSON.stringify(response)).toString("base64url");
  return encoded;
}

// ── IRC client ──

const nick = creds.handle.split(".")[0] || "coder";
let ws: WebSocket;
let saslDone = false;
let msgsigKey: { publicKey: string; privateKey: CryptoKey } | null = null;

// Generate Ed25519 keypair for MSGSIG
async function generateMsgsigKey() {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(
    { name: "Ed25519" },
    true,
    ["sign", "verify"],
  );
  const pubBytes = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey));
  // Freeq expects 32-byte base64url-encoded ed25519 public key (not did:key)
  const pubkeyB64url = Buffer.from(pubBytes).toString("base64url");
  msgsigKey = { publicKey: pubkeyB64url, privateKey };
  return pubkeyB64url;
}

function send(line: string) {
  console.log(`> ${line}`);
  ws.send(line + "\r\n");
}

function handleLine(line: string) {
  console.log(`< ${line}`);

  // Parse IRC message: [:prefix] command params...
  const parts = line.split(" ");
  const offset = parts[0].startsWith(":") ? 1 : 0;
  const command = parts[offset];

  // CAP LS response — ":server CAP * LS :caps..."
  if (command === "CAP" && parts[offset + 2] === "LS") {
    const available = parts.slice(offset + 3).join(" ").replace(/^:/, "");
    const wanted = [
      "message-tags", "server-time", "batch", "multi-prefix",
      "echo-message", "account-notify", "extended-join", "away-notify",
      "sasl",
    ].filter((c) => available.includes(c));
    send(`CAP REQ :${wanted.join(" ")}`);
    return;
  }

  // CAP ACK — ":server CAP nick ACK :caps..."
  if (command === "CAP" && parts[offset + 2] === "ACK") {
    const acked = parts.slice(offset + 3).join(" ").replace(/^:/, "");
    if (acked.includes("sasl")) {
      send("AUTHENTICATE ATPROTO-CHALLENGE");
    } else {
      send("CAP END");
    }
    return;
  }

  // AUTHENTICATE challenge from server
  if (command === "AUTHENTICATE") {
    const param = parts[offset + 1];
    if (!param || param === "+") return;

    console.log(`SASL challenge received, building pds-session response...`);
    if (!sessionToken) {
      console.error("No session token available");
      ws.close();
      return;
    }
    const responsePayload = buildSaslResponse(param, sessionToken);
    if (responsePayload.length <= 400) {
      send(`AUTHENTICATE ${responsePayload}`);
    } else {
      for (let i = 0; i < responsePayload.length; i += 400) {
        send(`AUTHENTICATE ${responsePayload.slice(i, i + 400)}`);
      }
      send("AUTHENTICATE +");
    }
    return;
  }

  // 900 — SASL authenticated
  if (command === "900") {
    console.log(`SASL authenticated as ${parts[parts.length - 1]}`);
    saslDone = true;
    return;
  }

  // 903 — SASL success
  if (command === "903") {
    console.log("SASL success, sending CAP END");
    generateMsgsigKey().then((pubkey) => {
      console.log(`MSGSIG pubkey: ${pubkey}`);
      send(`MSGSIG ${pubkey}`);
    });
    send("CAP END");
  }

  // 904 — SASL failed
  if (command === "904") {
    console.error(`SASL failed: ${parts.slice(offset + 1).join(" ")}`);
    ws.close();
    return;
  }

  // 001 — registered
  if (command === "001") {
    console.log(`Registered as ${parts[offset + 1]}`);
    send("POLICY #freeq ACCEPT");
    send("JOIN #freeq");
    return;
  }

  // PING
  if (command === "PING") {
    send(`PONG :${parts[offset + 1]}`);
    return;
  }

  // PRIVMSG
  if (command === "PRIVMSG") {
    const target = parts[offset + 1];
    const text = parts.slice(offset + 2).join(" ").replace(/^:/, "");
    const from = parts[0].replace(/^:/, "").split("!")[0];
    console.log(`<${from}> ${text}`);
    return;
  }
}

async function connect() {
  console.log(`Creating session token on ${creds.pds_origin}...`);
  sessionToken = await createSessionToken();
  console.log(`Session token: ${sessionToken}`);

  console.log(`Connecting to ${FREEQ_URL}...`);

  ws = new WebSocket(FREEQ_URL);

  ws.on("open", () => {
    console.log("WebSocket connected");
    // Send IRC registration
    send("CAP LS 302");
    send(`NICK ${nick}`);
    send(`USER ${nick} 0 * :freeq`);
  });

  ws.on("message", (data: Buffer) => {
    const lines = data.toString().split("\r\n").filter(Boolean);
    for (const line of lines) {
      handleLine(line);
    }
  });

  ws.on("close", (code, reason) => {
    console.log(`WebSocket closed: ${code} ${reason.toString()}`);
  });

  ws.on("error", (err) => {
    console.error(`WebSocket error: ${err.message}`);
  });
}

connect();
