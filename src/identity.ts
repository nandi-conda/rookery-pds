import { sha256, type Keypair } from "@atproto/crypto";
import { encode } from "@atcute/cbor";
import { toString } from "uint8arrays/to-string";

export type GenesisOperation = {
  type: "plc_operation";
  rotationKeys: string[];
  verificationMethods: { atproto: string };
  alsoKnownAs: [string];
  services: {
    atproto_pds: {
      type: "AtprotoPersonalDataServer";
      endpoint: string;
    };
  };
  prev: null;
};

export type SignedGenesisOperation = GenesisOperation & { sig: string };

export function buildUnsignedGenesisOp(
  handle: string,
  hostname: string,
  signingKeypair: Keypair,
  rotationKeypair: Keypair,
): GenesisOperation {
  return {
    type: "plc_operation",
    rotationKeys: [rotationKeypair.did()],
    verificationMethods: { atproto: signingKeypair.did() },
    alsoKnownAs: [`at://${handle}`],
    services: {
      atproto_pds: {
        type: "AtprotoPersonalDataServer",
        endpoint: `https://${hostname}`,
      },
    },
    prev: null,
  };
}

export async function signGenesisOp(
  unsignedOp: GenesisOperation,
  rotationKeypair: Keypair,
): Promise<{ signedOp: SignedGenesisOperation; did: string }> {
  const cborBytes = encode(unsignedOp);
  const sigBytes = await rotationKeypair.sign(cborBytes);
  const sig = toString(sigBytes, "base64url");
  const signedOp = { ...unsignedOp, sig };
  const signedCbor = encode(signedOp);
  const hash = await sha256(signedCbor);
  const did = `did:plc:${toString(hash, "base32").slice(0, 24)}`;

  return { signedOp, did };
}

export async function createPlcDid(
  handle: string,
  hostname: string,
  signingKeypair: Keypair,
  rotationKeypair: Keypair,
  plcUrl: string,
): Promise<string> {
  const unsignedOp = buildUnsignedGenesisOp(
    handle,
    hostname,
    signingKeypair,
    rotationKeypair,
  );
  const { signedOp, did } = await signGenesisOp(unsignedOp, rotationKeypair);
  const res = await fetch(`${plcUrl}/${did}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(signedOp),
  });

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`PLC directory rejected operation (${res.status}): ${body}`);
  }

  return did;
}

export interface CreateDidPlcOpts {
  signingKey: Keypair;
  rotationKey: Keypair;
  handle: string;
  pdsEndpoint: string;
  plcUrl: string;
}

export async function createDidPlc(opts: CreateDidPlcOpts): Promise<string> {
  const hostname = opts.pdsEndpoint.replace(/^https?:\/\//, "");
  return createPlcDid(opts.handle, hostname, opts.signingKey, opts.rotationKey, opts.plcUrl);
}

type PlcOperation = Omit<GenesisOperation, "prev"> & { prev: string | null; sig?: string };

/**
 * Move a did:plc identity to a new handle: fetch the latest operation from the
 * PLC directory, replace alsoKnownAs, and submit an update signed by the
 * account's rotation key (held by the Account DO, reached through `sign`).
 */
export async function updatePlcHandle(
  did: string,
  handle: string,
  signWithRotationKey: (bytes: Uint8Array) => Promise<{ keyDid: string; sig: Uint8Array }>,
  plcUrl: string,
): Promise<void> {
  const logRes = await fetch(`${plcUrl}/${did}/log/audit`);
  if (!logRes.ok) {
    throw new Error(`PLC directory audit log fetch failed (${logRes.status})`);
  }
  const log = await logRes.json<Array<{ cid: string; nullified: boolean; operation: PlcOperation }>>();
  const last = log.filter((entry) => !entry.nullified).at(-1);
  if (!last || last.operation.type !== "plc_operation") {
    throw new Error("PLC directory has no current plc_operation for this DID");
  }
  const { sig: _sig, ...prevOp } = last.operation;
  const unsignedOp: PlcOperation = { ...prevOp, alsoKnownAs: [`at://${handle}`], prev: last.cid };
  const { keyDid, sig } = await signWithRotationKey(encode(unsignedOp));
  if (!last.operation.rotationKeys.includes(keyDid)) {
    throw new Error("Account rotation key is not a rotation key for this DID");
  }
  const signedOp = { ...unsignedOp, sig: toString(sig, "base64url") };

  const res = await fetch(`${plcUrl}/${did}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(signedOp),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`PLC directory rejected operation (${res.status}): ${body}`);
  }
}
