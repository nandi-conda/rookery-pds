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
