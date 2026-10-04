import {
  encode as atcuteEncode,
  decode as atcuteDecode,
  toCIDLink,
  toBytes,
  fromBytes,
  type Bytes,
  type CIDLink,
} from "@atcute/cbor";
import { parse } from "@atcute/cid";
import type { CID } from "@atproto/lex-data";

function isAtprotoCid(value: unknown): value is CID {
  if (value === null || typeof value !== "object") {
    return false;
  }
  const obj = value as Record<string | symbol, unknown>;
  return "asCID" in obj && obj[Symbol.toStringTag] === "CID";
}

function isBytes(value: unknown): value is Bytes {
  return value !== null && typeof value === "object" && "$bytes" in value;
}

function atprotoCidToCidLink(cid: CID): CIDLink {
  return toCIDLink(parse(cid.toString()));
}

function convertCidsForEncode(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value !== "object") {
    return value;
  }
  if (ArrayBuffer.isView(value) && value instanceof Uint8Array) {
    return toBytes(value);
  }
  if (isAtprotoCid(value)) {
    return atprotoCidToCidLink(value);
  }
  if (Array.isArray(value)) {
    return (value as unknown[]).map(convertCidsForEncode);
  }
  const obj = value as object;
  if (obj.constructor === Object) {
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(obj)) {
      result[key] = convertCidsForEncode(val);
    }
    return result;
  }
  return value;
}

export function encode(value: unknown): Uint8Array {
  const converted = convertCidsForEncode(value);
  return atcuteEncode(converted);
}

function convertWrappersForDecode(value: unknown): unknown {
  if (value === null || value === undefined) {
    return value;
  }
  if (typeof value !== "object") {
    return value;
  }
  if (isBytes(value)) {
    return fromBytes(value);
  }
  if (Array.isArray(value)) {
    return (value as unknown[]).map(convertWrappersForDecode);
  }
  const obj = value as object;
  if (obj.constructor === Object) {
    const result: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(obj)) {
      result[key] = convertWrappersForDecode(val);
    }
    return result;
  }
  return value;
}

export function decode(bytes: Uint8Array): unknown {
  const decoded = atcuteDecode(bytes);
  return convertWrappersForDecode(decoded);
}
