/**
 * Crypto helpers + SSE line parser.
 * Zero external dependencies — Node.js crypto + Buffer math only.
 */
import * as crypto from "crypto";

// ----------------------------------------------------------------------------
// Constants (shared with official VS Code extension)
// ----------------------------------------------------------------------------

const OBF_STATIC_ENTROPY_1 = "7b29a8f4c1e05d36";
const OBF_STATIC_ENTROPY_2 = "9f8e7d6c5b4a3921";
const OBF_SALT = "notokenlimit-super-secret-salt-v1";
const MACHINE_HASH_SALT = "notokenlimit-machine-v2";

// ----------------------------------------------------------------------------
// Base64url
// ----------------------------------------------------------------------------

export function b64urlEncode(buf: Buffer): string {
  return buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s: string): Buffer {
  const padded = s + "=".repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(padded, "base64");
}

// ----------------------------------------------------------------------------
// Hashing
// ----------------------------------------------------------------------------

export function sha256Hex(text: string): string {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

export function randomHex(nBytes: number): string {
  return crypto.randomBytes(nBytes).toString("hex");
}

export function machineHash(machineId: string): string {
  return sha256Hex(`${MACHINE_HASH_SALT}|${machineId}`);
}

// ----------------------------------------------------------------------------
// Obfuscation secret
// ----------------------------------------------------------------------------

export function getClientSecret(version: string, timestamp: string, nonce: string): string {
  const raw = [OBF_STATIC_ENTROPY_1, version, OBF_SALT, timestamp, OBF_STATIC_ENTROPY_2, nonce].join("|||");
  let h = raw;
  for (let i = 0; i < 3; i++) h = sha256Hex(h);
  return `ntl_sec_${h.slice(0, 32)}`;
}

// ----------------------------------------------------------------------------
// Ed25519 key pair
// ----------------------------------------------------------------------------

export interface ClientKeyPair {
  privatePem: string;
  publicDerB64url: string;
}

export function generateKeyPair(): ClientKeyPair {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const publicDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  return { privatePem, publicDerB64url: b64urlEncode(publicDer) };
}

export function signPayload(privatePem: string, payload: string): string {
  const key = crypto.createPrivateKey(privatePem);
  const sig = crypto.sign(null, Buffer.from(payload, "utf8"), key);
  return b64urlEncode(sig);
}

export function publicKeyFingerprint(publicDerB64url: string): string {
  return sha256Hex(b64urlDecode(publicDerB64url).toString("utf8"));
}

// ----------------------------------------------------------------------------
// SSE line parser
// ----------------------------------------------------------------------------

export interface ParsedSSEEvent {
  data: string;
  event?: string;
}

/** Parse a single SSE line. Returns the event when a blank line terminates a block. */
export function parseSSELine(
  line: string,
  buffer: string[],
): ParsedSSEEvent | null {
  if (line === "") {
    if (buffer.length === 0) return null;
    const data = buffer.join("\n");
    buffer.length = 0;
    return { data };
  }
  if (line.startsWith("data: ")) {
    buffer.push(line.slice(6));
  } else if (line.startsWith("data:")) {
    buffer.push(line.slice(5));
  } else if (line.startsWith("event: ")) {
    // event type — ignored for NoTokenLimit
  } else if (line.startsWith(":")) {
    // comment — skip
  }
  return null;
}
