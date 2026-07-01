/**
 * auth.ts — Token management + Ed25519 identity for NoTokenLimit.
 * HTTP calls routed through transport.py (Python httpx) for TLS compatibility.
 */
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import * as crypto from "node:crypto";
import { type ClientKeyPair } from "./wire";
import { refreshTokens } from "./transport";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface IdentityConfig {
  client_kind: string;
  version: string;
  user_agent_product: string;
  request_payload_prefix: string;
  machine_id: string;
  installation_id: string;
  private_key_pem: string;
  public_key_der_b64url: string;
  release_proof_path: string;
}

export interface ReleaseProof {
  release_id: string;
  signature: string;
  [key: string]: unknown;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

// ---------------------------------------------------------------------------
// Token refresh
// ---------------------------------------------------------------------------

const _refreshLocks = new Map<string, boolean>();

const _BAD_TOKEN_CODES = new Set(["EXPIRED", "NO_TOKEN", "BAD_TOKEN", "REVOKED"]);

export function isTokenError(statusCode: number, body: string): boolean {
  if (statusCode !== 401) return false;
  try {
    const obj = JSON.parse(body);
    const code = (obj.code ?? obj.error_code ?? "").toUpperCase();
    return _BAD_TOKEN_CODES.has(code);
  } catch { return false; }
}

export function isSSETokenError(event: { error_code?: string }): boolean {
  const code = (event.error_code ?? "").toUpperCase();
  return _BAD_TOKEN_CODES.has(code);
}

export async function refreshToken(
  baseUrl: string,
  refreshToken: string,
  keyPair: ClientKeyPair,
  identity: IdentityConfig,
  releaseProof: ReleaseProof,
): Promise<TokenPair | null> {
  const accountName = "main";
  if (_refreshLocks.get(accountName)) return null;
  _refreshLocks.set(accountName, true);
  try {
    const result = await refreshTokens(refreshToken);
    return { accessToken: result.accessToken, refreshToken: result.refreshToken };
  } catch {
    return null;
  } finally {
    _refreshLocks.set(accountName, false);
  }
}

// ---------------------------------------------------------------------------
// Identity management
// ---------------------------------------------------------------------------

const IDENTITY_FILE = "identity.json";

function getIdentityPath(): string {
  return path.join(os.homedir(), ".config", "pi-notoken", IDENTITY_FILE);
}

function ensureDir(): void {
  fs.mkdirSync(path.dirname(getIdentityPath()), { recursive: true, mode: 0o700 });
}

export function initIdentity(config: IdentityConfig): ClientKeyPair {
  const existing = loadIdentityConfig();
  if (existing && existing.private_key_pem && existing.public_key_der_b64url) {
    config.private_key_pem = existing.private_key_pem;
    config.public_key_der_b64url = existing.public_key_der_b64url;
    config.machine_id = existing.machine_id || config.machine_id;
    config.installation_id = existing.installation_id || config.installation_id;
    return { privatePem: existing.private_key_pem, publicDerB64url: existing.public_key_der_b64url };
  }

  const kp = crypto.generateKeyPairSync("ed25519");
  const priv = kp.privateKey.export({ type: "pkcs8", format: "pem" }) as string;
  const pubDer = kp.publicKey.export({ type: "spki", format: "der" });
  const pubB64url = pubDer.toString("base64url");

  if (!config.machine_id) config.machine_id = crypto.randomUUID();
  if (!config.installation_id) config.installation_id = `inst_${crypto.randomBytes(16).toString("hex")}`;

  config.private_key_pem = priv;
  config.public_key_der_b64url = pubB64url;

  saveIdentityConfig(config);
  return { privatePem: priv, publicDerB64url: pubB64url };
}

export function loadIdentityConfig(): IdentityConfig | null {
  const p = getIdentityPath();
  if (!fs.existsSync(p)) return null;
  try { return JSON.parse(fs.readFileSync(p, "utf8")); }
  catch { return null; }
}

export function saveIdentityConfig(config: IdentityConfig): void {
  ensureDir();
  fs.writeFileSync(getIdentityPath(), JSON.stringify(config, null, 2), { mode: 0o600 });
}

export function loadReleaseProof(releaseProofPath: string): ReleaseProof {
  const candidates = [releaseProofPath, path.join(__dirname, releaseProofPath), path.join(__dirname, "..", releaseProofPath)];
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      const raw = fs.readFileSync(p, "utf8");
      const clean = raw.charCodeAt(0) === 0xFEFF ? raw.slice(1) : raw;
      return JSON.parse(clean);
    }
  }
  throw new Error(`release-proof.json not found (searched: ${candidates.join(", ")})`);
}
