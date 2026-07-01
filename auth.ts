/**
 * Ed25519 key management + token refresh for NoTokenLimit.
 *
 * Handles:
 *   - Loading/generating Ed25519 key pairs
 *   - Loading release-proof.json
 *   - Token refresh via /api/auth/extension/refresh
 *   - Per-account refresh locks
 */
import * as fs from "fs";
import { generateKeyPair, type ClientKeyPair } from "./wire";
import { buildRequestHeaders } from "./metadata";

// ----------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------

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
  alg: string;
  client: string;
  version: string;
  release_id: string;
  signature: string;
  issued_at: string;
  [key: string]: unknown;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

// ----------------------------------------------------------------------------
// Identity init
// ----------------------------------------------------------------------------

export function initIdentity(identity: IdentityConfig): ClientKeyPair {
  let keyPair: ClientKeyPair;
  let changed = false;

  if (identity.private_key_pem && identity.public_key_der_b64url) {
    keyPair = { privatePem: identity.private_key_pem, publicDerB64url: identity.public_key_der_b64url };
  } else {
    keyPair = generateKeyPair();
    identity.private_key_pem = keyPair.privatePem;
    identity.public_key_der_b64url = keyPair.publicDerB64url;
    changed = true;
  }

  if (!identity.installation_id) {
    identity.installation_id = `inst_${Date.now().toString(36)}${Math.random().toString(36).slice(2, 8)}`;
    changed = true;
  }
  if (!identity.machine_id) {
    identity.machine_id = crypto.randomUUID();
    changed = true;
  }

  return keyPair;
}

export function loadReleaseProof(releaseProofPath: string): ReleaseProof {
  const raw = fs.readFileSync(releaseProofPath, "utf8");
  const proof = JSON.parse(raw) as ReleaseProof;
  for (const field of ["alg", "client", "version", "release_id", "signature", "issued_at"]) {
    if (!(field in proof)) throw new Error(`release proof missing field: ${field}`);
  }
  return proof;
}

// ----------------------------------------------------------------------------
// Token refresh
// ----------------------------------------------------------------------------

const _BAD_TOKEN_CODES = new Set(["EXPIRED", "NO_TOKEN", "BAD_TOKEN", "REVOKED"]);
const _refreshLocks = new Map<string, boolean>();

export function isTokenError(statusCode: number, body: string): boolean {
  if (statusCode !== 401) return false;
  try {
    const obj = JSON.parse(body);
    const code = obj?.error?.code ?? obj?.code ?? "";
    return typeof code === "string" && _BAD_TOKEN_CODES.has(code);
  } catch {
    return false;
  }
}

export function isSSETokenError(event: { error_code?: string }): boolean {
  const code = event.error_code ?? "";
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
    const apiPath = "/api/auth/extension/refresh";
    const headers = buildRequestHeaders({
      method: "POST",
      path: apiPath,
      accessToken: "",
      privatePem: keyPair.privatePem,
      publicDerB64url: keyPair.publicDerB64url,
      installationId: identity.installation_id,
      machineId: identity.machine_id,
      version: identity.version,
      clientKind: identity.client_kind,
      userAgentProduct: identity.user_agent_product,
      requestPayloadPrefix: identity.request_payload_prefix,
      releaseProof,
      extra: { "Content-Type": "application/json" },
    });

    const resp = await fetch(`${baseUrl.replace(/\/$/, "")}${apiPath}`, {
      method: "POST",
      headers,
      body: JSON.stringify({ refresh_token: refreshToken }),
    });

    if (!resp.ok) return null;
    const data = await resp.json() as Record<string, unknown>;
    const newAccess = data.access_token as string | undefined;
    const newRefresh = data.refresh_token as string | undefined;
    if (!newAccess) return null;

    return {
      accessToken: newAccess,
      refreshToken: newRefresh || refreshToken,
    };
  } catch {
    return null;
  } finally {
    _refreshLocks.set(accountName, false);
  }
}

// ----------------------------------------------------------------------------
// In-memory credential cache
// ----------------------------------------------------------------------------

let _credentials: { accessToken: string; refreshToken: string; baseUrl: string } | null = null;

export function setProxyCredentials(creds: { accessToken: string; refreshToken: string; baseUrl: string } | null): void {
  _credentials = creds;
}

export function getProxyCredentials(): typeof _credentials {
  return _credentials;
}
