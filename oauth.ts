/**
 * oauth.ts — Login flow using browser session cookies.
 * All HTTP routed through Python transport (TLS compatibility).
 */
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { login as transportLogin } from "./transport";
import { type ClientKeyPair } from "./wire";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface OAuthCredentials {
  accessToken: string;
  refreshToken: string;
  baseUrl: string;
  issuedAt: string;
  keyPair: {
    privatePem: string;
    publicDerB64url: string;
  };
  identity: {
    client_kind: string;
    version: string;
    user_agent_product: string;
    request_payload_prefix: string;
    machine_id: string;
    installation_id: string;
  };
}

// ---------------------------------------------------------------------------
// Credential storage
// ---------------------------------------------------------------------------

const APP_DIR = path.join(os.homedir(), ".config", "pi-notoken");
const CREDS_FILE = "credentials.json";

function ensureDir(): void {
  fs.mkdirSync(APP_DIR, { recursive: true, mode: 0o700 });
}

export function loadCredentials(): OAuthCredentials | null {
  const p = path.join(APP_DIR, CREDS_FILE);
  if (!fs.existsSync(p)) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(p, "utf8"));
    if (typeof parsed.accessToken !== "string" || !parsed.accessToken) return null;
    return parsed;
  } catch { return null; }
}

export function saveCredentials(creds: OAuthCredentials): void {
  ensureDir();
  fs.writeFileSync(path.join(APP_DIR, CREDS_FILE), JSON.stringify(creds, null, 2), { mode: 0o600 });
}

export function deleteCredentials(): boolean {
  const p = path.join(APP_DIR, CREDS_FILE);
  if (!fs.existsSync(p)) return false;
  fs.unlinkSync(p);
  return true;
}

// ---------------------------------------------------------------------------
// Login with browser session cookies
// ---------------------------------------------------------------------------

export async function loginWithCookies(
  sessionCookie: string,
  csrfCookie: string,
  keyPair: ClientKeyPair,
  identity: Record<string, string>,
): Promise<{ accessToken: string; refreshToken: string; userName?: string; plan?: string }> {
  const result = await transportLogin(sessionCookie, csrfCookie);
  return {
    accessToken: result.accessToken,
    refreshToken: result.refreshToken,
    userName: result.userName,
    plan: result.plan,
  };
}
