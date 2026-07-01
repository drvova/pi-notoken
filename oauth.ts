/**
 * Device-code OAuth flow for NoTokenLimit.
 * Same flow as the official VS Code extension.
 */
import * as fs from "fs";
import * as path from "path";
import * as os from "os";
import { spawn } from "child_process";
import { buildRequestHeaders } from "./metadata";
import { type ClientKeyPair, randomHex } from "./wire";

// ----------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------

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

export interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  verification_uri_complete: string;
  expires_in: number;
  interval: number;
}

// ----------------------------------------------------------------------------
// Credential storage
// ----------------------------------------------------------------------------

const APP_DIR = path.join(os.homedir(), ".config", "pi-notoken");
const CREDS_FILE = "credentials.json";

function ensureDir(): void {
  fs.mkdirSync(APP_DIR, { recursive: true, mode: 0o700 });
}

export function loadCredentials(): OAuthCredentials | null {
  const p = path.join(APP_DIR, CREDS_FILE);
  if (!fs.existsSync(p)) return null;
  const raw = fs.readFileSync(p, "utf8");
  const parsed = JSON.parse(raw) as Record<string, unknown>;
  if (typeof parsed.accessToken !== "string" || !parsed.accessToken) return null;
  if (typeof parsed.baseUrl !== "string" || !parsed.baseUrl) return null;
  return parsed as unknown as OAuthCredentials;
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

// ----------------------------------------------------------------------------
// Device code flow
// ----------------------------------------------------------------------------

export async function startDeviceCode(
  baseUrl: string,
  keyPair: ClientKeyPair,
  identity: { client_kind: string; version: string; user_agent_product: string; request_payload_prefix: string; installation_id: string; machine_id: string },
  releaseProof: { release_id: string; signature: string; [key: string]: unknown },
): Promise<DeviceCodeResponse> {
  const apiPath = "/api/auth/extension/device-code";
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
    body: "{}",
  });

  const data = await resp.json() as Record<string, unknown>;
  if (resp.status !== 200) {
    throw new Error(`Device code failed: ${JSON.stringify(data)}`);
  }

  return {
    device_code: data.device_code as string,
    user_code: data.user_code as string,
    verification_uri: data.verification_uri as string,
    verification_uri_complete: (data.verification_uri_complete as string) || "",
    expires_in: (data.expires_in as number) || 600,
    interval: (data.interval as number) || 5,
  };
}

export async function pollDeviceCode(
  baseUrl: string,
  deviceCode: string,
  deviceName: string,
  keyPair: ClientKeyPair,
  identity: { client_kind: string; version: string; user_agent_product: string; request_payload_prefix: string; installation_id: string; machine_id: string },
  releaseProof: { release_id: string; signature: string; [key: string]: unknown },
): Promise<{ status: number; data: Record<string, unknown> }> {
  const apiPath = "/api/auth/extension/poll";
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
    body: JSON.stringify({ device_code: deviceCode, device_name: deviceName }),
  });

  const data = await resp.json() as Record<string, unknown>;
  return { status: resp.status, data };
}

// ----------------------------------------------------------------------------
// Full flow with loopback callback
// ----------------------------------------------------------------------------

export async function runLoginLoopback(
  baseUrl: string,
  keyPair: ClientKeyPair,
  identity: { client_kind: string; version: string; user_agent_product: string; request_payload_prefix: string; installation_id: string; machine_id: string },
  releaseProof: { release_id: string; signature: string; [key: string]: unknown },
  onUrl: (url: string) => void,
  signal?: AbortSignal,
): Promise<OAuthCredentials> {
  const init = await startDeviceCode(baseUrl, keyPair, identity, releaseProof);
  const url = init.verification_uri_complete || init.verification_uri;
  onUrl(url);

  await openBrowser(url).catch(() => {});

  const expiresAt = Date.now() + init.expires_in * 1000;
  const intervalMs = Math.max(2000, init.interval * 1000);

  while (Date.now() < expiresAt) {
    await sleep(intervalMs);
    if (signal?.aborted) throw new Error("Sign-in cancelled.");

    try {
      const result = await pollDeviceCode(baseUrl, init.device_code, `pi-${randomHex(4)}`, keyPair, identity, releaseProof);
      const data = result.data;

      if (result.status === 200 && data.access_token) {
        const creds: OAuthCredentials = {
          accessToken: data.access_token as string,
          refreshToken: (data.refresh_token as string) || "",
          baseUrl,
          issuedAt: new Date().toISOString(),
          keyPair: { privatePem: keyPair.privatePem, publicDerB64url: keyPair.publicDerB64url },
          identity: {
            client_kind: identity.client_kind,
            version: identity.version,
            user_agent_product: identity.user_agent_product,
            request_payload_prefix: identity.request_payload_prefix,
            machine_id: identity.machine_id,
            installation_id: identity.installation_id,
          },
        };
        saveCredentials(creds);
        return creds;
      }

      const code = data.code as string | undefined;
      if (code === "PENDING") continue;
      if (code === "SLOW_DOWN") { await sleep(intervalMs); continue; }
      if (code === "SESSION_LIMIT") throw new Error("Active session on another device. Revoke it first.");

      const errorMsg = (data.error as string) || "Authorization failed.";
      throw new Error(errorMsg);
    } catch (e) {
      if (e instanceof Error && e.message.includes("cancelled")) throw e;
      if (e instanceof Error && e.message.includes("Authorization")) throw e;
      // retry on network errors
    }
  }

  throw new Error("Authorization code expired. Please try again.");
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function openBrowser(url: string): Promise<void> {
  const cmds =
    process.platform === "darwin"
      ? [{ cmd: "open", args: [url] }]
      : process.platform === "win32"
        ? [{ cmd: "cmd", args: ["/c", "start", '""', url] }]
        : [{ cmd: "xdg-open", args: [url] }, { cmd: "sensible-browser", args: [url] }];

  for (const c of cmds) {
    const ok = await new Promise<boolean>((resolve) => {
      const child = spawn(c.cmd, c.args, { stdio: "ignore", detached: true });
      child.on("error", () => resolve(false));
      child.on("spawn", () => { child.unref(); resolve(true); });
    });
    if (ok) return;
  }
  throw new Error(`Unable to open browser. Open this URL manually:\n  ${url}`);
}
