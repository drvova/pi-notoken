/**
 * NoTokenLimit Provider for Pi
 *
 * Login via browser session cookies → Python transport for all upstream HTTP.
 * Models fetched dynamically from upstream.
 *
 * Usage: /login notoken (will ask for cookies)
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { OAuthCredentials, OAuthLoginCallbacks } from "@earendil-works/pi-ai";
import { startProxy, stopProxy, PROXY_SECRET, setProxyCredentials } from "./proxy";
import { loadCredentials, saveCredentials, deleteCredentials, loginWithCookies } from "./oauth";
import { initIdentity, loadReleaseProof, type IdentityConfig, type ReleaseProof } from "./auth";
import { type ClientKeyPair } from "./wire";
import { chatSSE, fetchModels, stopTransport } from "./transport";

let _pi: ExtensionAPI | null = null;

/** Build Pi model definition from transport model. */
function modelToPi(m: { id: string; name?: string; provider?: string; tier?: string; desc?: string; locked?: boolean; context_window?: number; max_output_tokens?: number; disabled?: boolean }) {
  const ctx = m.context_window ?? 0;
  const maxOut = m.max_output_tokens ?? 0;
  const ctxStr = ctx > 0 ? ` (${ctx >= 1_000_000 ? `${Math.round(ctx / 1_000_000)}M` : `${Math.round(ctx / 1_000)}K`})` : "";
  return {
    id: m.id,
    name: `${m.name || m.id}${ctxStr}`,
    reasoning: true,
    input: ["text", "image"] as ("text" | "image")[],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: ctx || 1,
    maxTokens: maxOut || 1,
  };
}

function initIdentityForProxy(): { keyPair: ClientKeyPair; identity: IdentityConfig; releaseProof: ReleaseProof } | null {
  try {
    const identity: IdentityConfig = {
      client_kind: "official-vscode",
      version: "1.4.20",
      user_agent_product: "notokenlimit-vscode",
      request_payload_prefix: "notokenlimit-vscode-request-v1",
      machine_id: "",
      installation_id: "",
      private_key_pem: "",
      public_key_der_b64url: "",
      release_proof_path: "./release-proof.json",
    };
    const keyPair = initIdentity(identity);
    const releaseProof = loadReleaseProof(identity.release_proof_path);
    return { keyPair, identity, releaseProof };
  } catch (e) {
    console.error(`[notoken] identity init failed: ${e instanceof Error ? e.message : String(e)}`);
    return null;
  }
}

// OAuth login via cookies
async function loginNotoken(callbacks: OAuthLoginCallbacks): Promise<OAuthCredentials> {
  const baseUrl = "https://notokenlimit.com";
  const identityResult = initIdentityForProxy();
  if (!identityResult) throw new Error("Failed to initialize identity.");

  // Ask user for cookies via notify
  callbacks.onAuth({ url: "https://notokenlimit.com" });

  // We need cookies — try to load from a file or env
  const sessionCookie = process.env.NOTOKEN_SESSION_COOKIE || "";
  const csrfCookie = process.env.NOTOKEN_CSRF_COOKIE || "";

  if (!sessionCookie) {
    throw new Error(
      "NoTokenLimit login requires browser session cookies.\n" +
      "1. Open https://notokenlimit.com in your browser\n" +
      "2. Open DevTools → Application → Cookies\n" +
      "3. Copy __Host-claude_session and claude_csrf values\n" +
      "4. Set NOTOKEN_SESSION_COOKIE and NOTOKEN_CSRF_COOKIE env vars\n" +
      "   Then restart Pi and run /login notoken again."
    );
  }

  const { accessToken, refreshToken, userName, plan } = await loginWithCookies(
    sessionCookie, csrfCookie, identityResult.keyPair, identityResult.identity as any,
  );

  const fullCreds: OAuthCredentials = {
    accessToken,
    refreshToken,
    baseUrl,
    issuedAt: new Date().toISOString(),
    keyPair: { privatePem: identityResult.keyPair.privatePem, publicDerB64url: identityResult.keyPair.publicDerB64url },
    identity: {
      client_kind: identityResult.identity.client_kind,
      version: identityResult.identity.version,
      user_agent_product: identityResult.identity.user_agent_product,
      request_payload_prefix: identityResult.identity.request_payload_prefix,
      machine_id: identityResult.identity.machine_id,
      installation_id: identityResult.identity.installation_id,
    },
  };

  saveCredentials(fullCreds);
  setProxyCredentials({
    accessToken, refreshToken, baseUrl,
    keyPair: identityResult.keyPair,
    identity: identityResult.identity,
    releaseProof: identityResult.releaseProof,
  });

  return { refresh: accessToken, access: accessToken, expires: Date.now() + 365 * 24 * 60 * 60 * 1000 };
}

async function refreshNotokenToken(c: OAuthCredentials): Promise<OAuthCredentials> { return c; }

// Extension entry
export default async function (pi: ExtensionAPI) {
  _pi = pi;
  const proxyPort = await startProxy();
  const baseUrl = `http://127.0.0.1:${proxyPort}/v1`;

  let hasCreds = false;
  let accessToken = "";
  let keyPair: ClientKeyPair | null = null;
  let identity: IdentityConfig | null = null;
  let releaseProof: ReleaseProof | null = null;

  try {
    const stored = loadCredentials();
    if (stored) {
      keyPair = { privatePem: stored.keyPair.privatePem, publicDerB64url: stored.keyPair.publicDerB64url };
      identity = {
        ...stored.identity,
        private_key_pem: stored.keyPair.privatePem,
        public_key_der_b64url: stored.keyPair.publicDerB64url,
        release_proof_path: "./release-proof.json",
      };
      try { releaseProof = loadReleaseProof(identity.release_proof_path); } catch { releaseProof = null; }
      if (releaseProof) {
        setProxyCredentials({
          accessToken: stored.accessToken,
          refreshToken: stored.refreshToken,
          baseUrl: stored.baseUrl,
          keyPair, identity, releaseProof,
        });
        hasCreds = true;
        accessToken = stored.accessToken;
      }
    }
  } catch { /* no creds */ }

  // Fetch models via transport
  let models: ReturnType<typeof modelToPi>[] = [];
  if (hasCreds && accessToken) {
    try {
      const upstream = await fetchModels(accessToken);
      models = upstream.filter((m) => !m.disabled).map(modelToPi);
      console.error(`[notoken] loaded ${models.length} models`);
    } catch (e) {
      console.error(`[notoken] model fetch failed: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  pi.registerProvider("notoken", {
    name: "NoTokenLimit",
    baseUrl,
    apiKey: PROXY_SECRET,
    api: "openai-completions",
    authHeader: true,
    models,
    oauth: {
      name: "NoTokenLimit",
      login: loginNotoken,
      refreshToken: refreshNotokenToken,
      getApiKey: (creds: OAuthCredentials) => creds.access,
    },
  });

  console.error(hasCreds ? `[notoken] connected -- ${models.length} models` : `[notoken] /login notoken to connect`);

  pi.registerCommand("notoken-status", {
    description: "Show NoTokenLimit auth status",
    handler: async (_args, ctx) => {
      const c = loadCredentials();
      if (!c) { ctx.ui.notify("NoTokenLimit: not signed in. /login notoken", "warning"); return; }
      ctx.ui.notify(`NoTokenLimit: authenticated (${c.baseUrl}) -- token issued ${c.issuedAt}`, "info");
    },
  });

  pi.registerCommand("notoken-logout", {
    description: "Sign out of NoTokenLimit",
    handler: async (_args, ctx) => {
      deleteCredentials();
      setProxyCredentials(null);
      stopTransport();
      ctx.ui.notify("NoTokenLimit: signed out.", "info");
    },
  });

  pi.registerCommand("notoken-refresh", {
    description: "Refresh NoTokenLimit model catalog",
    handler: async (_args, ctx) => {
      const c = loadCredentials();
      if (!c) { ctx.ui.notify("NoTokenLimit: not signed in.", "warning"); return; }
      try {
        const upstream = await fetchModels(c.accessToken);
        ctx.ui.notify(`NoTokenLimit: refreshed ${upstream.length} models. Restart Pi to apply.`, "info");
      } catch (e) {
        ctx.ui.notify(`NoTokenLimit: refresh error - ${e instanceof Error ? e.message : String(e)}`, "error");
      }
    },
  });

  pi.on("session_shutdown", async () => {
    _pi = null;
    stopTransport();
    stopProxy();
  });
}
