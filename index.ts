/**
 * NoTokenLimit Provider for Pi
 *
 * Enables NoTokenLimit models via local proxy.
 * Models are fetched dynamically from /api/copilot/models.
 *
 * Usage: /login notoken → /model notoken/<id>
 */
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { OAuthCredentials, OAuthLoginCallbacks } from "@earendil-works/pi-ai";
import { startProxy, stopProxy, PROXY_SECRET, setProxyCredentials } from "./proxy";
import { loadCredentials, saveCredentials, deleteCredentials, runDeviceCodeFlow } from "./oauth";
import { initIdentity, loadReleaseProof, type IdentityConfig, type ReleaseProof } from "./auth";
import { clearCachedCatalog, getCachedCatalog, type ModelCatalogEntry } from "./catalog";
import { type ClientKeyPair } from "./wire";

let _pi: ExtensionAPI | null = null;

/** Build a Pi model definition from a catalog entry. */
function catalogModelToPi(m: ModelCatalogEntry) {
  const ctx = m.contextWindow ?? 0;
  const maxOut = m.maxOutputTokens ?? 0;
  const ctxStr = ctx > 0 ? ` (${ctx >= 1_000_000 ? `${Math.round(ctx / 1_000_000)}M` : `${Math.round(ctx / 1_000)}K`})` : "";
  return {
    id: m.id,
    name: `${m.label}${ctxStr}`,
    reasoning: true,
    input: ["text", "image"] as ("text" | "image")[],
    cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
    contextWindow: ctx || 1,
    maxTokens: maxOut || 1,
  };
}

/** Fetch catalog and build dynamic model list. */
async function fetchDynamicModels(
  accessToken: string,
  baseUrl: string,
  keyPair: ClientKeyPair,
  identity: IdentityConfig,
  releaseProof: ReleaseProof,
): Promise<ReturnType<typeof catalogModelToPi>[]> {
  try {
    const catalog = await getCachedCatalog(baseUrl, accessToken, keyPair, identity, releaseProof);
    if (catalog && catalog.models.length > 0) {
      const models = catalog.models
        .filter((m) => !m.disabled)
        .map(catalogModelToPi);
      console.error(`[notoken] loaded ${models.length} models from catalog`);
      return models;
    }
  } catch (e) {
    console.error(`[notoken] catalog fetch failed: ${e instanceof Error ? e.message : String(e)}`);
  }
  return [];
}

/** Init or load identity + release proof for a given baseUrl. */
function initIdentityForProxy(
  baseUrl: string,
): { keyPair: ClientKeyPair; identity: IdentityConfig; releaseProof: ReleaseProof } | null {
  try {
    const identity: IdentityConfig = {
      client_kind: "official-vscode",
      version: "1.4.20",
      user_agent_product: "notokenlimit-vscode",
      request_payload_prefix: "notokenlimit-vscode-request-v1",
      machine_id: "",
      installation_id: "",
      private_key_pem: "",
      public_der_b64url: "",
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

// OAuth login
async function loginNotoken(callbacks: OAuthLoginCallbacks): Promise<OAuthCredentials> {
  const baseUrl = "https://notokenlimit.com";
  const identityResult = initIdentityForProxy(baseUrl);
  if (!identityResult) throw new Error("Failed to initialize identity. Check release-proof.json.");

  const { keyPair, identity, releaseProof } = identityResult;

  // Device code flow: start → show code + URL → open browser → poll automatically
  const tokens = await runDeviceCodeFlow(
    baseUrl,
    keyPair,
    identity,
    releaseProof,
    (userCode, verificationUrl) => {
      // Show the user their code and the URL to visit
      callbacks.onAuth({ url: verificationUrl });
      console.error(`[notoken] Your code: ${userCode}`);
      console.error(`[notoken] Open: ${verificationUrl}`);
    },
  );

  const fullCreds: OAuthCredentials = {
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
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

  saveCredentials(fullCreds);
  setProxyCredentials({
    accessToken: tokens.accessToken,
    refreshToken: tokens.refreshToken,
    baseUrl: fullCreds.baseUrl,
    keyPair,
    identity,
    releaseProof,
  });
  clearCachedCatalog();
  return {
    refresh: tokens.accessToken,
    access: tokens.accessToken,
    expires: Date.now() + 365 * 24 * 60 * 60 * 1000,
  };
}

async function refreshNotokenToken(c: OAuthCredentials): Promise<OAuthCredentials> {
  return c;
}

// Extension entry
export default async function (pi: ExtensionAPI) {
  _pi = pi;

  const proxyPort = await startProxy();
  const baseUrl = `http://127.0.0.1:${proxyPort}/v1`;

  let hasCreds = false;
  let accessToken = "";
  let storedBaseUrl = "https://notokenlimit.com";
  let keyPair: ClientKeyPair | null = null;
  let identity: IdentityConfig | null = null;
  let releaseProof: ReleaseProof | null = null;

  try {
    const stored = loadCredentials();
    if (stored) {
      // Reconstruct key pair and identity from stored credentials
      keyPair = { privatePem: stored.keyPair.privatePem, publicDerB64url: stored.keyPair.publicDerB64url };
      identity = {
        ...stored.identity,
        private_key_pem: stored.keyPair.privatePem,
        public_key_der_b64url: stored.keyPair.publicDerB64url,
        release_proof_path: "./release-proof.json",
      };
      try {
        releaseProof = loadReleaseProof(identity.release_proof_path);
      } catch {
        releaseProof = null;
      }
      if (releaseProof) {
        setProxyCredentials({
          accessToken: stored.accessToken,
          refreshToken: stored.refreshToken,
          baseUrl: stored.baseUrl,
          keyPair,
          identity,
          releaseProof,
        });
        hasCreds = true;
        accessToken = stored.accessToken;
        storedBaseUrl = stored.baseUrl;
      }
    }
  } catch { /* no creds yet */ }

  const models = hasCreds && keyPair && identity && releaseProof
    ? await fetchDynamicModels(accessToken, storedBaseUrl, keyPair, identity, releaseProof)
    : [];

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

  console.error(hasCreds ? `[notoken] connected — ${models.length} models` : `[notoken] /login notoken to connect`);

  pi.registerCommand("notoken-status", {
    description: "Show NoTokenLimit auth status",
    handler: async (_args, ctx) => {
      const c = loadCredentials();
      if (!c) {
        ctx.ui.notify("NoTokenLimit: not signed in. /login notoken", "warning");
        return;
      }
      ctx.ui.notify(`NoTokenLimit: authenticated (${c.baseUrl}) — token issued ${c.issuedAt}`, "info");
    },
  });

  pi.registerCommand("notoken-logout", {
    description: "Sign out of NoTokenLimit",
    handler: async (_args, ctx) => {
      const ok = deleteCredentials();
      setProxyCredentials(null);
      clearCachedCatalog();
      ctx.ui.notify(ok ? "NoTokenLimit: signed out." : "Already signed out.", "info");
    },
  });

  pi.registerCommand("notoken-refresh", {
    description: "Refresh NoTokenLimit model catalog",
    handler: async (_args, ctx) => {
      const c = loadCredentials();
      if (!c) {
        ctx.ui.notify("NoTokenLimit: not signed in. /login notoken", "warning");
        return;
      }
      clearCachedCatalog();
      const identityResult = initIdentityForProxy(c.baseUrl);
      if (!identityResult) {
        ctx.ui.notify("NoTokenLimit: failed to init identity.", "error");
        return;
      }
      try {
        const catalog = await getCachedCatalog(c.baseUrl, c.accessToken, identityResult.keyPair, identityResult.identity, identityResult.releaseProof);
        if (catalog) {
          ctx.ui.notify(`NoTokenLimit: refreshed ${catalog.models.length} models. Restart Pi to apply.`, "info");
        } else {
          ctx.ui.notify("NoTokenLimit: refresh failed. Check connection.", "warning");
        }
      } catch (e) {
        ctx.ui.notify(`NoTokenLimit: refresh error - ${e instanceof Error ? e.message : String(e)}`, "error");
      }
    },
  });

  pi.on("session_shutdown", async () => {
    _pi = null;
    stopProxy();
  });
}
