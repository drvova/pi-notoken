/**
 * Live model catalog from NoTokenLimit /api/copilot/models.
 * Fetches at startup and after login. Cached with TTL.
 */
import { buildRequestHeaders } from "./metadata";
import { fetch11 } from "./fetch11";
import { type ClientKeyPair } from "./wire";

const CATALOG_TTL_MS = 10 * 60 * 1000;

export interface ModelCatalogEntry {
  id: string;
  label: string;
  provider?: string;
  disabled?: boolean;
  contextWindow?: number;
  maxOutputTokens?: number;
}

interface CacheEntry {
  models: ModelCatalogEntry[];
  fetchedAt: number;
}

let cached: CacheEntry | null = null;
let inFlight: Promise<CacheEntry> | null = null;

// tslint:disable-next-line:no-empty-interface
interface IdentityLike {
  client_kind: string;
  version: string;
  user_agent_product: string;
  request_payload_prefix: string;
  installation_id: string;
  machine_id: string;
}

// tslint:disable-next-line:no-empty-interface
interface ReleaseProofLike {
  release_id: string;
  signature: string;
  [key: string]: unknown;
}

async function fetchCatalog(
  baseUrl: string,
  accessToken: string,
  keyPair: ClientKeyPair,
  identity: IdentityLike,
  releaseProof: ReleaseProofLike,
  signal?: AbortSignal,
): Promise<CacheEntry> {
  const apiPath = "/api/copilot/models";
  const headers = buildRequestHeaders({
    method: "GET",
    path: apiPath,
    accessToken,
    privatePem: keyPair.privatePem,
    publicDerB64url: keyPair.publicDerB64url,
    installationId: identity.installation_id,
    machineId: identity.machine_id,
    version: identity.version,
    clientKind: identity.client_kind,
    userAgentProduct: identity.user_agent_product,
    requestPayloadPrefix: identity.request_payload_prefix,
    releaseProof,
  });

  const resp = await fetch11(`${baseUrl.replace(/\/$/, "")}${apiPath}`, { method: "GET", headers, signal });
  if (!resp.ok) throw new Error(`Catalog fetch failed: HTTP ${resp.status}`);

  const data = await resp.json() as unknown;
  let rawModels: unknown[] = [];
  if (Array.isArray(data)) {
    rawModels = data;
  } else if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    rawModels = (obj.models as unknown[]) || (obj.data as unknown[]) || [];
  }

  const models: ModelCatalogEntry[] = rawModels
    .filter((m): m is Record<string, unknown> => typeof m === "object" && m !== null && "id" in m)
    .map((m) => ({
      id: String(m.id),
      label: String(m.id),
      provider: typeof m.provider === "string" ? m.provider : undefined,
      disabled: typeof m.disabled === "boolean" ? m.disabled : false,
      contextWindow: typeof m.context_window === "number" ? m.context_window : undefined,
      maxOutputTokens: typeof m.max_output_tokens === "number" ? m.max_output_tokens : undefined,
    }));

  return { models, fetchedAt: Date.now() };
}

export async function getCachedCatalog(
  baseUrl: string,
  accessToken: string,
  keyPair: ClientKeyPair,
  identity: IdentityLike,
  releaseProof: ReleaseProofLike,
  signal?: AbortSignal,
): Promise<CacheEntry | null> {
  if (cached && Date.now() - cached.fetchedAt < CATALOG_TTL_MS) return cached;
  if (inFlight) {
    try { return await inFlight; } catch { return null; }
  }

  const promise = fetchCatalog(baseUrl, accessToken, keyPair, identity, releaseProof, signal);
  inFlight = promise;
  try {
    const result = await promise;
    cached = result;
    return result;
  } catch {
    return null;
  } finally {
    if (inFlight === promise) inFlight = null;
  }
}

export function clearCachedCatalog(): void {
  cached = null;
  inFlight = null;
}
