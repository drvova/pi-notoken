/**
 * catalog.ts — Model catalog with transport-backed fetching.
 */
import { fetchModels, type TransportModel } from "./transport";

export interface ModelCatalogEntry {
  id: string;
  label: string;
  contextWindow: number | undefined;
  maxOutputTokens: number | undefined;
  disabled: boolean;
}

export interface ModelCatalog {
  models: ModelCatalogEntry[];
  fetchedAt: number;
}

let _cache: ModelCatalog | null = null;
const CACHE_TTL_MS = 5 * 60 * 1000;

export function clearCachedCatalog(): void { _cache = null; }

export async function getCachedCatalog(accessToken: string): Promise<ModelCatalog> {
  if (_cache && Date.now() - _cache.fetchedAt < CACHE_TTL_MS) return _cache;
  const upstream = await fetchModels(accessToken);
  _cache = {
    models: upstream.map((m: TransportModel) => ({
      id: m.id,
      label: m.name || m.id,
      contextWindow: m.context_window,
      maxOutputTokens: m.max_output_tokens,
      disabled: m.locked || false,
    })),
    fetchedAt: Date.now(),
  };
  return _cache;
}
