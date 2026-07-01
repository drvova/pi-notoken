/**
 * Minimal model resolution — catalog is the single source of truth.
 */

export interface ResolvedModel {
  modelId: string;
}

/** Pass-through: the raw model name IS the UID. */
export function resolveModelOrPassthrough(modelName: string): ResolvedModel {
  return { modelId: modelName };
}

export function getDefaultModel(): string {
  return "";
}

export function getCanonicalModels(): string[] {
  return [];
}
