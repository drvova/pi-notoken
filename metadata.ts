/**
 * HTTP header builder for NoTokenLimit API requests.
 * Replicates the Ed25519 signed header flow from the official VS Code extension.
 */
import { signPayload, publicKeyFingerprint, machineHash, getClientSecret, randomHex } from "./wire";

const TS_NOW = (): string => String(Math.floor(Date.now()));

export interface HeaderBuilderInput {
  method: string;
  path: string;
  accessToken: string;
  privatePem: string;
  publicDerB64url: string;
  installationId: string;
  machineId: string;
  version: string;
  clientKind: string;
  userAgentProduct: string;
  requestPayloadPrefix: string;
  releaseProof: {
    release_id: string;
    signature: string;
    [key: string]: unknown;
  };
  extra?: Record<string, string>;
}

/**
 * Build authenticated HTTP headers for a NoTokenLimit API request.
 */
export function buildRequestHeaders(input: HeaderBuilderInput): Record<string, string> {
  const ts = TS_NOW();
  const nonce = randomHex(16);
  const mhash = machineHash(input.machineId);
  const fp = publicKeyFingerprint(input.publicDerB64url);
  const userAgent = `${input.userAgentProduct}/${input.version}`;
  const methodUpper = input.method.toUpperCase();

  const requestPayload = [
    input.requestPayloadPrefix,
    methodUpper,
    input.path,
    input.version,
    input.clientKind,
    input.installationId,
    mhash,
    ts,
    nonce,
    input.releaseProof.release_id,
    fp,
    userAgent,
  ].join("\n");

  const requestSig = signPayload(input.privatePem, requestPayload);

  const headers: Record<string, string> = {
    "User-Agent": userAgent,
    "x-ext-version": input.version,
    "x-ext-client": input.clientKind,
    "x-ext-installation": input.installationId,
    "x-ext-machine": mhash,
    "x-ext-ts": ts,
    "x-ext-nonce": nonce,
    "x-ext-release-id": input.releaseProof.release_id,
    "x-ext-release-signature": input.releaseProof.signature,
    "x-ext-client-public-key": input.publicDerB64url,
    "x-ext-request-signature": requestSig,
    "x-ext-obf-secret": getClientSecret(input.version, ts, nonce),
    "Accept": "application/json",
  };

  if (input.accessToken) {
    headers["Authorization"] = `Bearer ${input.accessToken}`;
  }
  if (input.extra) {
    Object.assign(headers, input.extra);
  }
  return headers;
}
