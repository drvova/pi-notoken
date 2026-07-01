/**
 * OpenAI-compatible HTTP proxy → NoTokenLimit REST.
 * Binds at 127.0.0.1:42102 (or fallback port). Accepts standard
 * /v1/chat/completions and /v1/models, translates to NoTokenLimit upstream.
 */
import * as crypto from "crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "http";
import { streamChatEvents, type ChatHistoryItem } from "./chat";
import { resolveModelOrPassthrough, getDefaultModel, getCanonicalModels } from "./models";
import { loadCredentials } from "./oauth";
import { type ClientKeyPair } from "./wire";
import { type IdentityConfig, type ReleaseProof, loadReleaseProof } from "./auth";
import { toolsToSystemPrompt, toolsToUserReminder, toolBlocksToOpenAIToolCalls, ToolCallDeltaAccumulator } from "./tools";

const PROXY_HOST = "127.0.0.1";
const PROXY_PORT = 42102;

// Per-process secret
export const PROXY_SECRET: string = crypto.randomBytes(32).toString("hex");

// In-memory credentials + identity
export let proxyCredentials: {
  accessToken: string;
  refreshToken: string;
  baseUrl: string;
  keyPair: ClientKeyPair;
  identity: IdentityConfig;
  releaseProof: ReleaseProof;
} | null = null;

export function setProxyCredentials(creds: typeof proxyCredentials): void {
  proxyCredentials = creds;
}

// ----------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------

interface ChatCompletionRequest {
  model?: string;
  messages: Array<{
    role: string;
    content: string | Array<{ type: string; text?: string; image_url?: { url: string } }>;
    tool_call_id?: string;
    tool_calls?: Array<{ id?: string; type?: string; function?: { name?: string; arguments?: string } }>;
  }>;
  stream?: boolean;
  temperature?: number;
  max_tokens?: number;
  tools?: Array<{ type?: string; function?: { name?: string; description?: string; parameters?: Record<string, unknown> } }>;
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

function mapMessage(m: ChatCompletionRequest["messages"][number]): ChatHistoryItem {
  let content = typeof m.content === "string" ? m.content : extractTextContent(m.content);
  const item: ChatHistoryItem = { role: m.role as ChatHistoryItem["role"], content };

  if (m.role === "tool" && typeof m.tool_call_id === "string") {
    item.tool_call_id = m.tool_call_id;
  }
  if (m.role === "assistant" && Array.isArray(m.tool_calls) && m.tool_calls.length > 0) {
    item.tool_calls = m.tool_calls
      .filter((tc) => typeof tc.function?.name === "string")
      .map((tc) => ({
        id: tc.id || `call_${crypto.randomBytes(12).toString("hex")}`,
        name: tc.function!.name!,
        arguments: tc.function!.arguments || "{}",
      }));
  }
  return item;
}

function extractTextContent(content: string | Array<Record<string, unknown>>): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  return content
    .filter((p) => p.type === "text" && typeof p.text === "string")
    .map((p) => p.text)
    .join("");
}

function jsonError(status: number, message: string) {
  return {
    status,
    body: JSON.stringify({ error: { message, type: "notoken_error", param: null, code: null } }),
    contentType: "application/json",
  };
}

async function authorizeRequest(req: IncomingMessage): Promise<{ status: number; body: string; contentType: string } | null> {
  const authHeader = (req.headers.authorization ?? "") as string;
  if (!authHeader.startsWith("Bearer ")) {
    return jsonError(401, "Unauthorized: missing or malformed Authorization header.");
  }
  const presented = authHeader.slice(7);
  const presentedBuf = Buffer.from(presented, "utf8");

  // Accept per-process secret
  const secretBuf = Buffer.from(PROXY_SECRET, "utf8");
  if (presentedBuf.length === secretBuf.length && crypto.timingSafeEqual(presentedBuf, secretBuf)) return null;

  // Accept in-memory credentials
  if (proxyCredentials?.accessToken) {
    const credBuf = Buffer.from(proxyCredentials.accessToken, "utf8");
    if (presentedBuf.length === credBuf.length && crypto.timingSafeEqual(presentedBuf, credBuf)) return null;
  }

  // Accept persisted credentials
  try {
    const creds = loadCredentials();
    if (creds?.accessToken && creds.accessToken !== proxyCredentials?.accessToken) {
      const credBuf = Buffer.from(creds.accessToken, "utf8");
      if (presentedBuf.length === credBuf.length && crypto.timingSafeEqual(presentedBuf, credBuf)) return null;
    }
  } catch { /* ignore */ }

  return jsonError(401, "Unauthorized: Invalid Bearer token.");
}

function getBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(Buffer.from(c)));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

// ----------------------------------------------------------------------------
// Request handler
// ----------------------------------------------------------------------------

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  try {
    const url = new URL(req.url ?? "/", `http://${PROXY_HOST}`);

    // /health — unauthenticated
    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
      return;
    }

    // Auth gate
    const authErr = await authorizeRequest(req);
    if (authErr) {
      res.writeHead(authErr.status, { "Content-Type": authErr.contentType });
      res.end(authErr.body);
      return;
    }

    // /v1/models
    if (url.pathname === "/v1/models" || url.pathname === "/models") {
      const modelIds = getCanonicalModels();
      const data = modelIds.map((id) => ({ id, object: "model", created: Math.floor(Date.now() / 1000), owned_by: "notokenlimit" }));
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ object: "list", data }));
      return;
    }

    // /v1/chat/completions
    if (url.pathname === "/v1/chat/completions" || url.pathname === "/chat/completions") {
      if (req.method !== "POST") {
        res.writeHead(405, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: "Method not allowed; use POST." } }));
        return;
      }

      const rawBody = await getBody(req);
      let requestBody: ChatCompletionRequest;
      try { requestBody = JSON.parse(rawBody); }
      catch { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: { message: "Malformed JSON." } })); return; }

      if (!requestBody.messages || !Array.isArray(requestBody.messages)) {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: "messages must be an array." } }));
        return;
      }

      const diskCreds = loadCredentials();
      let diskReleaseProof = proxyCredentials?.releaseProof ?? null;
      if (!diskReleaseProof) {
        try { diskReleaseProof = loadReleaseProof("./release-proof.json"); } catch { /* ignore */ }
      }
      const creds = diskCreds ? {
        accessToken: diskCreds.accessToken,
        refreshToken: diskCreds.refreshToken,
        baseUrl: diskCreds.baseUrl,
        keyPair: { privatePem: diskCreds.keyPair.privatePem, publicDerB64url: diskCreds.keyPair.publicDerB64url },
        identity: {
          ...diskCreds.identity,
          private_key_pem: diskCreds.keyPair.privatePem,
          public_key_der_b64url: diskCreds.keyPair.publicDerB64url,
          release_proof_path: "./release-proof.json",
        },
        releaseProof: diskReleaseProof,
      } : proxyCredentials;
      if (!creds || !creds.releaseProof) {
        res.writeHead(503, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { message: "Not authenticated. Run /login notoken first." } }));
        return;
      }

      const requestedModel = requestBody.model || getDefaultModel();
      const resolved = resolveModelOrPassthrough(requestedModel);

      // Tool injection
      const toolPrompt = toolsToSystemPrompt(requestBody.tools ?? null);
      const toolReminder = toolsToUserReminder(requestBody.tools ?? null);

      // Map messages
      let messages: ChatHistoryItem[] = requestBody.messages.map(mapMessage);

      // Inject tool prompt into system + last user message
      if (toolPrompt) {
        const lastUserIdx = messages.findLastIndex((m) => m.role === "user");
        if (lastUserIdx >= 0) {
          messages[lastUserIdx] = {
            ...messages[lastUserIdx],
            content: messages[lastUserIdx].content + toolReminder,
          };
        }
      }

      const isStreaming = requestBody.stream !== false;

      if (isStreaming) {
        res.writeHead(200, {
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          "Connection": "keep-alive",
        });

        const responseId = `chatcmpl-${crypto.randomUUID()}`;
        const abort = new AbortController();
        req.on("close", () => { if (!res.writableEnded) abort.abort(); });

        try {
          let firstChunkSent = false;
          let finishReason: string | null = null;
          let usage: { promptTokens?: number; completionTokens?: number; totalTokens?: number } | null = null;
          const deltaAccum = new ToolCallDeltaAccumulator();
          let collectedText = "";

          for await (const ev of streamChatEvents({
            accessToken: creds.accessToken,
            refreshToken: creds.refreshToken,
            baseUrl: creds.baseUrl,
            model: resolved.modelId,
            messages,
            tools: (requestBody.tools ?? []).map((t) => ({
              name: t.function?.name ?? "unknown",
              description: t.function?.description ?? "",
              parameters: t.function?.parameters ?? {},
            })),
            signal: abort.signal,
            keyPair: creds.keyPair,
            identity: creds.identity,
            releaseProof: creds.releaseProof,
          })) {
            if (ev.kind === "text") {
              collectedText += ev.text;
              const chunk = { id: responseId, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: requestedModel, choices: [{ index: 0, delta: firstChunkSent ? { content: ev.text } : { role: "assistant", content: ev.text }, finish_reason: null }] };
              res.write(`data: ${JSON.stringify(chunk)}\n\n`);
              firstChunkSent = true;
            } else if (ev.kind === "reasoning") {
              const chunk = { id: responseId, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: requestedModel, choices: [{ index: 0, delta: firstChunkSent ? { reasoning: ev.text } : { role: "assistant", reasoning: ev.text }, finish_reason: null }] };
              res.write(`data: ${JSON.stringify(chunk)}\n\n`);
              firstChunkSent = true;
            } else if (ev.kind === "tool_calls") {
              // Accumulate tool calls from upstream SSE
              for (const tc of ev.tool_calls) {
                if (typeof tc === "object" && tc !== null) {
                  deltaAccum.add([tc as Record<string, unknown>]);
                }
              }
            } else if (ev.kind === "finish") {
              finishReason = ev.reason;
            } else if (ev.kind === "usage") {
              usage = { promptTokens: ev.promptTokens, completionTokens: ev.completionTokens, totalTokens: ev.totalTokens };
            } else if (ev.kind === "error") {
              res.write(`data: ${JSON.stringify({ error: { message: ev.message } })}\n\n`);
              break;
            }
          }

          // Emit tool calls parsed from text blocks (if upstream didn't send structured tool_calls)
          const textToolCalls = toolBlocksToOpenAIToolCalls(collectedText);
          if (textToolCalls.length > 0) {
            for (const tc of textToolCalls) {
              const delta = { tool_calls: [{ index: 0, id: tc.id, type: "function", function: { name: tc.name, arguments: "" } }] };
              const chunk = { id: responseId, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: requestedModel, choices: [{ index: 0, delta: firstChunkSent ? delta : { role: "assistant", ...delta }, finish_reason: null }] };
              res.write(`data: ${JSON.stringify(chunk)}\n\n`);
            }
            finishReason = "tool_calls";
          } else {
            // Emit accumulated streaming tool calls
            const accumulated = deltaAccum.snapshot();
            if (accumulated.length > 0) {
              for (let i = 0; i < accumulated.length; i++) {
                const tc = accumulated[i];
                const delta = { tool_calls: [{ index: i, id: tc.id, type: "function", function: { name: tc.name, arguments: tc.arguments } }] };
                const chunk = { id: responseId, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: requestedModel, choices: [{ index: 0, delta: firstChunkSent ? delta : { role: "assistant", ...delta }, finish_reason: null }] };
                res.write(`data: ${JSON.stringify(chunk)}\n\n`);
              }
              finishReason = "tool_calls";
            }
          }

          const finalReason = finishReason ?? "stop";
          const finishChunk = { id: responseId, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: requestedModel, choices: [{ index: 0, delta: {}, finish_reason: finalReason }] };
          res.write(`data: ${JSON.stringify(finishChunk)}\n\n`);

          if (usage) {
            const usageChunk = { id: responseId, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: requestedModel, choices: [], usage: { prompt_tokens: usage.promptTokens ?? 0, completion_tokens: usage.completionTokens ?? 0, total_tokens: usage.totalTokens ?? 0 } };
            res.write(`data: ${JSON.stringify(usageChunk)}\n\n`);
          }

          res.write("data: [DONE]\n\n");
          res.end();
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : "Unknown error";
          try {
            res.write(`data: ${JSON.stringify({ error: { message: errorMessage } })}\n\n`);
            const fChunk = { id: responseId, object: "chat.completion.chunk", created: Math.floor(Date.now() / 1000), model: requestedModel, choices: [{ index: 0, delta: {}, finish_reason: "stop" }] };
            res.write(`data: ${JSON.stringify(fChunk)}\n\n`);
            res.write("data: [DONE]\n\n");
            res.end();
          } catch { /* socket dead */ }
        }
      } else {
        // Non-streaming
        let collected = "";
        let finishReason: string | null = null;
        let usage: { promptTokens?: number; completionTokens?: number; totalTokens?: number } | null = null;
        const abort = new AbortController();

        for await (const ev of streamChatEvents({
          accessToken: creds.accessToken,
          refreshToken: creds.refreshToken,
          baseUrl: creds.baseUrl,
          model: resolved.modelId,
          messages,
          tools: (requestBody.tools ?? []).map((t) => ({
            name: t.function?.name ?? "unknown",
            description: t.function?.description ?? "",
            parameters: t.function?.parameters ?? {},
          })),
          signal: abort.signal,
          keyPair: creds.keyPair,
          identity: creds.identity,
          releaseProof: creds.releaseProof,
        })) {
          if (ev.kind === "text") collected += ev.text;
          else if (ev.kind === "finish") finishReason = ev.reason;
          else if (ev.kind === "usage") usage = { promptTokens: ev.promptTokens, completionTokens: ev.completionTokens, totalTokens: ev.totalTokens };
          else if (ev.kind === "error") { res.writeHead(502, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: { message: ev.message } })); return; }
        }

        // Parse tool calls from text
        const textToolCalls = toolBlocksToOpenAIToolCalls(collected);
        if (textToolCalls.length > 0) finishReason = "tool_calls";

        const assistantMessage = textToolCalls.length > 0
          ? { role: "assistant" as const, content: collected, tool_calls: textToolCalls.map((tc) => ({ id: tc.id, type: "function" as const, function: { name: tc.name, arguments: tc.arguments } })) }
          : { role: "assistant" as const, content: collected };

        const resp: Record<string, unknown> = {
          id: `chatcmpl-${crypto.randomUUID()}`,
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: requestedModel,
          choices: [{ index: 0, message: assistantMessage, finish_reason: finishReason ?? "stop" }],
          ...(usage ? { usage: { prompt_tokens: usage.promptTokens ?? 0, completion_tokens: usage.completionTokens ?? 0, total_tokens: usage.totalTokens ?? 0 } } : {}),
        };

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(resp));
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: { message: `Unsupported path: ${url.pathname}` } }));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    try {
      res.writeHead(500, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: { message } }));
    } catch { /* ignore */ }
  }
}

// ----------------------------------------------------------------------------
// Server
// ----------------------------------------------------------------------------

let serverInstance: ReturnType<typeof createServer> | null = null;

export function startProxy(port: number = PROXY_PORT): Promise<number> {
  if (serverInstance) return Promise.resolve((serverInstance.address() as { port: number }).port);

  return new Promise((resolve, reject) => {
    const srv = createServer(handleRequest);
    srv.on("error", (err: NodeJS.ErrnoException) => {
      if (err.code === "EADDRINUSE") {
        srv.listen(0, PROXY_HOST, () => {
          serverInstance = srv;
          resolve((srv.address() as { port: number }).port);
        });
        return;
      }
      reject(err);
    });
    srv.listen(port, PROXY_HOST, () => {
      serverInstance = srv;
      resolve((srv.address() as { port: number }).port);
    });
  });
}

export function stopProxy(): void {
  if (serverInstance) {
    try { serverInstance.close(); } catch { /* ignore */ }
    serverInstance = null;
  }
}
