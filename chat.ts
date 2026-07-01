/**
 * HTTP SSE streaming for NoTokenLimit chat completions.
 * Translates OpenAI chat requests → NoTokenLimit REST, streams SSE back.
 */
import { chatSSE } from "./transport";
import { type ClientKeyPair } from "./wire";
import { isTokenError, isSSETokenError, refreshToken, type TokenPair } from "./auth";
import { parseSSELine } from "./wire";

// ----------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------

const SSE_IDLE_TIMEOUT_MS = 120_000;

export type ContentPart =
  | { type: "text"; text: string }
  | { type: "image"; mimeType: string; base64Data: string; caption?: string };

export interface ChatHistoryItem {
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  tool_call_id?: string;
  tool_calls?: Array<{ id: string; name: string; arguments: string }>;
}

export interface ToolDef {
  name: string;
  description: string;
  parameters: unknown;
}

export type ChatEvent =
  | { kind: "text"; text: string }
  | { kind: "reasoning"; text: string }
  | { kind: "tool_calls"; tool_calls: unknown[] }
  | { kind: "finish"; reason: string }
  | { kind: "usage"; promptTokens?: number; completionTokens?: number; totalTokens?: number }
  | { kind: "error"; message: string; error_code?: string };

export interface CloudChatRequest {
  accessToken: string;
  refreshToken: string;
  baseUrl: string;
  model: string;
  messages: ChatHistoryItem[];
  tools?: ToolDef[];
  chatId?: string;
  signal?: AbortSignal;
  keyPair: ClientKeyPair;
  identity: {
    client_kind: string;
    version: string;
    user_agent_product: string;
    request_payload_prefix: string;
    installation_id: string;
    machine_id: string;
  };
  releaseProof: { release_id: string; signature: string; [key: string]: unknown };
}

export interface ChatCallbacks {
  onTokenRefresh?: (newTokens: TokenPair) => void;
}

// ----------------------------------------------------------------------------
// System message extraction
// ----------------------------------------------------------------------------

function separateSystemMessages(messages: ChatHistoryItem[]): { systemPrompt: string; conversation: ChatHistoryItem[] } {
  const systemParts: string[] = [];
  const conversation: ChatHistoryItem[] = [];

  for (const m of messages) {
    if (m.role === "system") {
      systemParts.push(m.content);
    } else {
      conversation.push(m);
    }
  }

  return { systemPrompt: systemParts.join("\n\n"), conversation };
}

// ----------------------------------------------------------------------------
// Build upstream payload
// ----------------------------------------------------------------------------

function buildUpstreamPayload(
  systemPrompt: string,
  messages: ChatHistoryItem[],
  model: string,
  chatId?: string,
): Record<string, unknown> {
  const upstreamMessages: Array<{ role: string; content: string }> = [];

  if (systemPrompt) {
    upstreamMessages.push({ role: "system", content: systemPrompt });
  }

  for (const m of messages) {
    if (m.role === "tool") {
      const toolName = m.tool_call_id || "tool";
      upstreamMessages.push({ role: "user", content: `[Tool result: ${toolName}]\n${m.content || "[no output]"}` });
      continue;
    }

    let content = m.content;
    if (m.role === "assistant" && m.tool_calls && m.tool_calls.length > 0) {
      const blocks = m.tool_calls.map((tc) => {
        let args: Record<string, unknown> = {};
        try { args = JSON.parse(tc.arguments); } catch { /* keep empty */ }
        const params = Object.entries(args)
          .map(([k, v]) => (typeof v === "string" ? `${k}="${v}"` : `${k}=${JSON.stringify(v)}`))
          .join(" ");
        return params
          ? "```tool:" + tc.name + " " + params + "\n```"
          : "```tool:" + tc.name + "\n```";
      });
      content = content ? content + "\n" + blocks.join("\n") : blocks.join("\n");
    }

    upstreamMessages.push({ role: m.role, content });
  }

  const payload: Record<string, unknown> = { messages: upstreamMessages, model };
  if (chatId) payload.chatId = chatId;
  return payload;
}

// ----------------------------------------------------------------------------
// SSE parser for NoTokenLimit events
// ----------------------------------------------------------------------------

function parseSSEData(dataStr: string): ChatEvent | null {
  dataStr = dataStr.trim();
  if (!dataStr || dataStr === "[DONE]") return null;

  let obj: Record<string, unknown>;
  try { obj = JSON.parse(dataStr); } catch { return { kind: "text", text: dataStr }; }
  if (typeof obj !== "object" || obj === null) return null;

  const evtType = (obj.type as string) || "";

  if (evtType === "meta") return null;
  if (evtType === "error") {
    return { kind: "error", message: String(obj.message || obj.error || ""), error_code: String(obj.code || "") };
  }
  if (evtType === "done") return null;

  if (obj.usage && evtType !== "meta") {
    const u = obj.usage as Record<string, unknown>;
    return {
      kind: "usage",
      promptTokens: Number(u.prompt_tokens) || 0,
      completionTokens: Number(u.completion_tokens) || 0,
      totalTokens: Number(u.total_tokens) || 0,
    };
  }

  const choices = obj.choices;
  if (Array.isArray(choices) && choices.length > 0) {
    const choice = choices[0] as Record<string, unknown>;
    const finish = choice.finish_reason as string | undefined;
    const delta = (choice.delta || choice.message || {}) as Record<string, unknown>;
    const content = (delta.content as string) || "";
    const reasoning = (delta.reasoning || delta.reasoning_content || delta.reasoning_text || "") as string;
    const toolCalls = delta.tool_calls as unknown[] | undefined;

    if (content) return { kind: "text", text: content };
    if (reasoning) return { kind: "reasoning", text: reasoning };
    if (toolCalls) return { kind: "tool_calls", tool_calls: toolCalls };
    if (finish) return { kind: "finish", reason: finish };
    return null;
  }

  const content = (obj.content as string) || "";
  const reasoning = (obj.reasoning || obj.reasoning_text || obj.reasoning_content || "") as string;
  const toolCalls = obj.tool_calls as unknown[] | undefined;

  if (content) return { kind: "text", text: content };
  if (reasoning) return { kind: "reasoning", text: reasoning };
  if (toolCalls) return { kind: "tool_calls", tool_calls: toolCalls };
  if (obj.finish_reason) return { kind: "finish", reason: obj.finish_reason as string };
  return null;
}

// ----------------------------------------------------------------------------
// Main streaming function
// ----------------------------------------------------------------------------

export async function* streamChatEvents(
  req: CloudChatRequest,
  callbacks?: ChatCallbacks,
): AsyncGenerator<ChatEvent> {
  const apiPath = "/api/copilot/chat";
  const { systemPrompt, conversation } = separateSystemMessages(req.messages);
  const payload = buildUpstreamPayload(systemPrompt, conversation, req.model, req.chatId);

  let currentToken = req.accessToken;
  let currentRefreshToken = req.refreshToken;

  for (let retryAttempt = 0; retryAttempt < 2; retryAttempt++) {
    const sseBuffer: string[] = [];
    let accumulatedText = "";
    let shouldRetry = false;

    try {
      for await (const rawLine of chatSSE(currentToken, payload.messages as any, payload.model as string, payload.chatId as string | undefined)) {
        const event = parseSSELine(rawLine, sseBuffer);
        if (!event) continue;

        const parsed = parseSSEData(event.data);
        if (!parsed) continue;

        if (parsed.kind === "error") {
          if (isSSETokenError(parsed) && !accumulatedText && retryAttempt === 0) {
            const newTokens = await refreshToken(req.baseUrl, currentRefreshToken, req.keyPair, req.identity, req.releaseProof);
            if (newTokens) {
              currentToken = newTokens.accessToken;
              currentRefreshToken = newTokens.refreshToken;
              callbacks?.onTokenRefresh?.(newTokens);
              shouldRetry = true;
              break;
            }
          }
          yield parsed;
          return;
        }

        if (parsed.kind === "text") accumulatedText += parsed.text;
        yield parsed;
      }
      if (shouldRetry) continue;
      return;
    } catch (e) {
      yield { kind: "error", message: String(e) };
      return;
    }
  }
}
