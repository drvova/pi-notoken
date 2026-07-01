/**
 * Tool calling protocol for NoTokenLimit.
 *
 * Injects tool definitions into the system prompt and parses tool calls
 * from the assistant's text response. Uses the fenced code-block format:
 *   ```tool:tool_name key=value
 *   body
 *   ```
 */
import * as crypto from "crypto";

const TOOL_CALL_RE = /```tool:([A-Za-z0-9_.:-]+)([^\n`]*)\r?\n([\s\S]*?)```/gi;
const PARAM_RE = /([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s]+))/g;

// ----------------------------------------------------------------------------
// Types
// ----------------------------------------------------------------------------

export interface ToolCall {
  name: string;
  params: Record<string, string>;
  body: string;
}

export interface OpenAIToolSpec {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
}

// ----------------------------------------------------------------------------
// Parsing
// ----------------------------------------------------------------------------

function parseParams(paramStr: string): Record<string, string> {
  if (!paramStr) return {};
  const result: Record<string, string> = {};
  let m: RegExpExecArray | null;
  PARAM_RE.lastIndex = 0;
  while ((m = PARAM_RE.exec(paramStr))) {
    result[m[1]] = m[2] ?? m[3] ?? m[4] ?? "";
  }
  return result;
}

export function parseToolCalls(text: string): ToolCall[] {
  if (!text) return [];
  const out: ToolCall[] = [];
  let m: RegExpExecArray | null;
  let safety = 0;
  TOOL_CALL_RE.lastIndex = 0;
  while ((m = TOOL_CALL_RE.exec(text))) {
    if (++safety > 50) break;
    out.push({
      name: m[1].toLowerCase(),
      params: parseParams(m[2].trim()),
      body: m[3].replace(/^\r?\n|\r?\n$/g, ""),
    });
  }
  return out;
}

export function stripToolBlocks(text: string): string {
  if (!text) return "";
  return text.replace(TOOL_CALL_RE, "").trim();
}

// ----------------------------------------------------------------------------
// System prompt generation
// ----------------------------------------------------------------------------

function shorten(value: string, limit: number): string {
  const text = (value || "").replace(/\s+/g, " ").trim();
  return text.length <= limit ? text : text.slice(0, limit - 3).trimEnd() + "...";
}

export function toolsToSystemPrompt(tools: unknown[] | null): string {
  if (!tools || tools.length === 0) return "";

  const specs: OpenAIToolSpec[] = [];
  for (const raw of tools) {
    const func = (raw && typeof raw === "object" && (raw as Record<string, unknown>).function) || raw;
    if (!func || typeof func !== "object") continue;
    const f = func as Record<string, unknown>;
    const name = String(f.name || "").trim();
    if (!name) continue;
    specs.push({
      name,
      description: String(f.description || ""),
      parameters: (typeof f.parameters === "object" && f.parameters) || {},
    });
  }

  if (specs.length === 0) return "";

  const lines = [
    "You are NoTokenLimit running inside a host application that will execute OpenAI function tools for you.",
    "The host has provided REAL tools in this request. You do not execute actions directly in prose; you request them by emitting `tool:` fenced blocks.",
    "",
    "TOOL CALL PROTOCOL:",
    "Emit one or more fenced blocks and then stop so the host can run them:",
    "",
    "```tool:<exact_tool_name>",
    '{"argument_name":"argument value"}',
    "```",
    "",
    "You may also put simple scalar arguments on the opening line as key=value, but JSON in the block body is preferred for accuracy.",
    "Use only the exact tool names listed below. The proxy converts each block to OpenAI `tool_calls` for the client.",
    "",
    "AVAILABLE TOOLS:",
  ];

  for (const spec of specs) {
    const params = (spec.parameters.properties as Record<string, unknown>) || {};
    const required = (spec.parameters.required as string[]) || [];
    const desc = shorten(spec.description, 160);
    const details: string[] = [];
    if (desc) details.push(desc);
    const reqNames = Object.keys(params).filter((k) => required.includes(k));
    const optNames = Object.keys(params).filter((k) => !required.includes(k));
    if (reqNames.length) details.push("required: " + reqNames.join(", "));
    if (optNames.length) details.push("optional: " + optNames.slice(0, 16).join(", "));
    lines.push(`- ${spec.name}` + (details.length ? `: ${details.join("; ")}` : ""));
  }

  lines.push(
    "",
    "RULES:",
    "1. If the user asks for information that requires any listed tool, call the relevant tool instead of explaining that you cannot.",
    "2. Do not ask the user to run commands, open files, paste file contents, or perform work that a listed tool can do.",
    "3. When you need tool results before answering, emit only tool blocks and no prose.",
    "4. After tool results arrive, continue from those results. Call more tools if needed; otherwise give the final answer.",
    "5. If a tool can access files, terminals, browsers, web search, calendars, or other external systems, treat that access as available through the host tool.",
  );

  return lines.join("\n");
}

export function toolsToUserReminder(tools: unknown[] | null): string {
  if (!tools || tools.length === 0) return "";
  const names: string[] = [];
  for (const raw of tools) {
    const func = (raw && typeof raw === "object" && (raw as Record<string, unknown>).function) || raw;
    if (!func || typeof func !== "object") continue;
    const name = String((func as Record<string, unknown>).name || "").trim();
    if (name) names.push(name);
  }
  if (names.length === 0) return "";
  return (
    `\n\n[Tool access reminder: this request includes executable host tools. ` +
    `When a listed tool can satisfy the request, emit a \`tool:<exact_tool_name>\` ` +
    `fenced block and stop for results. Available tool names: ${names.join(", ")}]`
  );
}

// ----------------------------------------------------------------------------
// Text tool blocks → OpenAI tool_calls
// ----------------------------------------------------------------------------

export function toolBlocksToOpenAIToolCalls(text: string): Array<{ id: string; name: string; arguments: string }> {
  const calls = parseToolCalls(text);
  return calls.map((call) => {
    let args: Record<string, unknown> = { ...call.params };
    const body = call.body.trim();
    if (body) {
      try {
        const parsed = JSON.parse(body);
        if (typeof parsed === "object" && parsed !== null) Object.assign(args, parsed);
      } catch {
        // body is not JSON — check if there's a single required string param
        args.body = body;
      }
    }
    return {
      id: `call_${crypto.randomBytes(12).toString("hex")}`,
      name: call.name,
      arguments: JSON.stringify(args),
    };
  });
}

// ----------------------------------------------------------------------------
// Streaming tool call accumulator
// ----------------------------------------------------------------------------

export class ToolCallDeltaAccumulator {
  private byIndex = new Map<number, { id?: string; name?: string; arguments: string }>();

  add(rawCalls: Array<Record<string, unknown>>): void {
    for (let i = 0; i < rawCalls.length; i++) {
      const raw = rawCalls[i];
      const index = (typeof raw.index === "number" ? raw.index : i) || 0;
      const current = this.byIndex.get(index) || { arguments: "" };
      if (typeof raw.id === "string") current.id = raw.id;
      if (typeof raw.name === "string") current.name = raw.name;
      const func = raw.function;
      if (func && typeof func === "object") {
        const fn = func as Record<string, unknown>;
        if (typeof fn.name === "string") current.name = fn.name;
        if (typeof fn.arguments === "string") current.arguments += fn.arguments;
      } else if (typeof raw.arguments === "string") {
        current.arguments += raw.arguments;
      }
      this.byIndex.set(index, current);
    }
  }

  snapshot(): Array<{ id: string; name: string; arguments: string }> {
    const out: Array<{ id: string; name: string; arguments: string }> = [];
    for (const [index] of [...this.byIndex.entries()].sort((a, b) => a[0] - b[0])) {
      const item = this.byIndex.get(index)!;
      if (!item.name) continue;
      out.push({
        id: item.id || `call_${crypto.randomBytes(12).toString("hex")}`,
        name: item.name,
        arguments: item.arguments || "{}",
      });
    }
    return out;
  }
}
