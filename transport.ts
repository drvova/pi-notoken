/**
 * transport.ts — TS ↔ Python bridge for notokenlimit.com HTTP.
 *
 * The server TLS-fingerprint-rejects all Node.js/Bun clients.
 * Python httpx is the only accepted HTTP stack. This module spawns
 * a persistent Python subprocess and communicates via JSON lines.
 */
import { spawn, type ChildProcess } from "child_process";
import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

export interface TransportModel {
  id: string;
  name?: string;
  provider?: string;
  tier?: string;
  desc?: string;
  locked?: boolean;
  context_window?: number;
  max_output_tokens?: number;
  disabled?: boolean;
}

// ---------------------------------------------------------------------------
// Bridge
// ---------------------------------------------------------------------------

let _proc: ChildProcess | null = null;
let _buf = "";
let _chatResolve: ((line: string) => void) | null = null;
let _chatDone = false;
let _chatError: string | null = null;

function findTransportScript(): string {
  const candidates = [
    path.join(__dirname, "transport.py"),
    path.join(__dirname, "..", "pi-notoken", "transport.py"),
  ];
  for (const c of candidates) {
    try { fs.accessSync(c); return c; } catch {}
  }
  return path.join(__dirname, "transport.py");
}

function ensureProc(): ChildProcess {
  if (_proc && !_proc.killed) return _proc;
  const script = findTransportScript();
  console.error(`[transport] spawning python3 ${script}`);
  _proc = spawn("python3", [script], {
    stdio: ["pipe", "pipe", "pipe"],
    env: { ...process.env, PYTHONUNBUFFERED: "1" },
  });
  _proc.stdout?.setEncoding("utf8");
  _proc.stderr?.setEncoding("utf8");
  _proc.stderr?.on("data", (d) => console.error(`[transport:py] ${d.trimEnd()}`));
  _proc.stdout?.on("data", onStdout);
  _proc.on("exit", (code) => {
    console.error(`[transport] python3 exited (${code})`);
    _proc = null;
    _chatDone = true;
    _chatError = `transport exited (${code})`;
    _chatResolve?.("");
  });
  return _proc;
}

// Response buffer for simple commands
let _simpleBuf = "";
let _simpleResolve: ((line: string) => void) | null = null;

function onStdout(chunk: string) {
  _buf += chunk;
  const lines = _buf.split("\n");
  _buf = lines.pop() ?? "";
  for (const line of lines) {
    if (!line.trim()) continue;
    // Route to chat stream or simple command handler
    if (_chatResolve) {
      _chatResolve(line);
    } else if (_simpleResolve) {
      const r = _simpleResolve;
      _simpleResolve = null;
      r(line);
    }
  }
}

function sendSimple(command: string, params: Record<string, any> = {}): Promise<any> {
  const proc = ensureProc();
  const msg = JSON.stringify({ command, params });
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      _simpleResolve = null;
      reject(new Error(`transport timeout: ${command}`));
    }, 30_000);
    _simpleResolve = (line) => {
      clearTimeout(timeout);
      try {
        const m = JSON.parse(line);
        resolve(m);
      } catch {
        reject(new Error(`bad response: ${line}`));
      }
    };
    proc.stdin?.write(msg + "\n");
  });
}

// ---------------------------------------------------------------------------
// Streaming chat — raw SSE lines
// ---------------------------------------------------------------------------

export async function* chatSSE(
  accessToken: string,
  messages: Array<{ role: string; content: string }>,
  model: string,
  chatId?: string,
): AsyncGenerator<string> {
  const proc = ensureProc();
  const msg = JSON.stringify({
    command: "chat",
    params: { access_token: accessToken, messages, model, chat_id: chatId },
  });

  _chatDone = false;
  _chatError = null;

  const pendingLines: string[] = [];
  let resolveWait: (() => void) | null = null;

  // Temporarily take over stdout handler for streaming
  const origBuf = _buf;
  _buf = "";

  const origDataHandler = (chunk: string) => {
    _buf += chunk;
    const lines = _buf.split("\n");
    _buf = lines.pop() ?? "";
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const m = JSON.parse(line);
        if (m.event !== undefined) {
          pendingLines.push(m.event);
        } else if (m.done) {
          _chatDone = true;
        } else if (m.error) {
          _chatError = m.error;
          _chatDone = true;
        }
      } catch {
        // Raw line (not JSON) — pass through
        pendingLines.push(line);
      }
      resolveWait?.();
    }
  };

  proc.stdout?.removeListener("data", onStdout);
  proc.stdout?.on("data", origDataHandler);

  try {
    proc.stdin?.write(msg + "\n");

    while (!_chatDone || pendingLines.length > 0) {
      if (pendingLines.length > 0) {
        yield pendingLines.shift()!;
      } else if (_chatError) {
        throw new Error(_chatError);
      } else {
        await new Promise<void>((r) => { resolveWait = r; });
        resolveWait = null;
      }
    }
  } finally {
    proc.stdout?.removeListener("data", origDataHandler);
    proc.stdout?.on("data", onStdout);
    _buf = origBuf;
  }
}

// ---------------------------------------------------------------------------
// Simple commands
// ---------------------------------------------------------------------------

export async function login(
  sessionCookie: string,
  csrfCookie: string,
): Promise<TokenPair & { userName?: string; userEmail?: string; plan?: string }> {
  const r = await sendSimple("login", { session_cookie: sessionCookie, csrf_cookie: csrfCookie });
  if (r.error) throw new Error(r.error);
  return {
    accessToken: r.access_token,
    refreshToken: r.refresh_token,
    userName: r.user_name,
    userEmail: r.user_email,
    plan: r.plan,
  };
}

export async function refreshTokens(refreshToken: string): Promise<TokenPair> {
  const r = await sendSimple("refresh", { refresh_token: refreshToken });
  if (r.error) throw new Error(r.error);
  return { accessToken: r.access_token, refreshToken: r.refresh_token };
}

export async function fetchModels(accessToken: string): Promise<TransportModel[]> {
  const r = await sendSimple("models", { access_token: accessToken });
  if (r.error) throw new Error(r.error);
  return r.models ?? [];
}

export function stopTransport(): void {
  if (_proc) {
    _proc.kill();
    _proc = null;
  }
  _chatResolve = null;
  _simpleResolve = null;
  _buf = "";
}
