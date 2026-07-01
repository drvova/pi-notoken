/**
 * HTTP/1.1 fetch wrapper using node:https (not undici).
 *
 * The NoTokenLimit server TLS-fingerprint-checks connections.
 * undici/fetch() gets rejected. node:https uses OpenSSL directly
 * and is accepted. This wraps node:https in a fetch-like API.
 *
 * Supports both buffered (text/json) and streaming (body.getReader()) modes.
 * Use text() or json() for non-streaming responses.
 * Use body.getReader() for SSE streaming — data arrives as it comes.
 * Do NOT mix: either read body OR call text/json, not both.
 */
import https from "node:https";

interface Fetch11Response {
  status: number;
  ok: boolean;
  headers: Record<string, string>;
  text(): Promise<string>;
  json(): Promise<any>;
  body: ReadableStream<Uint8Array> | null;
}

export function fetch11(
  url: string | URL,
  init?: RequestInit,
): Promise<Fetch11Response> {
  const target = typeof url === "string" ? new URL(url) : url;
  const method = init?.method?.toUpperCase() ?? "GET";
  const headers: Record<string, string> = {};

  if (init?.headers) {
    if (init.headers instanceof Headers) {
      init.headers.forEach((v, k) => { headers[k] = v; });
    } else if (Array.isArray(init.headers)) {
      for (const [k, v] of init.headers) headers[k] = v;
    } else {
      Object.assign(headers, init.headers);
    }
  }

  const body = typeof init?.body === "string" ? init.body : undefined;

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: target.hostname,
      port: target.port || 443,
      path: target.pathname + target.search,
      method,
      headers,
      ALPNProtocols: ["http/1.1"],
    }, (res) => {
      const respHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(res.headers)) {
        if (v !== undefined) respHeaders[k] = Array.isArray(v) ? v.join(", ") : v;
      }

      // Single ReadableStream from the raw node response.
      // Consumers choose: getReader() for streaming, or text()/json() which drain it.
      const bodyStream = new ReadableStream<Uint8Array>({
        start(controller) {
          res.on("data", (chunk: Buffer) => {
            try { controller.enqueue(new Uint8Array(chunk)); } catch { /* closed */ }
          });
          res.on("end", () => { try { controller.close(); } catch { /* closed */ } });
          res.on("error", (err) => controller.error(err));
        },
        cancel() { res.destroy(); },
      });

      // text/json drain the stream
      const drain = async (): Promise<string> => {
        const reader = bodyStream.getReader();
        const parts: Uint8Array[] = [];
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          parts.push(value);
        }
        return new TextDecoder().decode(Buffer.concat(parts.map(Buffer.from)));
      };

      resolve({
        status: res.statusCode ?? 0,
        ok: (res.statusCode ?? 0) >= 200 && (res.statusCode ?? 0) < 300,
        headers: respHeaders,
        text: drain,
        json: async () => JSON.parse(await drain()),
        body: bodyStream,
      });
    });

    req.on("error", reject);
    if (init?.signal) {
      init.signal.addEventListener("abort", () => req.destroy(new Error("Aborted")));
    }
    if (body) req.write(body);
    req.end();
  });
}
