/**
 * HTTP/1.1 fetch wrapper using node:https (not undici).
 *
 * The NoTokenLimit server TLS-fingerprint-checks connections.
 * undici/fetch() gets rejected. node:https uses OpenSSL directly
 * and is accepted. This wraps node:https in a fetch-like API.
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

/**
 * Fetch that uses node:https instead of undici.
 * Forces HTTP/1.1 ALPN. Drop-in for global fetch on upstream calls.
 */
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

      // Collect full body for text()/json(), also expose as ReadableStream
      const chunks: Buffer[] = [];
      res.on("data", (c) => chunks.push(c));

      const getText = () => new Promise<string>((r) => {
        res.on("end", () => r(Buffer.concat(chunks).toString("utf8")));
      });

      // Wrap as ReadableStream for body.getReader() consumers
      const bodyStream = new ReadableStream<Uint8Array>({
        start(controller) {
          res.on("data", (chunk: Buffer) => {
            controller.enqueue(new Uint8Array(chunk));
          });
          res.on("end", () => {
            try { controller.close(); } catch { /* already closed */ }
          });
          res.on("error", (err) => controller.error(err));
        },
        cancel() { res.destroy(); },
      });

      resolve({
        status: res.statusCode ?? 0,
        ok: (res.statusCode ?? 0) >= 200 && (res.statusCode ?? 0) < 300,
        headers: respHeaders,
        text: getText,
        json: async () => JSON.parse(await getText()),
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
