# pi-notoken

NoTokenLimit provider for Pi. Enables NoTokenLimit models via a local OpenAI-compatible proxy.

## Setup

```bash
# From Pi:
pi install ./pi-notoken

# Login:
/login notoken

# Use models:
/model notoken/gemini-2.5-flash
```

## How it works

1. On startup, starts a local HTTP proxy on `127.0.0.1:42102`
2. Pi connects to the proxy via OpenAI Chat Completions API
3. The proxy translates to NoTokenLimit's REST API with Ed25519 signed headers
4. Models are fetched dynamically from `/api/copilot/models`

## Architecture

```
Pi Client  ──OpenAI API──>  Local Proxy (42102)  ──REST+SSE──>  NoTokenLimit Cloud
```

## Files

| File | Purpose |
|------|---------|
| `index.ts` | Pi extension entry (provider registration) |
| `proxy.ts` | HTTP server (OpenAI API -> NoTokenLimit REST) |
| `chat.ts` | SSE streaming with Ed25519 signed headers |
| `catalog.ts` | Model catalog from `/api/copilot/models` |
| `models.ts` | Minimal model resolution |
| `auth.ts` | Ed25519 key management + token refresh |
| `metadata.ts` | HTTP header builder |
| `wire.ts` | Crypto helpers + SSE parser |
| `oauth.ts` | Device code auth flow |
| `tools.ts` | Tool calling protocol |

## Commands

- `/login notoken` - Sign in via device code flow
- `/notoken-status` - Show auth status
- `/notoken-logout` - Sign out
- `/notoken-refresh` - Refresh model catalog

## Dependencies

Zero runtime dependencies. Uses only Node.js built-ins (`crypto`, `http`, `fs`, `path`, `os`, `child_process`).
