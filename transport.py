#!/usr/bin/env python3
"""
transport.py — Python HTTP bridge for notokenlimit.com.
The server TLS-fingerprint-rejects all Node.js/Bun clients.
Python httpx is the only accepted HTTP stack.

Protocol: stdin/stdout JSON lines.

Commands:
  login   {session_cookie, csrf_cookie} -> {access_token, refresh_token, ...}
  refresh {refresh_token}               -> {access_token, refresh_token, ...}
  models  {access_token}                -> {models: [...]}
  chat    {access_token, messages, model} -> SSE chunks streamed to stdout
"""
import sys, json, os, time, random, hashlib, base64

# Inline crypto to avoid pip dependencies beyond httpx+cryptography
try:
    import httpx
except ImportError:
    print(json.dumps({"error": "httpx not installed. Run: pip install httpx"}))
    sys.exit(1)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

BASE_URL = "https://notokenlimit.com"
ORIGIN = "vscode-file://vscode-app"

def load_config():
    candidates = [
        os.path.join(os.path.dirname(__file__), "..", ".config.json"),
        ".config.json",
    ]
    for p in candidates:
        if os.path.exists(p):
            with open(p, "rb") as f:
                raw = f.read()
            if raw[:3] == b'\xef\xbb\xbf':
                raw = raw[3:]
            return json.loads(raw)
    return {}

def load_release_proof():
    candidates = ["./release-proof.json", "../release-proof.json"]
    for p in candidates:
        if os.path.exists(p):
            with open(p) as f:
                return json.load(f)
    return {"release_id": "", "signature": ""}

# --- Crypto helpers (inlined to avoid dependencies) ---

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64url_decode(s: str) -> bytes:
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)

def _random_hex(n: int) -> str:
    return os.urandom(n).hex()

def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def _machine_hash(machine_id: str) -> str:
    return hashlib.sha256(machine_id.encode()).hexdigest()[:64]

def _get_client_secret(version: str, ts: str, nonce: str) -> str:
    payload = f"notokenlimit-vscode-client-v1\n{version}\n{ts}\n{nonce}"
    return _sha256_hex(payload.encode())[:32]

def _sign_ed25519(private_pem: str, message: str) -> str:
    if not HAS_CRYPTO:
        return ""
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    sig = key.sign(message.encode())
    return _b64url_encode(sig)

def _public_key_fingerprint(pub_der_b64url: str) -> str:
    raw = _b64url_decode(pub_der_b64url)
    return _sha256_hex(raw)

def build_request_headers(
    method: str, path: str, access_token: str, config: dict,
    extra: dict = None,
) -> dict:
    ci = config.get("client_identity", {})
    rp = load_release_proof()

    ts = str(int(time.time() * 1000))
    nonce = _random_hex(16)
    machine_id = ci.get("machine_id", "")
    version = ci.get("version", "1.4.20")
    client_kind = ci.get("client_kind", "official-vscode")
    user_agent_product = ci.get("user_agent_product", "notokenlimit-vscode")
    request_payload_prefix = ci.get("request_payload_prefix", "notokenlimit-vscode-request-v1")
    installation_id = ci.get("installation_id", "")
    private_pem = ci.get("private_key_pem", "")
    public_der_b64url = ci.get("public_key_der_b64url", "")

    mhash = _machine_hash(machine_id)
    fp = _public_key_fingerprint(public_der_b64url)
    user_agent = f"{user_agent_product}/{version}"

    request_payload = "\n".join([
        request_payload_prefix, method.upper(), path, version,
        client_kind, installation_id, mhash, ts, nonce,
        rp.get("release_id", ""), fp, user_agent,
    ])
    request_sig = _sign_ed25519(private_pem, request_payload)

    headers = {
        "User-Agent": user_agent,
        "x-ext-version": version,
        "x-ext-client": client_kind,
        "x-ext-installation": installation_id,
        "x-ext-machine": mhash,
        "x-ext-ts": ts,
        "x-ext-nonce": nonce,
        "x-ext-release-id": rp.get("release_id", ""),
        "x-ext-release-signature": rp.get("signature", ""),
        "x-ext-client-public-key": public_der_b64url,
        "x-ext-request-signature": request_sig,
        "x-ext-obf-secret": _get_client_secret(version, ts, nonce),
        "Accept": "application/json",
        "Origin": ORIGIN,
        "Referer": f"{ORIGIN}/",
    }
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    if extra:
        headers.update(extra)
    return headers

# --- Commands ---

def cmd_login(params):
    config = load_config()
    cookies = {}
    if params.get("session_cookie"):
        cookies["__Host-claude_session"] = params["session_cookie"]
    if params.get("csrf_cookie"):
        cookies["claude_csrf"] = params["csrf_cookie"]

    # Step 1: device code
    api_path = "/api/auth/extension/device-code"
    headers = build_request_headers("POST", api_path, "", config,
        extra={"Content-Type": "application/json"})
    r = httpx.post(f"{BASE_URL}{api_path}", headers=headers, content="{}", timeout=15)
    if r.status_code != 200:
        return {"error": f"device-code failed: {r.status_code} {r.text[:200]}"}
    dc = r.json()
    dc_code = dc["device_code"]
    user_code = dc["user_code"]

    # Step 2: authorize with cookies
    if cookies:
        r2 = httpx.post(
            f"{BASE_URL}/api/auth/extension/authorize",
            cookies=cookies,
            headers={"Content-Type": "application/json", "Origin": "https://notokenlimit.com",
                      "Referer": "https://notokenlimit.com/link"},
            content=json.dumps({"code": user_code}),
            timeout=10,
        )
        if r2.status_code != 200 or "approved" not in r2.text:
            return {"error": f"authorize failed: {r2.status_code} {r2.text[:200]}"}
    else:
        print(json.dumps({"status": "waiting", "user_code": user_code,
                           "url": dc.get("verification_uri_complete", dc.get("verification_uri"))}),
              flush=True)
        # Wait for manual authorization
        deadline = time.time() + dc.get("expires_in", 600)
        interval = dc.get("interval", 5)
        while time.time() < deadline:
            time.sleep(interval)

    # Step 3: poll
    device_name = f"VS Code-{_random_hex(4)}"
    deadline = time.time() + dc.get("expires_in", 600)
    interval = dc.get("interval", 5)
    while time.time() < deadline:
        time.sleep(interval)
        api_path = "/api/auth/extension/poll"
        h = build_request_headers("POST", api_path, "", config,
            extra={"Content-Type": "application/json"})
        r = httpx.post(f"{BASE_URL}{api_path}", headers=h,
                       content=json.dumps({"device_code": dc_code, "device_name": device_name}),
                       timeout=15)
        data = r.json()
        if data.get("code") == "PENDING":
            continue
        if r.status_code == 200 and data.get("access_token"):
            # Step 4: get user info
            me = httpx.get(f"{BASE_URL}/api/auth/me",
                           cookies=cookies if cookies else {},
                           headers={"User-Agent": "Mozilla/5.0"},
                           timeout=10)
            user_info = me.json() if me.status_code == 200 else {}
            return {
                "access_token": data["access_token"],
                "refresh_token": data.get("refresh_token", ""),
                "user_name": user_info.get("name", ""),
                "user_email": user_info.get("email", ""),
                "plan": user_info.get("plan", ""),
            }
        if data.get("code") not in ("PENDING", "SLOW_DOWN"):
            return {"error": f"poll failed: {json.dumps(data)[:200]}"}
    return {"error": "device code expired"}

def cmd_refresh(params):
    config = load_config()
    api_path = "/api/auth/extension/refresh"
    headers = build_request_headers("POST", api_path, "", config,
        extra={"Content-Type": "application/json"})
    r = httpx.post(f"{BASE_URL}{api_path}", headers=headers,
                   content=json.dumps({"refresh_token": params["refresh_token"]}),
                   timeout=15)
    if r.status_code == 200 and r.json().get("access_token"):
        data = r.json()
        return {"access_token": data["access_token"],
                "refresh_token": data.get("refresh_token", params["refresh_token"])}
    return {"error": f"refresh failed: {r.status_code} {r.text[:200]}"}

def cmd_models(params):
    config = load_config()
    api_path = "/api/copilot/models"
    headers = build_request_headers("GET", api_path, params["access_token"], config)
    r = httpx.get(f"{BASE_URL}{api_path}", headers=headers, timeout=15)
    if r.status_code == 200:
        return r.json()
    return {"error": f"models failed: {r.status_code} {r.text[:200]}"}

def cmd_chat(params):
    config = load_config()
    api_path = "/api/copilot/chat"
    headers = build_request_headers("POST", api_path, params["access_token"], config,
        extra={"Content-Type": "application/json", "Accept": "text/event-stream"})
    body = json.dumps({
        "messages": params["messages"],
        "model": params["model"],
        "chatId": params.get("chat_id"),
    })
    with httpx.stream("POST", f"{BASE_URL}{api_path}", headers=headers,
                      content=body, timeout=300) as r:
        if r.status_code != 200:
            print(json.dumps({"error": f"chat {r.status_code}: {r.read().decode()[:300]}"}), flush=True)
            return
        for line in r.iter_lines():
            if line.strip():
                print(json.dumps({"event": line.strip()}), flush=True)
        print(json.dumps({"done": True}), flush=True)

# --- Main loop ---

COMMANDS = {
    "login": cmd_login,
    "refresh": cmd_refresh,
    "models": cmd_models,
    "chat": cmd_chat,
}

def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        cmd = msg.get("command", "")
        params = msg.get("params", {})
        if cmd not in COMMANDS:
            print(json.dumps({"error": f"unknown command: {cmd}"}), flush=True)
            continue
        try:
            result = COMMANDS[cmd](params)
            if result is not None:
                print(json.dumps(result), flush=True)
        except Exception as e:
            print(json.dumps({"error": str(e)}), flush=True)

if __name__ == "__main__":
    main()
