#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Get Feishu user_access_token via OAuth (authorization_code) using localhost callback.

Usage (PowerShell):
  python feishu_oauth_get_user_token.py --app-id <cli_xxx> --app-secret <secret>

Prerequisite:
- In Feishu Open Platform console for your app, add redirect URL:
    http://localhost:8000/callback

This script will:
1) Start a local HTTP server on localhost:8000
2) Open the browser to Feishu authorize page
3) Receive ?code=... at /callback
4) Exchange code -> user_access_token

Notes:
- Keep app_secret safe; do NOT commit it.
- The app must have required permissions enabled (Docs/Drive) and user grants them.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional, Tuple


def http_json(method: str, url: str, body: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    headers = dict(headers or {})
    data: Optional[bytes]
    if body is None:
        data = None
    else:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers.setdefault("Content-Type", "application/json; charset=utf-8")

    req = urllib.request.Request(url, method=method.upper(), data=data)
    for k, v in headers.items():
        req.add_header(k, v)

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raw = e.read()
        text = raw.decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {e.code} calling {url}: {text[:2000]}")

    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        snippet = raw[:2000].decode("utf-8", errors="replace")
        raise RuntimeError(f"Non-JSON response calling {url}: {e}; body={snippet!r}")


def build_authorize_url(*, app_id: str, redirect_uri: str, state: str, scope: str = "") -> str:
    # Feishu OAuth authorize endpoint (interactive login/consent)
    # Commonly used endpoint:
    #   https://open.feishu.cn/open-apis/authen/v1/index?app_id=...&redirect_uri=...&state=...
    q = {
        "app_id": app_id,
        "redirect_uri": redirect_uri,
        "state": state,
    }
    # Some tenants/apps require explicitly requesting scopes to ensure new permissions
    # are included in the resulting user_access_token.
    if str(scope or "").strip():
        q["scope"] = str(scope).strip()
    return "https://open.feishu.cn/open-apis/authen/v1/index?" + urllib.parse.urlencode(q)


def _normalize_scopes(scopes_raw: str) -> str:
    """Normalize scopes to OAuth 'scope' parameter format (space-delimited).

    Accepts comma and/or whitespace separated strings.
    """

    s = str(scopes_raw or "").strip()
    if not s:
        return ""
    parts = []
    for chunk in s.replace(",", " ").split():
        c = chunk.strip()
        if c:
            parts.append(c)
    # OAuth2 scope is space-delimited.
    return " ".join(dict.fromkeys(parts))


def exchange_code_for_user_token(*, app_id: str, app_secret: str, code: str, redirect_uri: str) -> Dict[str, Any]:
    # Token exchange endpoints differ across Feishu doc versions.
    # Try a couple of known endpoints and payload shapes.

    attempts = []

    # 1) OAuth v2-style endpoint
    attempts.append(
        (
            "https://open.feishu.cn/open-apis/authen/v2/oauth/token",
            {
                "grant_type": "authorization_code",
                "client_id": app_id,
                "client_secret": app_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )
    )

    # 2) OIDC-style endpoint
    attempts.append(
        (
            "https://open.feishu.cn/open-apis/authen/v1/oidc/access_token",
            {
                "grant_type": "authorization_code",
                "client_id": app_id,
                "client_secret": app_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )
    )

    last_err: Optional[Exception] = None
    for url, payload in attempts:
        try:
            resp = http_json("POST", url, body=payload)
        except Exception as e:
            last_err = e
            continue

        # Common Feishu wrapper: {code,msg,data:{...}}
        if isinstance(resp, dict) and "code" in resp and "data" in resp:
            if int(resp.get("code") or 0) != 0:
                last_err = RuntimeError(f"Token exchange failed at {url}: {resp}")
                continue
            # Return the full wrapper so caller can also see top-level fields
            # (some variants may include fields outside data).
            return resp

        # Plain OAuth JSON
        if isinstance(resp, dict) and ("access_token" in resp or "user_access_token" in resp):
            return resp

        last_err = RuntimeError(f"Unrecognized token response at {url}: {resp}")

    if last_err:
        raise last_err
    raise RuntimeError("Token exchange failed: unknown error")


class _CallbackHandler(BaseHTTPRequestHandler):
    server_version = "FeishuOAuth/1.0"

    def do_GET(self):  # noqa: N802
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != "/callback":
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not found")
            return

        qs = urllib.parse.parse_qs(parsed.query)
        code = (qs.get("code") or [""])[0]
        state = (qs.get("state") or [""])[0]

        self.server._result = (code, state)  # type: ignore[attr-defined]

        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("OK. You can close this tab and return to the terminal.\n".encode("utf-8"))

    def log_message(self, fmt: str, *args):
        # Keep quiet.
        return


def wait_for_code(host: str, port: int, expected_state: str, timeout_sec: int) -> Tuple[str, str]:
    httpd = HTTPServer((host, port), _CallbackHandler)
    httpd._result = ("", "")  # type: ignore[attr-defined]

    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    start = time.time()
    try:
        while time.time() - start < timeout_sec:
            code, state = httpd._result  # type: ignore[attr-defined]
            if code:
                return code, state
            time.sleep(0.1)
        raise TimeoutError("Timed out waiting for callback.")
    finally:
        httpd.shutdown()


def main() -> int:
    ap = argparse.ArgumentParser(description="Get Feishu user_access_token via OAuth localhost callback")
    ap.add_argument("--app-id", required=False, default=os.environ.get("FEISHU_APP_ID", ""), help="App ID (cli_xxx)")
    ap.add_argument(
        "--app-secret",
        required=False,
        default=os.environ.get("FEISHU_APP_SECRET", ""),
        help="App secret (keep safe).",
    )
    ap.add_argument(
        "--redirect-uri",
        default="http://localhost:8000/callback",
        help="Must match the redirect URL configured in Feishu open platform",
    )
    ap.add_argument(
        "--scopes",
        default=os.environ.get("FEISHU_OAUTH_SCOPES", ""),
        help=(
            "Optional OAuth scopes to request (comma or space separated). "
            "Example for Wiki read: wiki:wiki:readonly wiki:node:read"
        ),
    )
    ap.add_argument("--timeout", type=int, default=300, help="Wait time for callback (seconds)")
    ap.add_argument("--no-browser", action="store_true", help="Do not auto-open browser")
    ap.add_argument(
        "--stdout-token",
        action="store_true",
        help=(
            "Print only the access token to stdout (all logs go to stderr). "
            "Useful for PowerShell capture without echoing the token, e.g. "
            "$env:FEISHU_USER_ACCESS_TOKEN=(python ... --stdout-token)"
        ),
    )
    ap.add_argument("--dump", action="store_true", help="Dump full token exchange JSON (may include sensitive fields)")
    args = ap.parse_args()

    def log(msg: str = "") -> None:
        if args.stdout_token:
            print(msg, file=sys.stderr)
        else:
            print(msg)

    app_id = str(args.app_id or "").strip()
    app_secret = str(args.app_secret or "").strip()
    redirect_uri = str(args.redirect_uri or "").strip()

    if args.stdout_token and args.dump:
        log("ERROR: --stdout-token cannot be used with --dump (would risk leaking secrets).")
        return 2

    if not app_id or not app_secret:
        log("Missing app_id/app_secret.")
        log("Provide via args: --app-id/--app-secret")
        log("or env: FEISHU_APP_ID / FEISHU_APP_SECRET")
        return 2

    u = urllib.parse.urlsplit(redirect_uri)
    host = u.hostname or "localhost"
    port = int(u.port or 8000)

    state = secrets.token_urlsafe(16)
    scopes = _normalize_scopes(str(args.scopes or ""))
    auth_url = build_authorize_url(app_id=app_id, redirect_uri=redirect_uri, state=state, scope=scopes)

    log("1) Ensure redirect URL is added in Feishu console:")
    log(f"   {redirect_uri}")
    log("\n2) Open this URL in a browser and authorize:")
    log(auth_url)
    if scopes:
        log("\nRequested scopes:")
        log(scopes)

    if not args.no_browser:
        try:
            import webbrowser

            webbrowser.open(auth_url)
        except Exception:
            pass

    log(f"\n3) Waiting for callback on {host}:{port} ...")
    code, got_state = wait_for_code(host, port, state, int(args.timeout))

    if got_state and got_state != state:
        log("WARNING: state mismatch (possible CSRF or multiple tabs). Proceeding anyway.")

    log("\n4) Exchanging code for user_access_token...")
    token_resp = exchange_code_for_user_token(app_id=app_id, app_secret=app_secret, code=code, redirect_uri=redirect_uri)

    # Unwrap common wrapper: {code,msg,data:{...}}
    if isinstance(token_resp, dict) and "data" in token_resp and isinstance(token_resp.get("data"), dict):
        data = token_resp.get("data") or {}
    else:
        data = token_resp

    access_token = str(data.get("access_token") or data.get("user_access_token") or "").strip()
    # refresh_token might appear either in data or at top-level in some variants
    refresh_token = str((data.get("refresh_token") if isinstance(data, dict) else "") or token_resp.get("refresh_token") or "").strip()  # type: ignore[union-attr]
    expires_in = data.get("expires_in")

    if not access_token:
        log("Token exchange succeeded but access_token not found. Raw response data:")
        log(json.dumps(data, ensure_ascii=False, indent=2))
        return 3

    if args.stdout_token:
        # Emit token ONLY to stdout (for capture). Everything else stays on stderr.
        log("\nSUCCESS")
        if isinstance(data, dict):
            keys = ", ".join(sorted({str(k) for k in data.keys()}))
            log(f"token_response_keys: {keys}")
        if expires_in is not None:
            log(f"expires_in: {expires_in}")
        if refresh_token:
            log("refresh_token present (keep safe).")
        else:
            log("\nNOTE: refresh_token is not present in this token exchange response.")
            log("Some Feishu OAuth flows/apps do not issue refresh_token; in that case you cannot auto-refresh user_access_token.")
        sys.stdout.write(access_token)
        sys.stdout.write("\n")
        return 0

    log("\nSUCCESS")
    if isinstance(data, dict):
        keys = ", ".join(sorted({str(k) for k in data.keys()}))
        log(f"token_response_keys: {keys}")
    log("user_access_token:")
    log(access_token)
    if expires_in is not None:
        log(f"expires_in: {expires_in}")
    if refresh_token:
        log("refresh_token (keep safe):")
        log(refresh_token)
    else:
        log("\nNOTE: refresh_token is not present in this token exchange response.")
        log("Some Feishu OAuth flows/apps do not issue refresh_token; in that case you cannot auto-refresh user_access_token.")
        log("If you expect a refresh_token, verify: app type supports it, and authorization/consent was done for the same app_id.")

    if args.dump:
        log("\n--- RAW TOKEN EXCHANGE JSON ---")
        log(json.dumps(token_resp, ensure_ascii=False, indent=2))

    log("\nPowerShell env set (recommended):")
    log(f'$env:FEISHU_USER_ACCESS_TOKEN="{access_token}"')

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
