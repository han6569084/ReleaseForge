#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import os
import ssl
import base64
import urllib.parse
import urllib.request
from typing import Any, Dict, Optional, Tuple


def _mask_token(token: str, head: int = 6, tail: int = 4) -> str:
    token = str(token or "")
    if not token:
        return ""
    if len(token) <= head + tail:
        return token[: max(1, min(len(token), head))] + "***"
    return token[:head] + "***" + token[-tail:]


def _try_parse_json(text: str) -> Optional[Dict[str, Any]]:
    if not text:
        return None
    s = text.strip()
    if not s.startswith("{"):
        return None
    try:
        obj = json.loads(s)
    except Exception:
        return None
    return obj if isinstance(obj, dict) else None


def _extract_error_fields(err: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    if not isinstance(err, dict):
        return out
    for k in ("code", "msg"):
        if k in err:
            out[k] = err.get(k)
    e = err.get("error")
    if isinstance(e, dict) and "log_id" in e:
        out["log_id"] = e.get("log_id")
    pv = err.get("error", {})
    if isinstance(pv, dict):
        pvs = pv.get("permission_violations")
        if isinstance(pvs, list):
            out["permission_violations"] = pvs
    return out


def _b64url_decode(s: str) -> bytes:
    s = str(s or "")
    # Add padding
    pad = "=" * ((4 - (len(s) % 4)) % 4)
    return base64.urlsafe_b64decode((s + pad).encode("utf-8"))


def _try_decode_jwt_payload(token: str) -> Optional[Dict[str, Any]]:
    token = str(token or "").strip()
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        payload_raw = _b64url_decode(parts[1]).decode("utf-8", errors="replace")
        obj = json.loads(payload_raw)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def _http_json(*, method: str, url: str, headers: Dict[str, str], body: Optional[Dict[str, Any]] = None, timeout_sec: int = 30) -> Dict[str, Any]:
    data: Optional[bytes]
    if body is None:
        data = None
    else:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = {**headers, "Content-Type": "application/json; charset=utf-8"}

    req = urllib.request.Request(url, method=method.upper(), data=data)
    for k, v in (headers or {}).items():
        req.add_header(k, v)

    # Allow corporate/self-signed TLS interception if user chooses via env
    # Default: verify TLS.
    verify_tls = (os.environ.get("FEISHU_VERIFY_TLS") or "true").strip().lower() not in ("0", "false", "no")
    if url.lower().startswith("https://") and not verify_tls:
        ssl_ctx = ssl._create_unverified_context()  # noqa: SLF001
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_ctx))
    else:
        opener = urllib.request.build_opener()

    try:
        with opener.open(req, timeout=int(timeout_sec)) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raw = e.read() if hasattr(e, "read") else b""
        detail = raw.decode("utf-8", errors="replace")[:2000]
        raise RuntimeError(f"HTTP {e.code} calling {url}: {detail}")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Network error calling {url}: {e}")

    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        snippet = raw[:2000].decode("utf-8", errors="replace")
        raise RuntimeError(f"Non-JSON response calling {url}: {e}; body={snippet!r}")


def _extract_page_id_from_url(url: str) -> Optional[str]:
    if not url:
        return None
    u = urllib.parse.urlsplit(url.strip())

    # query candidates
    q = urllib.parse.parse_qs(u.query)
    for key in ("page_id", "pageId", "node_id", "nodeId", "id"):
        vals = q.get(key)
        if vals and str(vals[0]).strip():
            return str(vals[0]).strip()

    # path candidates
    # Common: https://xxx.feishu.cn/wiki/<page_id>
    parts = [p for p in u.path.split("/") if p]
    if not parts:
        return None
    if "wiki" in parts:
        idx = parts.index("wiki")
        if idx + 1 < len(parts):
            candidate = parts[idx + 1]
            if candidate:
                return candidate.strip()

    # fallback: last segment
    return parts[-1].strip() if parts[-1].strip() else None


def _summarize_wiki_get_node(data: Dict[str, Any]) -> Dict[str, str]:
    """Extract wiki node fields from wiki/v2/spaces/get_node response data."""

    out: Dict[str, str] = {}
    if not isinstance(data, dict):
        return out

    node = data.get("node") if isinstance(data.get("node"), dict) else None
    if not node:
        return out

    for k in (
        "space_id",
        "node_token",
        "obj_token",
        "obj_type",
        "parent_node_token",
        "title",
        "url",
    ):
        v = node.get(k)
        if v is None:
            continue
        s = str(v).strip()
        if s:
            out[k] = s
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch Feishu Wiki node/space info via wiki v2 get_node (knowledge fallback)")
    ap.add_argument("--page-id", default="", help="(Deprecated) knowledge page_id. Prefer --node-token/--url for Wiki.")
    ap.add_argument("--node-token", default="", help="Wiki node token (typically the part after /wiki/ in the URL)")
    ap.add_argument("--url", default="", help="A Feishu wiki page URL; script will extract node token")
    ap.add_argument("--token", default="", help="user_access_token (or set env FEISHU_USER_ACCESS_TOKEN)")
    ap.add_argument("--show-token", action="store_true", help="Print masked token info (prefix/len) for debugging")
    ap.add_argument(
        "--inspect-token",
        action="store_true",
        help="Decode JWT payload (no verification) and print key claims to confirm app_id/scopes",
    )
    ap.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds")
    ap.add_argument("--dump", action="store_true", help="Print full JSON response")
    args = ap.parse_args()

    token_source = "arg"
    token = str(args.token or "").strip()
    if not token:
        token_source = "env:FEISHU_USER_ACCESS_TOKEN"
        token = (os.environ.get("FEISHU_USER_ACCESS_TOKEN") or "").strip()
    if not token:
        raise SystemExit("Missing token. Provide --token or set env FEISHU_USER_ACCESS_TOKEN")

    if args.show_token:
        print(f"token_source: {token_source}")
        print(f"token_len: {len(token)}")
        print(f"token_masked: {_mask_token(token)}")

    if args.inspect_token:
        payload = _try_decode_jwt_payload(token)
        if not payload:
            print("token_payload: (not a decodable JWT payload)")
        else:
            # Print a minimal, safe subset
            keys = [
                "appid",
                "app_id",
                "tenant_key",
                "tenant",
                "sub",
                "user_id",
                "open_id",
                "union_id",
                "scope",
                "scopes",
                "privileges",
                "exp",
                "iat",
            ]
            out: Dict[str, Any] = {}
            for k in keys:
                if k in payload:
                    out[k] = payload.get(k)
            # Some tokens nest claims
            if "data" in payload and isinstance(payload.get("data"), dict):
                d = payload.get("data")
                for k in keys:
                    if k in d and k not in out:
                        out[k] = d.get(k)
            print("token_payload:")
            print(json.dumps(out, ensure_ascii=False, indent=2))

    node_token = (args.node_token or "").strip()
    if not node_token:
        node_token = _extract_page_id_from_url(str(args.url or "")) or ""

    try:
        # Primary: Wiki v2 get_node (URL /wiki/<token> is a node token)
        if node_token:
            api_url = f"https://open.feishu.cn/open-apis/wiki/v2/spaces/get_node?token={urllib.parse.quote(node_token)}"
            resp = _http_json(method="GET", url=api_url, headers={"Authorization": f"Bearer {token}"}, timeout_sec=int(args.timeout))
            code = int(resp.get("code") or 0)
            if code != 0:
                raise SystemExit(f"API error (wiki get_node): {resp}")

            data = resp.get("data") or {}
            info = _summarize_wiki_get_node(data)

            print("node_token:", info.get("node_token") or node_token)
            print("space_id:", info.get("space_id") or "")
            print("obj_type:", info.get("obj_type") or "")
            print("obj_token:", info.get("obj_token") or "")
            print("parent_node_token:", info.get("parent_node_token") or "")
            print("title:", info.get("title") or "")
            print("url:", info.get("url") or "")

            if args.dump:
                print("\n--- RAW JSON ---")
                print(json.dumps(resp, ensure_ascii=False, indent=2))
            return 0
    except RuntimeError as e:
        msg = str(e)
        err_obj = _try_parse_json(msg.split(": ", 1)[-1])
        err_fields = _extract_error_fields(err_obj) if err_obj else {}
        # Common expired token error from Feishu (seen as HTTP 401 with code 99991677)
        if "99991677" in msg or "Authentication token expired" in msg:
            print("Feishu token expired (HTTP 401 / code=99991677). Please request a new user_access_token and retry.")
            print("\nRecommended: use the provided OAuth helper to refresh the token:")
            print("  python .\\feishu_oauth_get_user_token.py --app-id <cli_xxx> --app-secret <secret>")
            print("\nThen set env and rerun:")
            print('  $env:FEISHU_USER_ACCESS_TOKEN="<new_token>"')
            print('  python .\\feishu_wiki_get_ids.py --url "https://zepp.feishu.cn/wiki/E4NRwVTmkigYl0kjStJcu7eYnAb"')
            return 2
        # Missing required scopes / user authorization for Wiki APIs
        if "99991679" in msg or "permission" in msg.lower() and "wiki:node:read" in msg:
            print("Feishu permission denied (HTTP 400 / code=99991679).")
            print("The app/user has not granted required Wiki scopes. Required one of:")
            print("  - wiki:wiki")
            print("  - wiki:wiki:readonly")
            print("  - wiki:node:read")
            if err_fields.get("log_id"):
                print(f"\nlog_id: {err_fields.get('log_id')}")
            pvs = err_fields.get("permission_violations")
            if isinstance(pvs, list) and pvs:
                missing = sorted({str(x.get('subject') or '').strip() for x in pvs if isinstance(x, dict) and x.get('subject')})
                missing = [x for x in missing if x]
                if missing:
                    print("missing_scopes:")
                    for s in missing:
                        print(f"  - {s}")
            print("\nFix steps:")
            print("1) In Feishu Open Platform console for your app, add the above permissions (scopes).")
            print("2) Re-authorize the user (consent again) to grant the new scopes:")
            print("   python .\\feishu_oauth_get_user_token.py --app-id <cli_xxx> --app-secret <secret>")
            print("3) Set env and retry:")
            print('   $env:FEISHU_USER_ACCESS_TOKEN="<new_token>"')
            print('   python .\\feishu_wiki_get_ids.py --url "https://zepp.feishu.cn/wiki/E4NRwVTmkigYl0kjStJcu7eYnAb"')
            print("\nExtra checks (common pitfalls):")
            print("- Ensure you are authorizing the SAME app_id that has these scopes enabled.")
            print("- If you added scopes after earlier authorization, you must re-consent (sometimes revoke app authorization first).")
            return 3
        raise

    # Fallback: knowledge page.get if user truly has a knowledge page_id
    page_id = (args.page_id or "").strip()
    if not page_id:
        print("Missing node token. Provide --node-token or --url.")
        print("Examples:")
        print('  python .\\feishu_wiki_get_ids.py --show-token --url "https://zepp.feishu.cn/wiki/E4NRwVTmkigYl0kjStJcu7eYnAb"')
        print('  python .\\feishu_wiki_get_ids.py --show-token --node-token "E4NRwVTmkigYl0kjStJcu7eYnAb"')
        return 2

    api_url = f"https://open.feishu.cn/open-apis/knowledge/v1/page/get?page_id={urllib.parse.quote(page_id)}"
    resp = _http_json(method="GET", url=api_url, headers={"Authorization": f"Bearer {token}"}, timeout_sec=int(args.timeout))
    code = int(resp.get("code") or 0)
    if code != 0:
        raise SystemExit(f"API error (knowledge page.get): {resp}")

    data = resp.get("data") or {}
    print("page_id:", page_id)
    # best-effort for knowledge payload
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    print("space_id:", str(page.get("space_id") or "").strip())
    print("title:", str(page.get("title") or "").strip())
    print("url:", str(page.get("url") or "").strip())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
