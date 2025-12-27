#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Trigger Jenkins parameterized builds and wait for completion, then write build URLs back into config JSON.

Default behavior:
- Trigger Release build first
- Immediately trigger Debug build (do not wait for Release completion)
- Monitor both builds until both finish
- Require both results to be SUCCESS
- Update these fields in-place:
    - jenkins.builds.release.build_url
    - jenkins.builds.debug.build_url

Config (minimal):
{
  "jenkins": {
    "base_url": "https://jenkins.example.com",
    "auth": {"type": "basic", "username": "...", "password": "..."},
    "builds": {"release": {"build_url": "..."}, "debug": {"build_url": "..."}},
    "triggers": {
      "job_url": "https://jenkins.example.com/job/.../job/HuamiOS_HS3/",
      "release": {"parameters": {"PRODUCT": "x", "TAG_NAME": "..."}},
      "debug": {"parameters": {"PRODUCT": "x", "TAG_NAME": "..."}}
    }
  }
}

Notes:
- Parameters not present in JSON are not submitted, so Jenkins uses job defaults.
- If Jenkins CSRF is enabled, this script will auto-detect crumb and include it.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import http.cookiejar
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple


@dataclass(frozen=True)
class JenkinsAuth:
    username: str
    password: str


def _now_tag() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _read_json(path: Path) -> Dict[str, Any]:
    raw = path.read_text(encoding="utf-8")
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise RuntimeError("Config JSON must be an object")
    return obj


def _atomic_write_json(path: Path, obj: Dict[str, Any], *, backup: bool) -> None:
    if backup:
        bak = path.with_suffix(path.suffix + f".bak.{_now_tag()}")
        shutil.copy2(path, bak)

    tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _get_by_path(obj: Dict[str, Any], dotted: str) -> Any:
    cur: Any = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            raise KeyError(dotted)
        cur = cur[part]
    return cur


def _set_by_path(obj: Dict[str, Any], dotted: str, value: Any) -> None:
    parts = dotted.split(".")
    cur: Any = obj
    for part in parts[:-1]:
        if not isinstance(cur, dict):
            raise KeyError(dotted)
        if part not in cur or not isinstance(cur[part], dict):
            cur[part] = {}
        cur = cur[part]
    if not isinstance(cur, dict):
        raise KeyError(dotted)
    cur[parts[-1]] = value


def _basic_auth_header(auth: JenkinsAuth) -> str:
    token = (auth.username + ":" + auth.password).encode("utf-8")
    return "Basic " + base64.b64encode(token).decode("ascii")


def _request(
    *,
    method: str,
    url: str,
    headers: Optional[Mapping[str, str]] = None,
    body: Optional[bytes] = None,
    timeout_sec: int = 30,
    opener: Optional[urllib.request.OpenerDirector] = None,
) -> Tuple[int, Mapping[str, str], bytes]:
    req = urllib.request.Request(url, method=method.upper(), data=body)
    for k, v in (headers or {}).items():
        req.add_header(k, v)

    try:
        do = opener.open if opener is not None else urllib.request.urlopen
        with do(req, timeout=timeout_sec) as resp:
            status = int(getattr(resp, "status", 200) or 200)
            data = resp.read() or b""
            return status, dict(resp.headers.items()), data
    except urllib.error.HTTPError as e:
        data = e.read() or b""
        return int(e.code), dict(e.headers.items()), data


def _request_json(
    *,
    method: str,
    url: str,
    headers: Optional[Mapping[str, str]] = None,
    body: Optional[bytes] = None,
    timeout_sec: int = 30,
    opener: Optional[urllib.request.OpenerDirector] = None,
) -> Dict[str, Any]:
    status, _hdrs, data = _request(method=method, url=url, headers=headers, body=body, timeout_sec=timeout_sec, opener=opener)
    if status < 200 or status >= 300:
        text = data.decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {status} calling {url}: {text[:2000]}")
    try:
        return json.loads((data or b"{}").decode("utf-8", errors="replace"))
    except json.JSONDecodeError as e:
        snippet = (data or b"")[:2000].decode("utf-8", errors="replace")
        raise RuntimeError(f"Non-JSON response calling {url}: {e}; body={snippet!r}")


def _http_post_json(
    *,
    url: str,
    payload: Dict[str, Any],
    timeout_sec: int,
    verify_tls: bool,
) -> Tuple[int, str]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(url, method="POST", data=data)
    req.add_header("Content-Type", "application/json; charset=utf-8")

    ctx = None
    if url.lower().startswith("https://") and not verify_tls:
        ctx = ssl._create_unverified_context()

    with urllib.request.urlopen(req, timeout=int(timeout_sec), context=ctx) as resp:
        raw = resp.read() or b""
        text = raw.decode("utf-8", errors="replace")
        return int(getattr(resp, "status", resp.getcode())), text[:2000]


def _get_webhook_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    notif = cfg.get("notifications")
    if not isinstance(notif, dict):
        return {}
    wh = notif.get("webhook")
    if not isinstance(wh, dict):
        return {}
    return wh


def _maybe_notify_webhook_text(
    *,
    cfg: Dict[str, Any],
    text: str,
    request_timeout_sec: int,
) -> None:
    wh = _get_webhook_cfg(cfg)
    if not bool(wh.get("enabled", False)):
        return

    url = str(wh.get("url") or "").strip()
    if not url:
        return

    verify_tls = bool(wh.get("verify_tls", True))
    timeout_sec = int(wh.get("timeout_sec", request_timeout_sec or 10))
    payload = {"text": str(text)}

    try:
        code, _resp = _http_post_json(url=url, payload=payload, timeout_sec=timeout_sec, verify_tls=verify_tls)
        print(f"WebHook notified: HTTP {code}")
    except Exception as e:
        print(f"WARN: failed to notify webhook: {e}", file=sys.stderr)


def _normalize_job_url(job_url: str) -> str:
    u = str(job_url or "").strip()
    if not u:
        return ""
    return u.rstrip("/") + "/"


def _try_get_crumb(
    *,
    base_url: str,
    auth: JenkinsAuth,
    timeout_sec: int,
    opener: Optional[urllib.request.OpenerDirector],
) -> Optional[Tuple[str, str]]:
    base = str(base_url or "").strip().rstrip("/")
    if not base:
        return None
    url = base + "/crumbIssuer/api/json"
    headers = {"Authorization": _basic_auth_header(auth)}
    try:
        resp = _request_json(method="GET", url=url, headers=headers, timeout_sec=timeout_sec, opener=opener)
    except Exception:
        return None

    field = str(resp.get("crumbRequestField") or "").strip()
    crumb = str(resp.get("crumb") or "").strip()
    if not field or not crumb:
        return None
    return field, crumb


def _encode_form_fields(params: Mapping[str, Any]) -> bytes:
    pairs: List[Tuple[str, str]] = []

    def add(k: str, v: Any) -> None:
        kk = str(k)
        if v is None:
            return
        if isinstance(v, bool):
            if not v:
                return
            pairs.append((kk, "true"))
            return
        if isinstance(v, (list, tuple)):
            for it in v:
                if it is None:
                    continue
                s = str(it)
                if s == "":
                    continue
                pairs.append((kk, s))
            return
        s = str(v)
        if s == "":
            # Explicit empty string means override Jenkins default to empty.
            pairs.append((kk, ""))
            return
        pairs.append((kk, s))

    for k, v in params.items():
        add(k, v)

    return urllib.parse.urlencode(pairs, doseq=True).encode("utf-8")


def _resolve_location(base_url: str, location: str) -> str:
    loc = str(location or "").strip()
    if not loc:
        return ""
    if loc.startswith("http://") or loc.startswith("https://"):
        return loc
    base = str(base_url or "").strip().rstrip("/") + "/"
    return urllib.parse.urljoin(base, loc.lstrip("/"))


def _trigger_build(
    *,
    job_url: str,
    base_url: str,
    auth: JenkinsAuth,
    parameters: Mapping[str, Any],
    crumb: Optional[Tuple[str, str]],
    timeout_sec: int,
    dry_run: bool,
    opener: Optional[urllib.request.OpenerDirector],
) -> str:
    job = _normalize_job_url(job_url)
    if not job:
        raise RuntimeError("jenkins.triggers.job_url is missing")

    url = job + "buildWithParameters"
    headers: Dict[str, str] = {
        "Authorization": _basic_auth_header(auth),
        "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
    }
    if crumb:
        headers[crumb[0]] = crumb[1]

    body = _encode_form_fields(parameters)

    if dry_run:
        print(f"DRY-RUN: POST {url}")
        print("DRY-RUN: parameters submitted:")
        for k in sorted(parameters.keys()):
            v = parameters.get(k)
            if isinstance(v, str) and len(v) > 200:
                vv = v[:200] + "..."
            else:
                vv = v
            print(f"  - {k}={vv!r}")
        return ""

    status, hdrs, data = _request(method="POST", url=url, headers=headers, body=body, timeout_sec=timeout_sec, opener=opener)

    if status in (401, 403):
        text = data.decode("utf-8", errors="replace")
        raise RuntimeError(
            f"Jenkins trigger failed (HTTP {status}). "
            f"If CSRF is enabled, ensure crumbIssuer is reachable. body={text[:2000]}"
        )
    if status < 200 or status >= 400:
        text = data.decode("utf-8", errors="replace")
        raise RuntimeError(f"Jenkins trigger failed (HTTP {status}): {text[:2000]}")

    loc = ""
    for hk, hv in hdrs.items():
        if hk.lower() == "location":
            loc = str(hv)
            break

    queue_url = _resolve_location(base_url, loc)
    if not queue_url:
        raise RuntimeError(
            "Jenkins trigger succeeded but did not return Location header for queue item. "
            "Your Jenkins/proxy may be stripping it; fallback matching is not implemented in v1."
        )

    print(f"Queue: {queue_url}")
    return queue_url.rstrip("/") + "/"


def _poll_queue_for_build(
    *,
    queue_url: str,
    auth: JenkinsAuth,
    poll_interval_sec: int,
    queue_timeout_sec: int,
    request_timeout_sec: int,
    opener: Optional[urllib.request.OpenerDirector],
) -> Tuple[int, str]:
    url = queue_url.rstrip("/") + "/api/json"
    headers = {"Authorization": _basic_auth_header(auth)}

    start = time.time()
    while True:
        if time.time() - start > queue_timeout_sec:
            raise TimeoutError(f"Timed out waiting for queue item to start build: {queue_url}")

        resp = _request_json(method="GET", url=url, headers=headers, timeout_sec=request_timeout_sec, opener=opener)
        if bool(resp.get("cancelled")):
            raise RuntimeError(f"Queue item cancelled: {queue_url}")

        execu = resp.get("executable")
        if isinstance(execu, dict) and execu.get("number") is not None:
            num = int(execu.get("number"))
            build_url = str(execu.get("url") or "").strip()
            if build_url:
                return num, build_url.rstrip("/") + "/"
            # If url missing, attempt build_url from task url + number (best effort)
            task = resp.get("task")
            if isinstance(task, dict) and task.get("url"):
                base = str(task.get("url") or "").rstrip("/") + "/"
                return num, base + str(num) + "/"
            return num, ""

        time.sleep(max(1, int(poll_interval_sec)))


def _poll_queues_for_builds(
    *,
    queues: Mapping[str, str],
    auth: JenkinsAuth,
    poll_interval_sec: int,
    queue_timeout_sec: int,
    request_timeout_sec: int,
    opener: Optional[urllib.request.OpenerDirector],
    on_build_started: Optional[Callable[[str, int, str], None]] = None,
) -> Dict[str, Tuple[int, str]]:
    """Poll multiple queue items until each has started a build.

    Returns: {run_name: (build_number, build_url)}
    """

    pending = {str(k): str(v) for k, v in queues.items() if str(k).strip() and str(v).strip()}
    if not pending:
        return {}

    headers = {"Authorization": _basic_auth_header(auth)}
    start = time.time()
    results: Dict[str, Tuple[int, str]] = {}

    while pending:
        if time.time() - start > queue_timeout_sec:
            pretty = ", ".join(f"{k}={v}" for k, v in pending.items())
            raise TimeoutError(f"Timed out waiting for queue items to start builds: {pretty}")

        done: List[str] = []
        # Heartbeat: show we're still polling.
        ts = time.strftime("%H:%M:%S")
        elapsed = int(time.time() - start)
        for run_name, queue_url in pending.items():
            url = queue_url.rstrip("/") + "/api/json"
            resp = _request_json(method="GET", url=url, headers=headers, timeout_sec=request_timeout_sec, opener=opener)
            if bool(resp.get("cancelled")):
                raise RuntimeError(f"Queue item cancelled for {run_name}: {queue_url}")

            execu = resp.get("executable")
            if isinstance(execu, dict) and execu.get("number") is not None:
                num = int(execu.get("number"))
                build_url = str(execu.get("url") or "").strip()
                if not build_url:
                    task = resp.get("task")
                    if isinstance(task, dict) and task.get("url"):
                        base = str(task.get("url") or "").rstrip("/") + "/"
                        build_url = base + str(num) + "/"
                if not build_url:
                    raise RuntimeError(f"Could not determine build_url for {run_name} (build #{num})")
                results[run_name] = (num, build_url.rstrip("/") + "/")
                done.append(run_name)
                if on_build_started is not None:
                    try:
                        on_build_started(run_name, num, results[run_name][1])
                    except Exception:
                        # Best-effort notification; do not break polling.
                        pass

        if pending:
            waiting = ", ".join(f"{k} queue" for k in sorted(pending.keys()))
            print(f"[{ts}] Waiting in queue ({elapsed}s): {waiting}")

        for k in done:
            pending.pop(k, None)

        if pending:
            time.sleep(max(1, int(poll_interval_sec)))

    return results


def _poll_build_result(
    *,
    build_url: str,
    auth: JenkinsAuth,
    poll_interval_sec: int,
    build_timeout_sec: int,
    request_timeout_sec: int,
    opener: Optional[urllib.request.OpenerDirector],
) -> str:
    if not build_url:
        raise RuntimeError("Missing build_url to poll")

    url = build_url.rstrip("/") + "/api/json"
    headers = {"Authorization": _basic_auth_header(auth)}

    start = time.time()
    last_state = ""
    while True:
        if time.time() - start > build_timeout_sec:
            raise TimeoutError(f"Timed out waiting for build to finish: {build_url}")

        resp = _request_json(method="GET", url=url, headers=headers, timeout_sec=request_timeout_sec, opener=opener)
        building = bool(resp.get("building"))
        result = str(resp.get("result") or "").strip()
        display_name = str(resp.get("displayName") or "").strip()
        if building:
            state = display_name or ("building" if not result else f"building({result})")
            if state != last_state:
                print(f"Build running: {build_url} ({state})")
                last_state = state
            time.sleep(max(1, int(poll_interval_sec)))
            continue

        if not result:
            # Some Jenkins may briefly show building=false and result=null. Retry.
            time.sleep(max(1, int(poll_interval_sec)))
            continue

        return result


def _poll_build_results(
    *,
    builds: Mapping[str, Tuple[int, str]],
    auth: JenkinsAuth,
    poll_interval_sec: int,
    build_timeout_sec: int,
    request_timeout_sec: int,
    opener: Optional[urllib.request.OpenerDirector],
    on_build_finished: Optional[Callable[[str, int, str, str], None]] = None,
) -> Dict[str, str]:
    """Poll multiple builds until each has finished.

    builds: {run_name: (build_number, build_url)}
    returns: {run_name: result}
    """

    pending: Dict[str, Tuple[int, str]] = {
        str(k): (int(v[0]), str(v[1]))
        for k, v in builds.items()
        if str(k).strip() and isinstance(v, tuple) and len(v) == 2 and str(v[1]).strip()
    }
    if not pending:
        return {}

    headers = {"Authorization": _basic_auth_header(auth)}
    start = time.time()
    results: Dict[str, str] = {}
    last_states: Dict[str, str] = {}

    while pending:
        if time.time() - start > build_timeout_sec:
            pretty = ", ".join(f"{k}={v[1]}" for k, v in pending.items())
            raise TimeoutError(f"Timed out waiting for builds to finish: {pretty}")

        done: List[str] = []
        ts = time.strftime("%H:%M:%S")
        elapsed = int(time.time() - start)
        heartbeat: Dict[str, str] = {}
        for run_name, (num, build_url) in pending.items():
            url = build_url.rstrip("/") + "/api/json"
            resp = _request_json(method="GET", url=url, headers=headers, timeout_sec=request_timeout_sec, opener=opener)

            building = bool(resp.get("building"))
            result = str(resp.get("result") or "").strip()
            display_name = str(resp.get("displayName") or "").strip()

            if building:
                state = display_name or "building"
                if last_states.get(run_name) != state:
                    print(f"Build running: {run_name} #{num} {build_url} ({state})")
                    last_states[run_name] = state
                heartbeat[run_name] = "building"
                continue

            if not result:
                # Some Jenkins may briefly show building=false and result=null. Retry.
                heartbeat[run_name] = "finishing"
                continue

            results[run_name] = result
            done.append(run_name)
            heartbeat[run_name] = result
            if on_build_finished is not None:
                try:
                    on_build_finished(run_name, num, build_url, result)
                except Exception:
                    # Best-effort notification; do not break polling.
                    pass

        if pending:
            parts = []
            for k in sorted(pending.keys()):
                parts.append(f"{k}={heartbeat.get(k,'polling')}")
            print(f"[{ts}] Polling builds ({elapsed}s): " + ", ".join(parts))

        for k in done:
            pending.pop(k, None)

        if pending:
            time.sleep(max(1, int(poll_interval_sec)))

    return results


def _get_auth_from_cfg(cfg: Dict[str, Any]) -> JenkinsAuth:
    j = cfg.get("jenkins") or {}
    if not isinstance(j, dict):
        j = {}
    a = j.get("auth") or {}
    if not isinstance(a, dict):
        a = {}

    username = str(a.get("username") or os.environ.get("JENKINS_USERNAME") or "").strip()
    password = str(a.get("password") or os.environ.get("JENKINS_PASSWORD") or "").strip()
    if not username or not password:
        raise RuntimeError("Missing Jenkins basic auth (jenkins.auth.username/password or env JENKINS_USERNAME/JENKINS_PASSWORD)")
    return JenkinsAuth(username=username, password=password)


def _get_jenkins_base_url(cfg: Dict[str, Any]) -> str:
    j = cfg.get("jenkins") or {}
    if not isinstance(j, dict):
        j = {}
    return str(j.get("base_url") or "").strip()


def _get_triggers_cfg(cfg: Dict[str, Any]) -> Dict[str, Any]:
    j = cfg.get("jenkins") or {}
    if not isinstance(j, dict):
        j = {}
    t = j.get("triggers") or {}
    if not isinstance(t, dict):
        t = {}
    return t


def _get_trigger_params(cfg: Dict[str, Any], run_name: str) -> Dict[str, Any]:
    tcfg = _get_triggers_cfg(cfg)
    run_cfg = tcfg.get(run_name) or {}
    if not isinstance(run_cfg, dict):
        run_cfg = {}
    params = run_cfg.get("parameters") or {}
    if not isinstance(params, dict):
        raise RuntimeError(f"jenkins.triggers.{run_name}.parameters must be an object")
    return params


def main() -> int:
    ap = argparse.ArgumentParser(description="Trigger Jenkins builds (release then debug) and write build_url back into JSON")
    ap.add_argument("--config", required=True, help="Path to release_pipeline config JSON")
    ap.add_argument("--no-backup", action="store_true", help="Do not write .bak backup before overwriting config")
    ap.add_argument(
        "--dry-run",
        action="store_true",
        help="Do not trigger Jenkins; only print what would be posted",
    )

    ap.add_argument(
        "--use-existing-build-urls",
        action="store_true",
        help="Do not trigger Jenkins. Use existing jenkins.builds.{release,debug}.build_url from config; poll until finished and then optionally run pipeline.",
    )
    ap.add_argument(
        "--mock-build-success",
        action="store_true",
        help="Do not trigger Jenkins and do not poll. Pretend both builds are SUCCESS (useful to test --run-pipeline handoff).",
    )

    ap.add_argument(
        "--preauth-feishu",
        action="store_true",
        help="Run Feishu OAuth pre-auth now (via release_pipeline_run.py --feishu-preauth-only) before triggering long builds.",
    )
    ap.add_argument(
        "--preauth-feishu-force",
        action="store_true",
        help="Force Feishu OAuth even if user_access_token already exists.",
    )

    ap.add_argument("--poll-interval-sec", type=int, default=5, help="Polling interval for queue/build status")
    ap.add_argument("--queue-timeout-sec", type=int, default=20 * 60, help="Max seconds to wait in Jenkins queue")
    ap.add_argument("--build-timeout-sec", type=int, default=3 * 60 * 60, help="Max seconds to wait for build to finish")
    ap.add_argument("--request-timeout-sec", type=int, default=30, help="Timeout for individual HTTP requests")

    ap.add_argument(
        "--run-pipeline",
        action="store_true",
        help="After builds finish SUCCESS and config is updated, run release_pipeline_run.py to continue download/upload/doc/feishu.",
    )
    ap.add_argument(
        "--pipeline-script",
        default="",
        help="Path to release_pipeline_run.py (default: sibling of this script).",
    )
    ap.add_argument(
        "--pipeline-args",
        action="append",
        default=[],
        help="Extra args passed to release_pipeline_run.py (repeatable). Example: --pipeline-args=--skip-feishu",
    )

    args = ap.parse_args()

    if bool(args.use_existing_build_urls) and bool(args.mock_build_success):
        print("ERROR: --use-existing-build-urls and --mock-build-success are mutually exclusive", file=sys.stderr)
        return 2

    cfg_path = Path(str(args.config)).expanduser().resolve()
    if not cfg_path.exists():
        print(f"Config not found: {cfg_path}", file=sys.stderr)
        return 2

    cfg = _read_json(cfg_path)

    def _cfg_get(dotted: str, default: Any) -> Any:
        try:
            return _get_by_path(cfg, dotted)
        except KeyError:
            return default

    def _cfg_bool(dotted: str, default: bool = False) -> bool:
        return bool(_cfg_get(dotted, default))

    # Optional: pre-auth Feishu OAuth before doing anything long-running.
    if bool(args.preauth_feishu) or _cfg_bool("jenkins.triggers.preauth_feishu", False):
        script = str(Path(__file__).with_name("release_pipeline_run.py"))
        cmd = [sys.executable, script, "--config", str(cfg_path), "--feishu-preauth-only"]
        if bool(args.preauth_feishu_force):
            cmd.append("--feishu-preauth-force")
        print("\n== Feishu PRE-AUTH ==")
        print(" ".join(cmd))
        p = subprocess.run(cmd)
        if int(p.returncode) != 0:
            raise RuntimeError(f"Feishu pre-auth failed with exit code {p.returncode}")

    wh = _get_webhook_cfg(cfg)
    wh_enabled = bool(wh.get("enabled", False))
    wh_url = str(wh.get("url") or "").strip()
    if wh_enabled and wh_url:
        print(f"WebHook enabled: {wh_url}")
    elif wh_enabled and not wh_url:
        print("WebHook enabled but url is empty (no notifications will be sent)")
    else:
        print("WebHook disabled (set notifications.webhook.enabled=true to enable)")

    # Keep cookies across crumb -> build trigger -> polling requests.
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

    # Validate triggers config (only needed when actually triggering builds)
    if not bool(args.use_existing_build_urls) and not bool(args.mock_build_success):
        tcfg = _get_triggers_cfg(cfg)
        if not str(tcfg.get("job_url") or "").strip():
            print("Missing jenkins.triggers.job_url", file=sys.stderr)
            return 2

    # Jenkins auth/crumb are only needed when triggering or polling real builds.
    auth: Optional[JenkinsAuth] = None
    crumb: Optional[Tuple[str, str]] = None
    if not bool(args.mock_build_success):
        base_url = _get_jenkins_base_url(cfg)
        auth = _get_auth_from_cfg(cfg)
        crumb = _try_get_crumb(base_url=base_url, auth=auth, timeout_sec=int(args.request_timeout_sec), opener=opener)
        if crumb:
            print(f"CSRF crumb detected: {crumb[0]}")
        else:
            print("CSRF crumb not detected (continuing)")
    else:
        print("CSRF crumb check skipped (mock mode)")

    try:
        # Trigger release first, then debug immediately (no waiting between them), unless using mock/existing-build modes.
        q_release = ""
        q_debug = ""
        if not bool(args.use_existing_build_urls) and not bool(args.mock_build_success):
            tcfg = _get_triggers_cfg(cfg)
            job_url = str(tcfg.get("job_url") or "").strip()
            if not job_url:
                raise RuntimeError("Missing jenkins.triggers.job_url")

            base_url = _get_jenkins_base_url(cfg)
            auth = _get_auth_from_cfg(cfg)

            print("\n== Trigger RELEASE ==")
            q_release = _trigger_build(
                job_url=job_url,
                base_url=base_url,
                auth=auth,
                parameters=_get_trigger_params(cfg, "release"),
                crumb=crumb,
                timeout_sec=int(args.request_timeout_sec),
                dry_run=bool(args.dry_run),
                opener=opener,
            )

            print("\n== Trigger DEBUG ==")
            q_debug = _trigger_build(
                job_url=job_url,
                base_url=base_url,
                auth=auth,
                parameters=_get_trigger_params(cfg, "debug"),
                crumb=crumb,
                timeout_sec=int(args.request_timeout_sec),
                dry_run=bool(args.dry_run),
                opener=opener,
            )

        auto_run_pipeline = bool(args.run_pipeline) or _cfg_bool("jenkins.triggers.auto_run_pipeline", False)

        def _resolve_pipeline_script() -> str:
            script = str(args.pipeline_script or "").strip()
            if script:
                return script
            script = str(_cfg_get("jenkins.triggers.pipeline_script", "")).strip()
            if script:
                return script
            return str(Path(__file__).with_name("release_pipeline_run.py"))

        def _resolve_pipeline_args() -> List[str]:
            cfg_args = _cfg_get("jenkins.triggers.pipeline_args", [])
            if not isinstance(cfg_args, list):
                cfg_args = []
            cli_args = args.pipeline_args or []
            merged = [str(x) for x in cfg_args if str(x).strip()] + [str(x) for x in cli_args if str(x).strip()]
            return merged

        if args.dry_run:
            if auto_run_pipeline:
                script = _resolve_pipeline_script()
                cmd = [sys.executable, script, "--config", str(cfg_path)] + _resolve_pipeline_args()
                print("\nDRY-RUN: would run pipeline:")
                print("  " + " ".join(cmd))
            else:
                print("\nDRY-RUN: pipeline auto-run is disabled (use --run-pipeline or set jenkins.triggers.auto_run_pipeline=true)")
            return 0

        def _notify_started(run_name: str, num: int, build_url: str) -> None:
            _maybe_notify_webhook_text(
                cfg=cfg,
                text=f"Jenkins {run_name} started: #{num} {build_url}",
                request_timeout_sec=int(args.request_timeout_sec),
            )

        def _notify_finished(run_name: str, num: int, build_url: str, result: str) -> None:
            _maybe_notify_webhook_text(
                cfg=cfg,
                text=f"Jenkins {run_name} finished: #{num} result={result} {build_url}",
                request_timeout_sec=int(args.request_timeout_sec),
            )

        builds: Dict[str, Tuple[int, str]] = {}
        results: Dict[str, str] = {}

        if bool(args.mock_build_success):
            rel_url = str(((cfg.get("jenkins") or {}).get("builds") or {}).get("release", {}).get("build_url") or "").strip()
            dbg_url = str(((cfg.get("jenkins") or {}).get("builds") or {}).get("debug", {}).get("build_url") or "").strip()
            builds = {
                "release": (0, rel_url),
                "debug": (0, dbg_url),
            }
            results = {
                "release": "SUCCESS",
                "debug": "SUCCESS",
            }
            print("\nMOCK: skipping Jenkins trigger/poll; assuming release=SUCCESS debug=SUCCESS")

            # In mock mode there is no polling loop, so explicitly notify once.
            _maybe_notify_webhook_text(
                cfg=cfg,
                text=f"Jenkins release finished (MOCK): result=SUCCESS {rel_url}",
                request_timeout_sec=int(args.request_timeout_sec),
            )
            _maybe_notify_webhook_text(
                cfg=cfg,
                text=f"Jenkins debug finished (MOCK): result=SUCCESS {dbg_url}",
                request_timeout_sec=int(args.request_timeout_sec),
            )

        elif bool(args.use_existing_build_urls):
            # Use existing build URLs from config and poll until finished.
            if auth is None:
                auth = _get_auth_from_cfg(cfg)
            rel_url = str(((cfg.get("jenkins") or {}).get("builds") or {}).get("release", {}).get("build_url") or "").strip()
            dbg_url = str(((cfg.get("jenkins") or {}).get("builds") or {}).get("debug", {}).get("build_url") or "").strip()
            if not rel_url or not dbg_url:
                raise RuntimeError("--use-existing-build-urls requires jenkins.builds.release.build_url and jenkins.builds.debug.build_url in config")

            # Best-effort build numbers from URL suffix.
            def _url_to_num(u: str) -> int:
                parts = str(u or "").strip().rstrip("/").split("/")
                if parts and parts[-1].isdigit():
                    return int(parts[-1])
                return 0

            builds = {
                "release": (_url_to_num(rel_url), rel_url.rstrip("/") + "/"),
                "debug": (_url_to_num(dbg_url), dbg_url.rstrip("/") + "/"),
            }
            print("\n== Using existing build URLs from config ==")
            print(f"- release: {builds['release'][1]}")
            print(f"- debug:   {builds['debug'][1]}")

            results = _poll_build_results(
                builds=builds,
                auth=auth,
                poll_interval_sec=int(args.poll_interval_sec),
                build_timeout_sec=int(args.build_timeout_sec),
                request_timeout_sec=int(args.request_timeout_sec),
                opener=opener,
                on_build_finished=_notify_finished,
            )

        else:
            if auth is None:
                auth = _get_auth_from_cfg(cfg)
            builds = _poll_queues_for_builds(
                queues={"release": q_release, "debug": q_debug},
                auth=auth,
                poll_interval_sec=int(args.poll_interval_sec),
                queue_timeout_sec=int(args.queue_timeout_sec),
                request_timeout_sec=int(args.request_timeout_sec),
                opener=opener,
                on_build_started=_notify_started,
            )

            rel_num, rel_url = builds["release"]
            dbg_num, dbg_url = builds["debug"]
            print("\nBuilds started:")
            print(f"- release: #{rel_num} {rel_url}")
            print(f"- debug:   #{dbg_num} {dbg_url}")

            results = _poll_build_results(
                builds=builds,
                auth=auth,
                poll_interval_sec=int(args.poll_interval_sec),
                build_timeout_sec=int(args.build_timeout_sec),
                request_timeout_sec=int(args.request_timeout_sec),
                opener=opener,
                on_build_finished=_notify_finished,
            )

        print("\nBuilds finished:")
        for run_name in ("release", "debug"):
            build_url = str(builds.get(run_name, (0, ""))[1] or "")
            print(f"- {run_name}: {build_url} result={results.get(run_name, '')}")

        # Always write back build URLs if we have them.
        rel_url = str(builds.get("release", (0, ""))[1] or "").strip()
        dbg_url = str(builds.get("debug", (0, ""))[1] or "").strip()
        if rel_url:
            _set_by_path(cfg, "jenkins.builds.release.build_url", rel_url)
        if dbg_url:
            _set_by_path(cfg, "jenkins.builds.debug.build_url", dbg_url)
        _atomic_write_json(cfg_path, cfg, backup=not bool(args.no_backup))

        if results.get("release") != "SUCCESS" or results.get("debug") != "SUCCESS":
            if auto_run_pipeline:
                print("\nPipeline was NOT started because Jenkins results are not all SUCCESS.")
            raise RuntimeError(
                f"Build results not all SUCCESS: release={results.get('release')} debug={results.get('debug')}"
            )

        print("\nUpdated config build URLs:")
        rel_num_out = int(builds.get("release", (0, ""))[0] or 0)
        dbg_num_out = int(builds.get("debug", (0, ""))[0] or 0)
        print(f"- release: {rel_url} (# {rel_num_out })")
        print(f"- debug:   {dbg_url} (# {dbg_num_out })")

        if auto_run_pipeline:
            script = _resolve_pipeline_script()
            cmd = [sys.executable, script, "--config", str(cfg_path)] + _resolve_pipeline_args()
            print("\n== Run PIPELINE ==")
            print(" ".join(cmd))

            _maybe_notify_webhook_text(
                cfg=cfg,
                text="Release pipeline starting: " + " ".join(cmd),
                request_timeout_sec=int(args.request_timeout_sec),
            )

            p = subprocess.run(cmd)
            if int(p.returncode) != 0:
                _maybe_notify_webhook_text(
                    cfg=cfg,
                    text=f"Release pipeline failed: exit_code={int(p.returncode)}",
                    request_timeout_sec=int(args.request_timeout_sec),
                )
                raise RuntimeError(f"release_pipeline_run.py failed with exit code {p.returncode}")

            _maybe_notify_webhook_text(
                cfg=cfg,
                text="Release pipeline finished: exit_code=0",
                request_timeout_sec=int(args.request_timeout_sec),
            )
        else:
            print("\nPipeline auto-run is disabled; not running release pipeline.")

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 3

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
