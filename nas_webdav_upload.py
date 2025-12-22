#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import json
import mimetypes
import os
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional, Tuple
from urllib.parse import quote


def _curl_bin() -> str:
    return "curl.exe" if os.name == "nt" else "curl"


@dataclass(frozen=True)
class UploadConfig:
    nas_base_url: str
    username: str
    password: str
    remote_base_dir: str
    folder_name: str
    local_dir: str
    verify_tls: bool = False
    timeout_sec: int = 60


def _norm_base_url(url: str) -> str:
    return url.rstrip("/")


def _norm_remote_path(path: str) -> str:
    # Expect absolute WebDAV path; allow user to omit leading slash.
    p = path.strip()
    if not p.startswith("/"):
        p = "/" + p
    # Keep trailing slash for directory paths.
    return p


def _join_remote(base: str, sub: str) -> str:
    base = base.rstrip("/")
    sub = sub.strip("/")
    if not sub:
        return base + "/"
    return base + "/" + sub + "/"


def _encode_path(path: str) -> str:
    # Encode as UTF-8 percent-encoding, keep slashes.
    return quote(path, safe="/")


def _remote_url(nas_base_url: str, remote_path: str) -> str:
    # remote_path must start with '/'
    return _norm_base_url(nas_base_url) + _encode_path(remote_path)


def _iter_files(local_root: Path) -> Iterable[Tuple[Path, str]]:
    # Yields (absolute_path, relative_posix_path)
    for p in sorted(local_root.rglob("*")):
        if p.is_file():
            rel = p.relative_to(local_root).as_posix()
            yield p, rel


class WebDavClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        verify_tls: bool,
        timeout_sec: int,
        show_progress: bool = False,
    ):
        self._base_url = _norm_base_url(base_url)
        self._verify_tls = verify_tls
        self._timeout_sec = timeout_sec
        self._show_progress = show_progress
        self._username = username
        self._password = password
        self._netrc_path: Optional[str] = None

    def __enter__(self) -> "WebDavClient":
        # Use a temporary netrc file so credentials never appear in process args.
        # curl will read this for Basic auth.
        tmp = tempfile.NamedTemporaryFile("w", prefix="webdav_netrc_", delete=False)
        try:
            # netrc expects machine without scheme/port; Synology uses host-based auth.
            host = self._base_url.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            tmp.write(f"machine {host}\n")
            tmp.write(f"  login {self._username}\n")
            tmp.write(f"  password {self._password}\n")
            tmp.flush()
            os.chmod(tmp.name, 0o600)
            self._netrc_path = tmp.name
        finally:
            tmp.close()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        if self._netrc_path:
            try:
                os.unlink(self._netrc_path)
            except OSError:
                pass
            self._netrc_path = None

    def _curl(
        self,
        *,
        method: str,
        url: str,
        data: Optional[bytes] = None,
        upload_file: Optional[Path] = None,
        headers: Optional[dict] = None,
        ok_codes: Tuple[int, ...] = (200,),
    ) -> None:
        if not self._netrc_path:
            raise RuntimeError("WebDavClient not initialized (missing netrc). Use as a context manager.")

        cmd = [
            _curl_bin(),
            "--show-error",
            "--location",  # follow redirects within same host
            "--compressed",
            "--netrc-file",
            self._netrc_path,
            "--request",
            method,
            "--connect-timeout",
            "10",
            "--max-time",
            str(int(self._timeout_sec)),
        ]
        # Only show progress for actual file transfers.
        if self._show_progress and upload_file is not None:
            cmd.append("--progress-bar")
        else:
            cmd.append("--silent")
        if not self._verify_tls:
            cmd.append("--insecure")

        # Add headers
        if headers:
            for k, v in headers.items():
                cmd.extend(["--header", f"{k}: {v}"])

        # Request body
        if data is not None:
            cmd.extend(["--data-binary", "@-"])

        # Upload file
        if upload_file is not None:
            cmd.extend(["--upload-file", str(upload_file)])

        # Capture http code
        cmd.extend(["--output", os.devnull, "--write-out", "%{http_code}", url])

        proc = subprocess.run(
            cmd,
            input=data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        if proc.returncode != 0:
            stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
            raise RuntimeError(
                f"curl {method} failed: rc={proc.returncode} url={url} stderr={stderr.strip()[:800]}"
            )
        http_code_text = (proc.stdout or b"").decode("utf-8", errors="replace").strip()
        try:
            http_code = int(http_code_text)
        except ValueError:
            http_code = 0

        if http_code in ok_codes:
            return

        stderr = (proc.stderr or b"").decode("utf-8", errors="replace")
        raise RuntimeError(f"curl {method} failed: status={http_code} url={url} stderr={stderr.strip()[:800]}")

    def mkcol(self, remote_dir_path: str) -> None:
        # remote_dir_path must end with '/'
        if not remote_dir_path.endswith("/"):
            remote_dir_path += "/"
        url = _remote_url(self._base_url, remote_dir_path)
        # 201 Created (ok), 405 Method Not Allowed (already exists), 200/204 (some servers)
        self._curl(method="MKCOL", url=url, ok_codes=(200, 201, 204, 405))

    def ensure_dir_tree(self, remote_dir_path: str) -> None:
        # Create each level under remote_dir_path
        p = _norm_remote_path(remote_dir_path)
        if not p.endswith("/"):
            p += "/"

        # Split into segments while preserving leading '/'
        # Example: /a/b/c/ -> ['', 'a', 'b', 'c', '']
        segments = [seg for seg in p.split("/") if seg]
        current = "/"
        for seg in segments:
            current = _join_remote(current, seg)
            self.mkcol(current)

    def put_file(self, remote_file_path: str, local_file: Path) -> None:
        url = _remote_url(self._base_url, _norm_remote_path(remote_file_path))
        content_type, _ = mimetypes.guess_type(str(local_file))
        headers = {}
        if content_type:
            headers["Content-Type"] = content_type

        # curl uses PUT when --upload-file is specified.
        self._curl(method="PUT", url=url, upload_file=local_file, headers=headers, ok_codes=(200, 201, 204))


def load_config(path: Path) -> UploadConfig:
    text: Optional[str] = None
    for enc in ("utf-8", "utf-8-sig", "mbcs", "gbk"):
        try:
            text = path.read_text(encoding=enc)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        # Last resort: replace undecodable bytes
        text = path.read_text(encoding="utf-8", errors="replace")

    data = json.loads(text)
    return UploadConfig(
        nas_base_url=str(data["nas_base_url"]),
        username=str(data["username"]),
        password=str(data.get("password", "")),
        remote_base_dir=str(data["remote_base_dir"]),
        folder_name=str(data["folder_name"]),
        local_dir=str(data["local_dir"]),
        verify_tls=bool(data.get("verify_tls", False)),
        timeout_sec=int(data.get("timeout_sec", 60)),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Upload a local folder to Synology DSM WebDAV.")
    parser.add_argument("--config", required=True, help="Path to JSON config")
    parser.add_argument("--dry-run", action="store_true", help="Print actions without uploading")
    parser.add_argument("--progress", action="store_true", help="Show curl progress (speed/ETA) for uploads")
    args = parser.parse_args()

    cfg = load_config(Path(args.config))

    password = cfg.password.strip()
    if not password:
        password = (os.environ.get("NAS_PASSWORD") or os.environ.get("WEBDAV_PASS") or "").strip()
    if not password:
        raise SystemExit('Missing password. Provide it via config JSON "password" or env NAS_PASSWORD/WEBDAV_PASS.')

    local_root = Path(cfg.local_dir).expanduser().resolve()
    if not local_root.is_dir():
        raise SystemExit(f"local_dir not found or not a directory: {local_root}")

    remote_base = _norm_remote_path(cfg.remote_base_dir)
    remote_target_dir = _join_remote(remote_base, cfg.folder_name)

    print(f"NAS: {cfg.nas_base_url}")
    print(f"Remote base: {remote_base}")
    print(f"Create/upload to: {remote_target_dir}")
    print(f"Local dir: {local_root}")

    client = WebDavClient(
        cfg.nas_base_url,
        cfg.username,
        password,
        verify_tls=cfg.verify_tls,
        timeout_sec=cfg.timeout_sec,
        show_progress=bool(args.progress),
    )

    # Ensure the temporary netrc is created and cleaned up.
    with client:
        if args.dry_run:
            print("[dry-run] would MKCOL ensure:", remote_target_dir)
        else:
            client.ensure_dir_tree(remote_target_dir)

        ensured_dirs = {remote_target_dir}

        files = list(_iter_files(local_root))
        if not files:
            print("No files to upload.")
            return 0

        for idx, (abs_path, rel_posix) in enumerate(files, start=1):
            remote_file = remote_target_dir.rstrip("/") + "/" + rel_posix
            remote_parent = os.path.dirname(remote_file)
            if not remote_parent.endswith("/"):
                remote_parent += "/"

            print(f"[{idx}/{len(files)}] {rel_posix} -> {remote_file}")
            if args.dry_run:
                continue

            # Ensure parent dir exists for nested files (avoid repeated MKCOL)
            if remote_parent not in ensured_dirs:
                client.ensure_dir_tree(remote_parent)
                ensured_dirs.add(remote_parent)
            client.put_file(remote_file, abs_path)

    print("Upload complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
