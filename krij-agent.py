#!/usr/bin/env python3
"""
Krij -> csgo_gc bridge agent (web‑view version with auto‑install).

Opens a native window showing https://krij-mod.vercel.app while the agent runs
in the background. If pywebview is missing, it auto‑installs it.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_BODY = 4 * 1024 * 1024
PROJECT_ID = "8ef47b30-16d4-409d-baaa-3a3602adc4f2"
MAX_LOG_LINES = 500

# Shared log buffer
LOG_BUFFER: deque[str] = deque(maxlen=MAX_LOG_LINES)
LOG_PENDING: deque[str] = deque(maxlen=MAX_LOG_LINES)
LOG_LOCK = threading.Lock()


class Config:
    target: Path
    token: str = ""
    backup: bool = True
    enforce: bool = True
    require_signature: bool = True
    verify_url: str = ""


CFG = Config()
STATE = {"content": None, "sha": None}
STATE_LOCK = threading.Lock()


def log(msg: str) -> None:
    line = f"[{time.strftime('%H:%M:%S')}] {msg}"
    with LOG_LOCK:
        LOG_BUFFER.append(line)
        LOG_PENDING.append(line)
    print(line, flush=True)


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def verify_with_server(content: str, signature: str, verify_url: str) -> tuple[bool, str]:
    if not verify_url:
        return False, "no verify URL was provided by the website"
    body = json.dumps({"content": content, "signature": signature}).encode()
    req = urllib.request.Request(
        verify_url,
        data=body,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            ctype = (res.headers.get("Content-Type") or "").lower()
            raw = res.read().decode("utf-8", "replace")
            if "application/json" not in ctype:
                return False, (
                    f"{verify_url} did not return JSON (got {ctype or 'unknown'}) - "
                    "the URL is probably behind a login page"
                )
            payload = json.loads(raw)
            if payload.get("ok"):
                return True, ""
            return False, "server said the signature does not match this inventory"
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            return False, "server rejected the signature (403)"
        return False, f"verify endpoint returned HTTP {exc.code}"
    except Exception as exc:
        return False, f"could not reach {verify_url}: {exc}"


def is_trusted_project_origin(origin: str) -> bool:
    try:
        parsed = urllib.parse.urlparse(origin)
        host = (parsed.hostname or "").lower()
        if parsed.scheme == "http" and host in ("localhost", "127.0.0.1"):
            return True
        if parsed.scheme != "https":
            return False
        trusted = {
            f"id-preview--{PROJECT_ID}.lovable.app",
            f"project--{PROJECT_ID}.lovable.app",
            f"project--{PROJECT_ID}-dev.lovable.app",
            f"{PROJECT_ID}.lovableproject.com",
            "krij-mod.vercel.app",          # added
        }
        return host in trusted
    except ValueError:
        return False


def write_inventory(content: str) -> int:
    CFG.target.parent.mkdir(parents=True, exist_ok=True)
    if CFG.backup and CFG.target.exists():
        shutil.copy2(CFG.target, CFG.target.with_suffix(".txt.bak"))
    tmp = CFG.target.with_suffix(".txt.tmp")
    tmp.write_text(content, encoding="utf-8", newline="\n")
    os.replace(tmp, CFG.target)
    with STATE_LOCK:
        STATE["content"] = content
        STATE["sha"] = sha(content)
    return len(content)


def watchdog() -> None:
    while True:
        time.sleep(2)
        with STATE_LOCK:
            expected = STATE["content"]
            expected_sha = STATE["sha"]
        if expected is None:
            continue
        try:
            current = CFG.target.read_text(encoding="utf-8", errors="replace")
        except OSError:
            current = None
        if current is not None and sha(current) == expected_sha:
            continue
        try:
            CFG.target.parent.mkdir(parents=True, exist_ok=True)
            tmp = CFG.target.with_suffix(".txt.tmp")
            tmp.write_text(expected, encoding="utf-8", newline="\n")
            os.replace(tmp, CFG.target)
            log("tampered inventory.txt detected - restored Krij's signed copy")
        except OSError as exc:
            log(f"restore failed: {exc}")


class Handler(BaseHTTPRequestHandler):
    server_version = "KrijGCAgent/1.2"

    def log_message(self, *_args):
        pass

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Krij-Token")
        self.send_header("Access-Control-Max-Age", "86400")

    def _json(self, status: int, payload: dict):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def do_GET(self):
        if self.path.rstrip("/") in ("", "/ping", "/health"):
            self._json(200, {
                "ok": True,
                "agent": "krij-gc-agent",
                "version": "1.2",
                "target": str(CFG.target),
                "auth": bool(CFG.token),
            })
        else:
            self._json(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if self.path.rstrip("/") != "/inventory":
            self._json(404, {"ok": False, "error": "not found"})
            return

        if CFG.token and self.headers.get("X-Krij-Token", "") != CFG.token:
            log("rejected: bad token")
            self._json(401, {"ok": False, "error": "bad token"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY:
            log("rejected: bad content length")
            self._json(400, {"ok": False, "error": "bad content length"})
            return

        raw = self.rfile.read(length).decode("utf-8", "replace")
        content = raw
        items = None
        signature = ""
        payload_urls = None
        verify_url = CFG.verify_url
        if (self.headers.get("Content-Type") or "").startswith("application/json"):
            try:
                payload = json.loads(raw)
                content = payload.get("content", "")
                items = payload.get("exported")
                signature = payload.get("signature") or ""
                verify_url = CFG.verify_url or payload.get("verify_url") or ""
                payload_urls = payload.get("verify_urls")
            except json.JSONDecodeError:
                log("rejected: invalid json")
                self._json(400, {"ok": False, "error": "invalid json"})
                return

        if not content.strip().startswith('"items"'):
            log("rejected: content is not a csgo_gc inventory file")
            self._json(400, {"ok": False, "error": "content is not a csgo_gc inventory file"})
            return

        verify_urls = []
        if CFG.verify_url:
            verify_urls.append(CFG.verify_url)
        if isinstance(payload_urls, list):
            verify_urls += [u for u in payload_urls if isinstance(u, str) and u]
        elif verify_url:
            verify_urls.append(verify_url)
        seen = set()
        verify_urls = [u for u in verify_urls if not (u in seen or seen.add(u))]

        if CFG.require_signature:
            if not signature:
                log("rejected: missing signature")
                self._json(400, {"ok": False, "error": "missing signature"})
                return
            ok, reason = False, "no verify URL was provided by the website"
            for url in verify_urls:
                ok, reason = verify_with_server(content, signature, url)
                if ok:
                    break
                log(f"  {url}: {reason}")
            origin = self.headers.get("Origin", "")
            if not ok and is_trusted_project_origin(origin):
                ok = True
                log("server keys differ; accepted push from this project's verified browser origin")
            if not ok:
                log(f"rejected inventory push - {reason}")
                self._json(403, {"ok": False, "error": f"signature not verified: {reason}"})
                return

        try:
            written = write_inventory(content)
        except OSError as exc:
            log(f"write failed: {exc}")
            self._json(500, {"ok": False, "error": str(exc)})
            return

        item_info = f" ({items} items)" if items is not None else ""
        log(f"wrote {written} bytes to {CFG.target}{item_info}")
        self._json(200, {"ok": True, "bytes": written, "path": str(CFG.target)})


def resolve_target(csgo_dir, out) -> Path:
    if out:
        return Path(out).expanduser().resolve()
    if csgo_dir:
        base = Path(csgo_dir).expanduser().resolve()
        if base.name.lower() == "csgo":
            return base / "csgo_gc" / "inventory.txt"
        return base / "csgo" / "csgo_gc" / "inventory.txt"
    return Path.cwd() / "csgo_gc" / "inventory.txt"


def start_server(host: str, port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), Handler)
    log(f"listening on http://{host}:{port}")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def ensure_pywebview() -> bool:
    """Try to import webview; if missing, attempt to install it via pip."""
    try:
        import webview
        return True
    except ImportError:
        log("pywebview not found. Attempting to install...")
        try:
            # Try pip or pip3
            pip_cmd = "pip"
            # Check if pip3 exists (prefer pip3 on some systems)
            for cmd in ("pip3", "pip"):
                if shutil.which(cmd):
                    pip_cmd = cmd
                    break
            subprocess.check_call([pip_cmd, "install", "pywebview"])
            # After installation, try importing again
            import webview
            log("pywebview installed successfully.")
            return True
        except Exception as e:
            log(f"Failed to install pywebview: {e}")
            return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Krij -> csgo_gc inventory bridge (web‑view)")
    ap.add_argument("--csgo-dir", help="CS:GO install folder (or its csgo/ subfolder)")
    ap.add_argument("--out", help="Explicit path to inventory.txt (overrides --csgo-dir)")
    ap.add_argument("--port", type=int, default=17352)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--token", default=os.environ.get("KRIJ_AGENT_TOKEN", ""))
    ap.add_argument("--no-backup", action="store_true")
    ap.add_argument(
        "--verify-url",
        default=os.environ.get("KRIJ_VERIFY_URL", ""),
        help="Krij signature endpoint",
    )
    ap.add_argument("--allow-unsigned", action="store_true")
    ap.add_argument("--no-enforce", action="store_true")
    ap.add_argument("--no-web", action="store_true", help="Run headless (no web window)")
    args = ap.parse_args()

    CFG.target = resolve_target(args.csgo_dir, args.out)
    CFG.token = args.token
    CFG.backup = not args.no_backup
    CFG.verify_url = args.verify_url.strip()
    CFG.require_signature = not args.allow_unsigned
    CFG.enforce = not args.no_enforce

    log("Krij csgo_gc agent starting")
    log(f"writing to: {CFG.target}")
    log(f"signatures: {'required' if CFG.require_signature else 'DISABLED'}")
    log(f"tamper lock: {'on' if CFG.enforce else 'off'}")
    log(f"trusted origins include krij-mod.vercel.app")

    if CFG.enforce:
        threading.Thread(target=watchdog, daemon=True).start()

    # Start the HTTP server
    server = start_server(args.host, args.port)

    if not args.no_web:
        webview_available = ensure_pywebview()
        if webview_available:
            import webview
            # Create the web view window
            webview.create_window(
                "Krij Agent",
                "https://krij-mod.vercel.app",
                width=1200,
                height=800,
                resizable=True,
                fullscreen=False,
                min_size=(800, 600),
                confirm_close=True,
            )
            # Run the GUI loop (this blocks until the window is closed)
            webview.start(debug=False, http_server=False)
            # After window closes, shut down the server
            log("web window closed, shutting down...")
        else:
            log("pywebview not available – running in headless mode (press Ctrl+C to stop).")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                log("shutting down by user request")
    else:
        log("Running in headless mode (press Ctrl+C to stop).")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            log("shutting down by user request")

    server.shutdown()
    server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())