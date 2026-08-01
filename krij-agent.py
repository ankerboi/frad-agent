#!/usr/bin/env python3
"""
Krij -> csgo_gc bridge agent (GUI version).

Minimal dark window with a green "connected" box and a Logs button.
Stdlib only - no pip installs needed.

Usage:
    pythonw krij_gc_agent_gui.py --csgo-dir "C:/Program Files (x86)/Steam/steamapps/common/Counter-Strike Global Offensive"
    (use pythonw on Windows to hide the console)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tkinter as tk
from tkinter import scrolledtext

MAX_BODY = 4 * 1024 * 1024
PROJECT_ID = "8ef47b30-16d4-409d-baaa-3a3602adc4f2"
MAX_LOG_LINES = 500

# Shared log buffer (thread-safe)
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
    # Never touch Tkinter from worker threads - the GUI polls LOG_PENDING.
    try:
        print(line, flush=True)
    except Exception:
        pass



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
        return host in {
            f"id-preview--{PROJECT_ID}.lovable.app",
            f"project--{PROJECT_ID}.lovable.app",
            f"project--{PROJECT_ID}-dev.lovable.app",
            f"{PROJECT_ID}.lovableproject.com",
        }
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


def hide_console():
    """Hide the console window on Windows so only the GUI is visible."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
    except Exception:
        pass


class RoundedBox(tk.Canvas):
    """Simple rounded rectangle with centered text (no external libs)."""

    def __init__(self, master, text="connected", radius=14, **kwargs):
        super().__init__(master, highlightthickness=0, **kwargs)
        self.radius = radius
        self.text = text
        self.bind("<Configure>", self._redraw)

    def _redraw(self, _event=None):
        self.delete("all")
        w = self.winfo_width()
        h = self.winfo_height()
        r = min(self.radius, w // 2, h // 2)
        # Green fill
        self.create_round_rect(0, 0, w, h, r, fill="#16a34a", outline="#22c55e", width=2)
        self.create_text(
            w // 2, h // 2,
            text=self.text,
            fill="#ffffff",
            font=("Segoe UI", 14, "bold"),
        )

    def create_round_rect(self, x1, y1, x2, y2, r, **kwargs):
        points = [
            x1 + r, y1,
            x2 - r, y1,
            x2, y1,
            x2, y1 + r,
            x2, y2 - r,
            x2, y2,
            x2 - r, y2,
            x1 + r, y2,
            x1, y2,
            x1, y2 - r,
            x1, y1 + r,
            x1, y1,
        ]
        return self.create_polygon(points, smooth=True, **kwargs)


class AgentGUI:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.server: ThreadingHTTPServer | None = None
        self.log_win: tk.Toplevel | None = None
        self.log_text: scrolledtext.ScrolledText | None = None

        self.root = tk.Tk()
        self.root.title("")  # no title text
        self.root.configure(bg="#1a1a1a")
        self.root.resizable(False, False)
        self.root.geometry("280x140")
        # White icon so it blends into the Windows title bar
        try:
            # 16x16 solid white image
            white = tk.PhotoImage(width=16, height=16)
            white.put("#ffffff", to=(0, 0, 16, 16))
            self.root.iconphoto(True, white)
            self._window_icon = white  # keep reference
        except Exception:
            pass
        try:
            self.root.iconbitmap("")
        except Exception:
            pass

        # Center
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - 140
        y = (self.root.winfo_screenheight() // 2) - 70
        self.root.geometry(f"+{x}+{y}")

        # Top bar with Logs button (top-right)
        top = tk.Frame(self.root, bg="#1a1a1a", height=28)
        top.pack(fill="x", side="top")
        top.pack_propagate(False)

        self.logs_btn = tk.Button(
            top,
            text="logs",
            font=("Segoe UI", 8),
            fg="#cccccc",
            bg="#2a2a2a",
            activeforeground="#ffffff",
            activebackground="#3a3a3a",
            relief="flat",
            bd=0,
            padx=10,
            pady=2,
            cursor="hand2",
            command=self.toggle_logs,
        )
        self.logs_btn.pack(side="right", padx=8, pady=4)

        # Center area with green connected box
        center = tk.Frame(self.root, bg="#1a1a1a")
        center.pack(expand=True, fill="both")

        self.box = RoundedBox(
            center,
            text="connected",
            radius=16,
            width=160,
            height=52,
            bg="#1a1a1a",
        )
        self.box.place(relx=0.5, rely=0.5, anchor="center")

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        # Poll new log lines from the GUI thread (Tk is not thread-safe).
        self.root.after(300, self._drain_logs)

    def _drain_logs(self):
        try:
            with LOG_LOCK:
                lines = list(LOG_PENDING)
                LOG_PENDING.clear()
            if lines and self.log_text and self.log_win and self.log_win.winfo_exists():
                self.log_text.configure(state="normal")
                for line in lines:
                    self.log_text.insert("end", line + "\n")
                self.log_text.see("end")
                self.log_text.configure(state="disabled")
        except Exception:
            pass
        try:
            self.root.after(300, self._drain_logs)
        except Exception:
            pass


    def toggle_logs(self):
        if self.log_win and self.log_win.winfo_exists():
            self.log_win.lift()
            return

        self.log_win = tk.Toplevel(self.root)
        self.log_win.title("Krij GC Agent — Logs")
        self.log_win.configure(bg="#1a1a1a")
        self.log_win.geometry("520x320")
        self.log_win.minsize(360, 200)

        # Position near main window
        try:
            mx = self.root.winfo_x()
            my = self.root.winfo_y()
            self.log_win.geometry(f"+{mx + 20}+{my + 40}")
        except Exception:
            pass

        header = tk.Frame(self.log_win, bg="#1a1a1a")
        header.pack(fill="x", padx=8, pady=(8, 4))

        tk.Label(
            header,
            text="Logs",
            fg="#e5e5e5",
            bg="#1a1a1a",
            font=("Segoe UI", 11, "bold"),
        ).pack(side="left")

        clear_btn = tk.Button(
            header,
            text="clear",
            font=("Segoe UI", 8),
            fg="#aaaaaa",
            bg="#2a2a2a",
            activeforeground="#ffffff",
            activebackground="#3a3a3a",
            relief="flat",
            bd=0,
            padx=8,
            pady=1,
            cursor="hand2",
            command=self._clear_logs,
        )
        clear_btn.pack(side="right")

        self.log_text = scrolledtext.ScrolledText(
            self.log_win,
            wrap="word",
            font=("Consolas", 9),
            bg="#111111",
            fg="#d4d4d4",
            insertbackground="#ffffff",
            relief="flat",
            bd=0,
            padx=8,
            pady=8,
            state="disabled",
        )
        self.log_text.pack(expand=True, fill="both", padx=8, pady=(0, 8))

        # Load existing buffer
        with LOG_LOCK:
            lines = list(LOG_BUFFER)
        self.log_text.configure(state="normal")
        for line in lines:
            self.log_text.insert("end", line + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

        self.log_win.protocol("WM_DELETE_WINDOW", self._close_logs)

    def _clear_logs(self):
        with LOG_LOCK:
            LOG_BUFFER.clear()
        if self.log_text:
            self.log_text.configure(state="normal")
            self.log_text.delete("1.0", "end")
            self.log_text.configure(state="disabled")

    def _close_logs(self):
        if self.log_win:
            self.log_win.destroy()
        self.log_win = None
        self.log_text = None

    def start_server(self):
        def run():
            try:
                self.server = ThreadingHTTPServer((self.host, self.port), Handler)
                log(f"listening on http://{self.host}:{self.port}")
                self.server.serve_forever()
            except Exception as exc:
                log(f"server error: {exc}")

        t = threading.Thread(target=run, daemon=True)
        t.start()

    def on_close(self):
        log("shutting down")
        if self.server:
            try:
                self.server.shutdown()
            except Exception:
                pass
        if self.log_win and self.log_win.winfo_exists():
            self.log_win.destroy()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main() -> int:
    # Hide console so only the GUI window is visible
    hide_console()

    ap = argparse.ArgumentParser(description="Krij -> csgo_gc inventory bridge (GUI)")
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

    if CFG.enforce:
        threading.Thread(target=watchdog, daemon=True).start()

    gui = AgentGUI(args.host, args.port)
    gui.start_server()
    gui.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
