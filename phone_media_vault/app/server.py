"""Browser mode: serve the UI and the JSON API over local HTTP.

Used when pywebview is unavailable, for development, and for demo mode. Each
server run creates a random token that is injected into ``index.html``; every
API call must present it in the ``X-PMV-Token`` header, so other web pages the
user visits cannot drive the API (they cannot read the token cross-origin).
By default the server binds to 127.0.0.1 only.
"""

from __future__ import annotations

import hmac
import json
import mimetypes
import secrets
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from .api import AppApi

UI_ROOT = Path(__file__).resolve().parents[1] / "ui"
_MAX_BODY = 1024 * 1024
_BOOTSTRAP_MARKER = "<!--PMV_BOOTSTRAP-->"


def public_api_methods(api: AppApi) -> dict[str, Any]:
    methods = {}
    for name in dir(api):
        if name.startswith("_"):
            continue
        attribute = getattr(api, name)
        if callable(attribute) and getattr(attribute, "__pmv_api__", False):
            methods[name] = attribute
    return methods


def make_handler(api: AppApi, token: str):
    methods = public_api_methods(api)

    class Handler(BaseHTTPRequestHandler):
        server_version = "PhoneMediaVault"

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return  # keep the console quiet

        def _send(self, status: int, body: bytes, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self) -> None:  # noqa: N802
            path = self.path.split("?", 1)[0]
            if path in ("", "/"):
                path = "/index.html"
            target = (UI_ROOT / path.lstrip("/")).resolve()
            try:
                target.relative_to(UI_ROOT)
            except ValueError:
                self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
                return
            if not target.is_file():
                self._send(HTTPStatus.NOT_FOUND, b"not found", "text/plain")
                return
            body = target.read_bytes()
            if target.name == "index.html":
                bootstrap = f'<script>window.PMV_TOKEN = {json.dumps(token)};</script>'
                body = body.decode("utf-8").replace(_BOOTSTRAP_MARKER, bootstrap).encode("utf-8")
            content_type = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if content_type.startswith("text/") or content_type.endswith("javascript"):
                content_type += "; charset=utf-8"
            self._send(HTTPStatus.OK, body, content_type)

        def do_POST(self) -> None:  # noqa: N802
            if not self.path.startswith("/api/"):
                self._send(HTTPStatus.NOT_FOUND, b"{}", "application/json")
                return
            supplied = self.headers.get("X-PMV-Token", "")
            if not hmac.compare_digest(supplied, token):
                self._send(HTTPStatus.FORBIDDEN, b'{"ok":false,"error":"forbidden"}', "application/json")
                return
            name = self.path[len("/api/"):]
            method = methods.get(name)
            if method is None:
                self._send(HTTPStatus.NOT_FOUND, b'{"ok":false,"error":"unknown method"}', "application/json")
                return
            length = int(self.headers.get("Content-Length") or 0)
            if length > _MAX_BODY:
                self._send(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, b"{}", "application/json")
                return
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
                args = payload.get("args", []) if isinstance(payload, dict) else []
                if not isinstance(args, list):
                    raise ValueError("args must be a list")
            except (ValueError, json.JSONDecodeError):
                self._send(HTTPStatus.BAD_REQUEST, b'{"ok":false,"error":"bad request"}', "application/json")
                return
            try:
                result = method(*args)
            except TypeError as exc:
                result = {"ok": False, "error": f"معاملات غير صالحة: {exc}"}
            body = json.dumps(result, ensure_ascii=False).encode("utf-8")
            self._send(HTTPStatus.OK, body, "application/json; charset=utf-8")

    return Handler


def serve(api: AppApi, *, host: str = "127.0.0.1", port: int = 8765, open_browser: bool = True) -> None:
    token = secrets.token_urlsafe(32)
    server = ThreadingHTTPServer((host, port), make_handler(api, token))
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '') else host}:{server.server_address[1]}/"
    print(f"Phone Media Vault — browser mode: {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        import webbrowser

        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
