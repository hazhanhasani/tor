from __future__ import annotations

import html
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .config import PANEL_PUBLIC_HOST, PANEL_TLS_ENABLED, PANEL_PORT

HTTP_FALLBACK_PORT = int(os.getenv("TORPANEL_HTTP_FALLBACK_PORT", "8787"))
HTTP_BIND = os.getenv("TORPANEL_HTTP_FALLBACK_BIND", "0.0.0.0")


def target_base_url() -> str:
    if not PANEL_TLS_ENABLED or not PANEL_PUBLIC_HOST:
        return ""
    suffix = "" if int(PANEL_PORT) == 443 else f":{int(PANEL_PORT)}"
    return f"https://{PANEL_PUBLIC_HOST}{suffix}"


class RedirectHandler(BaseHTTPRequestHandler):
    server_version = "TorLocationRedirect/1.0"

    def _send(self, with_body: bool) -> None:
        base = target_base_url()
        if not base:
            body = "Tor Location Manager HTTPS redirect is not active.\n"
            encoded = body.encode("utf-8")
            self.send_response(503)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            if with_body:
                self.wfile.write(encoded)
            return

        # Preserve only path/query from the request; never trust the Host header.
        parsed = urlsplit(self.path)
        path = parsed.path if parsed.path.startswith("/") else "/"
        location = base + path
        if parsed.query:
            location += "?" + parsed.query

        body = (
            "<!doctype html><meta charset=utf-8>"
            "<title>Redirecting…</title>"
            f'<a href="{html.escape(location, quote=True)}">Open secure panel</a>'
        ).encode("utf-8")
        self.send_response(308)
        self.send_header("Location", location)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if with_body:
            self.wfile.write(body)

    def do_GET(self) -> None:
        self._send(True)

    def do_HEAD(self) -> None:
        self._send(False)

    def log_message(self, format: str, *args) -> None:
        return


def main() -> None:
    if not target_base_url():
        return
    server = ThreadingHTTPServer((HTTP_BIND, HTTP_FALLBACK_PORT), RedirectHandler)
    server.serve_forever()


if __name__ == "__main__":
    main()
