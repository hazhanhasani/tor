from __future__ import annotations

import os
import sys
from pathlib import Path

from .config import (
    PANEL_BIND,
    PANEL_PORT,
    PANEL_TLS_CERTFILE,
    PANEL_TLS_ENABLED,
    PANEL_TLS_KEYFILE,
)


def main() -> None:
    args = [
        sys.executable,
        "-m",
        "gunicorn",
        "--workers",
        "2",
        "--threads",
        "4",
        "--timeout",
        "120",
        "--bind",
        f"{PANEL_BIND}:{PANEL_PORT}",
    ]
    if PANEL_TLS_ENABLED:
        cert = Path(PANEL_TLS_CERTFILE)
        key = Path(PANEL_TLS_KEYFILE)
        if not cert.is_file() or not key.is_file():
            raise SystemExit(
                "Panel HTTPS is enabled but the synchronized x-ui certificate/key are missing."
            )
        args.extend(["--certfile", str(cert), "--keyfile", str(key)])
    args.append("wsgi:app")
    os.execv(sys.executable, args)


if __name__ == "__main__":
    main()
