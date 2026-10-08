#!/usr/bin/env python3
"""Phone Media Vault launcher.

    python main.py                 # native window (pywebview / WebView2)
    python main.py --browser       # open the UI in the default browser instead
    python main.py --demo          # simulated phone, temporary key/settings
    python main.py cli verify D:/Vault/MyPhone   # command-line tools

Run from the ``phone_media_vault`` folder, or ``python -m phone_media_vault``
from the repository root.
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

if __package__ in (None, ""):
    # Allow `python main.py` from inside the package folder and frozen builds.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    __package__ = "phone_media_vault"  # noqa: A001

from phone_media_vault import __version__  # noqa: E402
from phone_media_vault.app.api import AppApi  # noqa: E402


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Phone Media Vault — خزنة الوسائط")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--browser", action="store_true", help="serve the UI to the web browser")
    parser.add_argument("--host", default="127.0.0.1", help="browser-mode bind address")
    parser.add_argument("--port", type=int, default=8765, help="browser-mode port")
    parser.add_argument("--no-open", action="store_true", help="do not open a browser tab")
    parser.add_argument("--demo", action="store_true", help="use a simulated phone (no ADB needed)")
    parser.add_argument("--debug", action="store_true", help="enable WebView developer tools")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "cli":
        from phone_media_vault.cli import main as cli_main

        return cli_main(argv[1:])

    args = build_parser().parse_args(argv)
    if args.demo:
        from phone_media_vault.app.demo import DemoPhone

        phone = DemoPhone()
        app_data = Path(tempfile.mkdtemp(prefix="pmv-demo-appdata-"))
        api = AppApi(adb=phone, writer=phone, app_data_dir=app_data, demo=True)
        print(f"[demo] simulated phone: {phone.root}")
        print(f"[demo] temporary app data: {app_data}")
    else:
        api = AppApi()

    from phone_media_vault.app.desktop import run_desktop, webview_available

    if not args.browser and webview_available():
        run_desktop(api, debug=args.debug)
        return 0
    if not args.browser:
        print("pywebview is not installed; falling back to browser mode.")
    from phone_media_vault.app.server import serve

    serve(api, host=args.host, port=args.port, open_browser=not args.no_open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
