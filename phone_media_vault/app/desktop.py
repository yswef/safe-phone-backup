"""Native desktop window (pywebview / Edge WebView2 on Windows)."""

from __future__ import annotations

from .api import AppApi
from .server import UI_ROOT


def webview_available() -> bool:
    try:
        import webview  # type: ignore  # noqa: F401
    except ImportError:
        return False
    return True


def run_desktop(api: AppApi, *, debug: bool = False) -> None:
    import webview  # type: ignore

    window = webview.create_window(
        "خزنة الوسائط — Phone Media Vault",
        url=str(UI_ROOT / "index.html"),
        js_api=api,
        width=1200,
        height=820,
        min_size=(980, 640),
        text_select=True,
    )
    api._window = window  # enables the native folder picker
    webview.start(debug=debug)
