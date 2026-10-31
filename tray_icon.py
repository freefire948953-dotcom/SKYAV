"""
tray_icon.py
Puts SkyAV in the Windows system tray so closing the window doesn't stop
real-time protection / registry guard — exactly how Defender's shield
icon works. Right-click the tray icon for Open/Exit.
"""

import os
import threading
from PIL import Image, ImageDraw
import pystray

ASSETS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")


def _load_custom_logo():
    """Loads the user's custom logo for the tray icon, if present."""
    logo_path = os.path.join(ASSETS_DIR, "tray_icon.png")
    if os.path.exists(logo_path):
        try:
            return Image.open(logo_path).convert("RGBA")
        except Exception:
            return None
    return None


def _make_shield_image(color="#7c8cff"):
    """Fallback: draws a simple shield icon in-memory if no custom logo is found."""
    size = 64
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Shield outline as a polygon
    points = [
        (32, 4), (58, 14), (58, 32),
        (58, 46), (32, 60), (6, 46),
        (6, 32), (6, 14),
    ]
    draw.polygon(points, fill=color)

    # Simple checkmark in the middle (white)
    draw.line([(20, 32), (28, 42), (46, 20)], fill="white", width=5, joint="curve")

    return img


def _get_icon_image():
    custom = _load_custom_logo()
    return custom if custom is not None else _make_shield_image()


class TrayIcon:
    def __init__(self, on_open, on_exit, on_quick_scan=None):
        """
        on_open: called when user clicks 'Open SkyAV' in the tray menu
        on_exit: called when user clicks 'Exit' — should fully close the app
        on_quick_scan: optional callback to trigger a quick scan from the tray
        """
        self.on_open = on_open
        self.on_exit = on_exit
        self.on_quick_scan = on_quick_scan
        self.icon = None

    def _build_menu(self):
        items = [pystray.MenuItem("Open SkyAV", self._handle_open, default=True)]
        if self.on_quick_scan:
            items.append(pystray.MenuItem("Quick Scan", self._handle_quick_scan))
        items.append(pystray.Menu.SEPARATOR)
        items.append(pystray.MenuItem("Exit", self._handle_exit))
        return pystray.Menu(*items)

    def _handle_open(self, icon, item):
        self.on_open()

    def _handle_quick_scan(self, icon, item):
        if self.on_quick_scan:
            self.on_quick_scan()

    def _handle_exit(self, icon, item):
        icon.stop()
        self.on_exit()

    def start(self):
        """Starts the tray icon in a background thread (non-blocking)."""
        self.icon = pystray.Icon(
            "SkyAV",
            _get_icon_image(),
            "SkyAV - Real-Time Protection Active",
            self._build_menu(),
        )
        thread = threading.Thread(target=self.icon.run, daemon=True)
        thread.start()

    def stop(self):
        if self.icon:
            self.icon.stop()

    def update_tooltip(self, text):
        if self.icon:
            self.icon.title = text

    def notify(self, message: str, title: str = None):
        """Shows a native desktop notification via the tray icon (Windows toast/balloon)."""
        if self.icon:
            try:
                self.icon.notify(message, title or "SkyAV")
            except Exception:
                pass  # notification support varies by OS backend; fail silently
