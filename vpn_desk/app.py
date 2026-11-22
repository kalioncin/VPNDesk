from __future__ import annotations
import os
import sys
from pathlib import Path
from PySide6.QtWidgets import QApplication
from .window import MainWindow


def portable_root() -> Path:
    if getattr(sys, 'frozen', False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent.parent


def portable_marker_path() -> Path:
    return portable_root() / 'portable.flag'


def local_data_dir() -> Path:
    base = os.environ.get('LOCALAPPDATA') or str(Path.home() / 'AppData' / 'Local')
    return Path(base) / 'VPNDesk'


def portable_data_dir() -> Path:
    return portable_root() / 'data'


def app_data_dir():
    path = portable_data_dir() if portable_marker_path().exists() else local_data_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def main():
    app = QApplication(sys.argv)
    app.setApplicationName('VPNDesk')
    app.setQuitOnLastWindowClosed(False)
    window = MainWindow(app_data_dir())
    window.show()
    return app.exec()
