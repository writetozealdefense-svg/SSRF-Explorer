import sys

from PyQt6.QtWidgets import QApplication

from ssrf_explorer.gui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("SSRF Explorer")
    w = MainWindow()
    w.show()
    return app.exec()
