from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ssrf_explorer.burp.history_parser import parse_history
from ssrf_explorer.burp.rest_client import BurpRestClient
from ssrf_explorer.config import AppConfig
from ssrf_explorer.enumeration.enumerator import Endpoint, enumerate_endpoints
from ssrf_explorer.gui.auth_gate import AuthGateDialog
from ssrf_explorer.gui.login_dialog import LoginDialog
from ssrf_explorer.report.generator import write_report
from ssrf_explorer.ssrf.runner import run_ssrf_scan


class BrowserWorker(QThread):
    log = pyqtSignal(str)
    done = pyqtSignal(bool, str)

    def __init__(self, cfg: AppConfig) -> None:
        super().__init__()
        self.cfg = cfg

    def run(self) -> None:  # runs off GUI thread
        try:
            from ssrf_explorer.browser.controller import launch_browser_and_login

            launch_browser_and_login(self.cfg, log=self.log.emit)
            self.done.emit(True, "Browser closed.")
        except Exception as e:  # noqa: BLE001
            self.done.emit(False, f"Browser error: {e}")


class ScanWorker(QThread):
    log = pyqtSignal(str)
    progress = pyqtSignal(int, int)
    done = pyqtSignal(bool, str, list)  # success, message, results

    def __init__(self, cfg: AppConfig, endpoints: list[Endpoint]) -> None:
        super().__init__()
        self.cfg = cfg
        self.endpoints = endpoints

    def run(self) -> None:
        try:
            results = run_ssrf_scan(
                self.cfg,
                self.endpoints,
                log=self.log.emit,
                progress=lambda d, t: self.progress.emit(d, t),
            )
            self.done.emit(True, f"Scan finished. {len(results)} findings.", results)
        except Exception as e:  # noqa: BLE001
            self.done.emit(False, f"Scan error: {e}", [])


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SSRF Explorer")
        self.resize(1200, 760)
        self.cfg = AppConfig()
        self.endpoints: list[Endpoint] = []
        self.findings: list[dict] = []
        self._build_ui()

    # ---------- UI ----------
    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        v = QVBoxLayout(central)

        toolbar = QHBoxLayout()
        self.btn_configure = QPushButton("1. Configure Target")
        self.btn_browser = QPushButton("2. Launch Browser + Login")
        self.btn_load = QPushButton("3. Load Burp Traffic")
        self.btn_scan = QPushButton("4. Run SSRF Scan")
        self.btn_report = QPushButton("5. Save Report")
        for b in (
            self.btn_configure,
            self.btn_browser,
            self.btn_load,
            self.btn_scan,
            self.btn_report,
        ):
            toolbar.addWidget(b)
        toolbar.addStretch(1)
        v.addLayout(toolbar)

        self.btn_configure.clicked.connect(self.configure)
        self.btn_browser.clicked.connect(self.launch_browser)
        self.btn_load.clicked.connect(self.load_traffic)
        self.btn_scan.clicked.connect(self.run_scan)
        self.btn_report.clicked.connect(self.save_report)

        for b in (self.btn_browser, self.btn_load, self.btn_scan, self.btn_report):
            b.setEnabled(False)

        self.tabs = QTabWidget()
        v.addWidget(self.tabs, 1)

        # Session / log
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.tabs.addTab(self.log_view, "Session Log")

        # Endpoints
        ep_wrap = QWidget()
        ep_layout = QVBoxLayout(ep_wrap)
        self.ep_table = QTableWidget(0, 5)
        self.ep_table.setHorizontalHeaderLabels(
            ["Method", "URL", "Params", "SSRF Candidate?", "Score"]
        )
        self.ep_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        ep_layout.addWidget(self.ep_table)
        self.tabs.addTab(ep_wrap, "Endpoints")

        # Results
        res_wrap = QWidget()
        res_layout = QVBoxLayout(res_wrap)
        self.res_table = QTableWidget(0, 6)
        self.res_table.setHorizontalHeaderLabels(
            ["Severity", "Endpoint", "Param", "Payload", "Status", "Signal"]
        )
        self.res_table.horizontalHeader().setSectionResizeMode(
            QHeaderView.ResizeMode.Stretch
        )
        res_layout.addWidget(self.res_table)
        self.tabs.addTab(res_wrap, "SSRF Results")

        self.status = QLabel("Idle.")
        self.statusBar().addWidget(self.status)

    def _log(self, msg: str) -> None:
        self.log_view.appendPlainText(msg)

    # ---------- Flow ----------
    def configure(self) -> None:
        gate = AuthGateDialog(self)
        if gate.exec() != gate.DialogCode.Accepted or not gate.result_auth:
            return
        self.cfg.auth = gate.result_auth

        dlg = LoginDialog(self.cfg, self)
        if dlg.exec() != dlg.DialogCode.Accepted:
            return

        scope_str = ", ".join(self.cfg.target.scope_hosts)
        self._log(
            f"[auth] operator={self.cfg.auth.operator} "
            f"ref={self.cfg.auth.engagement_ref} ts={self.cfg.auth.timestamp}"
        )
        self._log(f"[cfg] target={self.cfg.target.url} scope=[{scope_str}]")
        self._log(
            f"[cfg] proxy={self.cfg.burp.proxy_host}:{self.cfg.burp.proxy_port}"
        )
        for b in (self.btn_browser, self.btn_load):
            b.setEnabled(True)
        self.status.setText("Configured. Launch the browser.")

    def launch_browser(self) -> None:
        if not self.cfg.auth.attested:
            QMessageBox.warning(self, "Not authorized", "Configure first.")
            return
        self.btn_browser.setEnabled(False)
        self.status.setText("Launching Chromium via Burp...")
        self._worker = BrowserWorker(self.cfg)
        self._worker.log.connect(self._log)
        self._worker.done.connect(self._on_browser_done)
        self._worker.start()

    def _on_browser_done(self, ok: bool, msg: str) -> None:
        self._log(msg)
        self.btn_browser.setEnabled(True)
        self.status.setText(msg)

    def load_traffic(self) -> None:
        if not self.cfg.auth.attested:
            return
        try:
            if self.cfg.burp.rest_api_url:
                client = BurpRestClient(
                    self.cfg.burp.rest_api_url, self.cfg.burp.rest_api_key
                )
                reqs = client.fetch_history(self.cfg.target.scope_hosts)
                self._log(f"[burp] pulled {len(reqs)} requests via REST API")
            elif self.cfg.burp.history_xml_path:
                reqs = parse_history(self.cfg.burp.history_xml_path)
                self._log(
                    f"[burp] parsed {len(reqs)} requests from "
                    f"{self.cfg.burp.history_xml_path}"
                )
            else:
                path, _ = QFileDialog.getOpenFileName(
                    self, "Pick Burp proxy history XML export", "", "XML (*.xml)"
                )
                if not path:
                    return
                self.cfg.burp.history_xml_path = path
                reqs = parse_history(path)
                self._log(f"[burp] parsed {len(reqs)} requests from {path}")

            self.endpoints = enumerate_endpoints(reqs, self.cfg.target.scope_hosts)
            self._populate_endpoints()
            self._log(
                f"[enum] {len(self.endpoints)} unique endpoints "
                f"({sum(1 for e in self.endpoints if e.is_candidate)} SSRF candidates)"
            )
            self.btn_scan.setEnabled(any(e.is_candidate for e in self.endpoints))
            self.status.setText("Traffic loaded.")
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Load failed", str(e))

    def _populate_endpoints(self) -> None:
        self.ep_table.setRowCount(len(self.endpoints))
        for i, e in enumerate(self.endpoints):
            self.ep_table.setItem(i, 0, QTableWidgetItem(e.method))
            self.ep_table.setItem(i, 1, QTableWidgetItem(e.url))
            self.ep_table.setItem(
                i, 2, QTableWidgetItem(", ".join(e.param_names) or "-")
            )
            self.ep_table.setItem(
                i, 3, QTableWidgetItem("YES" if e.is_candidate else "")
            )
            self.ep_table.setItem(i, 4, QTableWidgetItem(str(e.score)))

    def run_scan(self) -> None:
        cands = [e for e in self.endpoints if e.is_candidate]
        if not cands:
            QMessageBox.information(self, "Nothing to test", "No SSRF candidates.")
            return
        if (
            QMessageBox.question(
                self,
                "Confirm scan",
                f"About to fire SSRF payloads against {len(cands)} endpoints. "
                f"Scope: {', '.join(self.cfg.target.scope_hosts)}.\nProceed?",
            )
            != QMessageBox.StandardButton.Yes
        ):
            return
        self.btn_scan.setEnabled(False)
        self.status.setText("Scanning...")
        self._scan_worker = ScanWorker(self.cfg, cands)
        self._scan_worker.log.connect(self._log)
        self._scan_worker.progress.connect(
            lambda d, t: self.status.setText(f"Scanning {d}/{t}")
        )
        self._scan_worker.done.connect(self._on_scan_done)
        self._scan_worker.start()

    def _on_scan_done(self, ok: bool, msg: str, results: list[dict]) -> None:
        self._log(msg)
        self.btn_scan.setEnabled(True)
        self.status.setText(msg)
        if ok:
            self.findings = results
            self._populate_results()
            self.btn_report.setEnabled(True)

    def _populate_results(self) -> None:
        self.res_table.setRowCount(len(self.findings))
        for i, r in enumerate(self.findings):
            self.res_table.setItem(i, 0, QTableWidgetItem(r.get("severity", "")))
            self.res_table.setItem(i, 1, QTableWidgetItem(r.get("endpoint", "")))
            self.res_table.setItem(i, 2, QTableWidgetItem(r.get("param", "")))
            self.res_table.setItem(i, 3, QTableWidgetItem(r.get("payload", "")))
            self.res_table.setItem(i, 4, QTableWidgetItem(str(r.get("status", ""))))
            self.res_table.setItem(
                i, 5, QTableWidgetItem(", ".join(r.get("signals", [])))
            )

    def save_report(self) -> None:
        try:
            self.cfg.report_dir.mkdir(parents=True, exist_ok=True)
            html_path, json_path = write_report(
                self.cfg, self.endpoints, self.findings
            )
            self._log(f"[report] {html_path}")
            self._log(f"[report] {json_path}")
            QMessageBox.information(self, "Report saved", f"HTML: {html_path}")
        except Exception as e:  # noqa: BLE001
            QMessageBox.critical(self, "Report failed", str(e))
