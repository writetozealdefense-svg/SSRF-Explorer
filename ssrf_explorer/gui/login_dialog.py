from urllib.parse import urlparse

from PyQt6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ssrf_explorer.config import AppConfig


class LoginDialog(QDialog):
    """Collects target creds, Burp proxy, and scan params."""

    def __init__(self, cfg: AppConfig, parent=None) -> None:
        super().__init__(parent)
        self.cfg = cfg
        self.setWindowTitle("Target & Proxy")
        self.setModal(True)
        self.resize(600, 460)

        root = QVBoxLayout(self)
        tabs = QTabWidget()
        root.addWidget(tabs)

        tabs.addTab(self._target_tab(), "Target")
        tabs.addTab(self._burp_tab(), "Burp")
        tabs.addTab(self._scan_tab(), "Scan")

        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok
            | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self._accept)
        buttons.rejected.connect(self.reject)
        root.addWidget(buttons)

    def _target_tab(self) -> QWidget:
        w = QWidget()
        f = QFormLayout(w)
        self.url = QLineEdit(self.cfg.target.url)
        self.url.setPlaceholderText("https://target.example.com/login")
        self.user = QLineEdit(self.cfg.target.username)
        self.pwd = QLineEdit(self.cfg.target.password)
        self.pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.scope = QLineEdit(",".join(self.cfg.target.scope_hosts))
        self.scope.setPlaceholderText("target.example.com, api.example.com")
        f.addRow("Target URL:", self.url)
        f.addRow("Username:", self.user)
        f.addRow("Password:", self.pwd)
        f.addRow("In-scope hosts:", self.scope)
        return w

    def _burp_tab(self) -> QWidget:
        w = QWidget()
        f = QFormLayout(w)
        self.proxy_host = QLineEdit(self.cfg.burp.proxy_host)
        self.proxy_port = QSpinBox()
        self.proxy_port.setRange(1, 65535)
        self.proxy_port.setValue(self.cfg.burp.proxy_port)

        self.ca_path = QLineEdit(self.cfg.burp.ca_cert_path or "")
        ca_row = QHBoxLayout()
        ca_row.addWidget(self.ca_path)
        browse = QPushButton("Browse...")
        browse.clicked.connect(self._pick_ca)
        ca_row.addWidget(browse)
        ca_wrap = QWidget()
        ca_wrap.setLayout(ca_row)

        self.rest_url = QLineEdit(self.cfg.burp.rest_api_url or "")
        self.rest_url.setPlaceholderText("http://127.0.0.1:1337/v0.1/  (optional)")
        self.rest_key = QLineEdit(self.cfg.burp.rest_api_key or "")
        self.rest_key.setEchoMode(QLineEdit.EchoMode.Password)

        self.hist_path = QLineEdit(self.cfg.burp.history_xml_path or "")
        hist_row = QHBoxLayout()
        hist_row.addWidget(self.hist_path)
        hb = QPushButton("Browse...")
        hb.clicked.connect(self._pick_history)
        hist_row.addWidget(hb)
        hist_wrap = QWidget()
        hist_wrap.setLayout(hist_row)

        f.addRow("Proxy host:", self.proxy_host)
        f.addRow("Proxy port:", self.proxy_port)
        f.addRow("CA cert (DER/PEM):", ca_wrap)
        f.addRow("REST API URL:", self.rest_url)
        f.addRow("REST API key:", self.rest_key)
        f.addRow("Proxy history XML:", hist_wrap)
        return w

    def _scan_tab(self) -> QWidget:
        w = QWidget()
        f = QFormLayout(w)
        self.concurrency = QSpinBox()
        self.concurrency.setRange(1, 64)
        self.concurrency.setValue(self.cfg.scan.max_concurrency)
        self.timeout = QSpinBox()
        self.timeout.setRange(1, 120)
        self.timeout.setValue(self.cfg.scan.request_timeout)
        self.oob = QLineEdit(self.cfg.scan.oob_canary_url)
        self.oob.setPlaceholderText("https://xxxx.oast.fun  (optional)")
        f.addRow("Max concurrency:", self.concurrency)
        f.addRow("Request timeout (s):", self.timeout)
        f.addRow("OOB canary URL:", self.oob)
        return w

    def _pick_ca(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Burp CA certificate", "", "Certificates (*.der *.pem *.crt *.cer)"
        )
        if path:
            self.ca_path.setText(path)

    def _pick_history(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Burp proxy history XML", "", "XML (*.xml)"
        )
        if path:
            self.hist_path.setText(path)

    def _accept(self) -> None:
        url = self.url.text().strip()
        if not url or not urlparse(url).netloc:
            QMessageBox.warning(self, "Invalid URL", "Enter a valid target URL.")
            return
        self.cfg.target.url = url
        self.cfg.target.username = self.user.text()
        self.cfg.target.password = self.pwd.text()
        hosts = [h.strip() for h in self.scope.text().split(",") if h.strip()]
        if not hosts:
            hosts = [urlparse(url).netloc]
        self.cfg.target.scope_hosts = hosts

        self.cfg.burp.proxy_host = self.proxy_host.text().strip()
        self.cfg.burp.proxy_port = self.proxy_port.value()
        self.cfg.burp.ca_cert_path = self.ca_path.text().strip() or None
        self.cfg.burp.rest_api_url = self.rest_url.text().strip() or None
        self.cfg.burp.rest_api_key = self.rest_key.text().strip() or None
        self.cfg.burp.history_xml_path = self.hist_path.text().strip() or None

        self.cfg.scan.max_concurrency = self.concurrency.value()
        self.cfg.scan.request_timeout = self.timeout.value()
        self.cfg.scan.oob_canary_url = self.oob.text().strip()
        self.accept()
