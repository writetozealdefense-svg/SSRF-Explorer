from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional


@dataclass
class BurpConfig:
    proxy_host: str = "127.0.0.1"
    proxy_port: int = 8080
    ca_cert_path: Optional[str] = None
    rest_api_url: Optional[str] = None  # e.g. http://127.0.0.1:1337/v0.1/
    rest_api_key: Optional[str] = None
    history_xml_path: Optional[str] = None


@dataclass
class TargetConfig:
    url: str = ""
    username: str = ""
    password: str = ""
    scope_hosts: List[str] = field(default_factory=list)


@dataclass
class Authorization:
    attested: bool = False
    engagement_ref: str = ""
    operator: str = ""
    timestamp: str = ""


@dataclass
class ScanConfig:
    max_concurrency: int = 5
    request_timeout: int = 10
    oob_canary_url: str = ""  # Interactsh/Collaborator


@dataclass
class AppConfig:
    target: TargetConfig = field(default_factory=TargetConfig)
    burp: BurpConfig = field(default_factory=BurpConfig)
    auth: Authorization = field(default_factory=Authorization)
    scan: ScanConfig = field(default_factory=ScanConfig)
    profile_dir: Path = field(default_factory=lambda: Path("profile"))
    report_dir: Path = field(default_factory=lambda: Path("report"))
