"""Classify probe responses into SSRF severity buckets."""
from __future__ import annotations

import re
from typing import Dict, List, Optional

META_MARKERS = (
    "ami-id",
    "instance-identity",
    "iam/security-credentials",
    "computeMetadata",
    "Metadata-Flavor",
    "access_token",
    "securityCredentials",
)
BANNER_MARKERS = (
    "SSH-2.0",
    "SSH-1.99",
    "220 ",
    "Redis",
    "MEMCACHED",
    "HTTP/1.0 4",
    "Server: gunicorn",
)
FILE_MARKERS = (
    "root:x:0:0",
    "[extensions]",
    "[fonts]",
    "for 16-bit app support",
)


def classify(
    payload_category: str,
    status: Optional[int],
    body_excerpt: str,
    elapsed_ms: int,
    baseline_ms: Optional[int] = None,
    oob_hit: bool = False,
) -> tuple[str, List[str]]:
    signals: List[str] = []
    body = body_excerpt or ""

    if any(m in body for m in META_MARKERS):
        signals.append("cloud-metadata-content")
    if any(m in body for m in BANNER_MARKERS):
        signals.append("service-banner")
    if any(m in body for m in FILE_MARKERS):
        signals.append("local-file-content")
    if status and 200 <= status < 400 and payload_category in ("loopback", "private"):
        signals.append(f"internal-reachable-{status}")
    if baseline_ms is not None and elapsed_ms - baseline_ms > 1500:
        signals.append(f"timing-delta-{elapsed_ms - baseline_ms}ms")
    if oob_hit:
        signals.append("oob-callback")

    if "oob-callback" in signals or "cloud-metadata-content" in signals or "local-file-content" in signals:
        severity = "Confirmed"
    elif "service-banner" in signals or any(
        s.startswith("internal-reachable-") for s in signals
    ):
        severity = "Likely"
    elif signals:
        severity = "Possible"
    else:
        severity = "None"
    return severity, signals
