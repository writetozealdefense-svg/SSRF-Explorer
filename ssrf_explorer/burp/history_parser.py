"""Parser for Burp Suite proxy history XML exports.

Burp's XML export wraps <items><item>...<request base64="true">...</request>...</item></items>.
Request and response bodies are (optionally) base64-encoded raw HTTP messages.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from lxml import etree


@dataclass
class RawRequest:
    method: str
    url: str
    host: str
    path: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    status: Optional[int] = None
    response_len: int = 0
    raw: str = ""


def _decode(el) -> str:
    if el is None or el.text is None:
        return ""
    text = el.text
    if el.get("base64") == "true":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:
            return ""
    return text


def _parse_request_bytes(raw: str) -> tuple[str, str, Dict[str, str], str]:
    """Parse a raw HTTP request. Returns (method, path, headers, body)."""
    if not raw:
        return "", "", {}, ""
    head, _, body = raw.partition("\r\n\r\n")
    if not head:
        head, _, body = raw.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        return "", "", {}, body
    request_line = lines[0]
    parts = request_line.split(" ")
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) >= 2 else ""
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
    return method, path, headers, body


def parse_history(path: str) -> List[RawRequest]:
    tree = etree.parse(path)
    out: List[RawRequest] = []
    for item in tree.iterfind(".//item"):
        url = (item.findtext("url") or "").strip()
        host_el = item.find("host")
        host = (host_el.text or "").strip() if host_el is not None else ""
        method = (item.findtext("method") or "").strip()
        path_el = (item.findtext("path") or "").strip()
        status_txt = (item.findtext("status") or "").strip()
        try:
            status = int(status_txt) if status_txt else None
        except ValueError:
            status = None
        resp_len = 0
        try:
            resp_len = int((item.findtext("responselength") or "0").strip() or "0")
        except ValueError:
            resp_len = 0

        raw_req = _decode(item.find("request"))
        m2, p2, headers, body = _parse_request_bytes(raw_req)
        out.append(
            RawRequest(
                method=method or m2,
                url=url,
                host=host,
                path=path_el or p2,
                headers=headers,
                body=body,
                status=status,
                response_len=resp_len,
                raw=raw_req,
            )
        )
    return out
