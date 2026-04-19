"""Thin wrapper around Burp's REST API when available.

The shape of the REST API varies across Burp editions. We expose a single
``fetch_history`` entry point that best-effort pulls traffic and coerces it
into the same ``RawRequest`` shape used by the XML parser, so the enumerator
doesn't care which path produced the data.
"""
from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlparse

import httpx

from ssrf_explorer.burp.history_parser import RawRequest, _parse_request_bytes


class BurpRestClient:
    def __init__(self, base_url: str, api_key: Optional[str] = None) -> None:
        self.base_url = base_url.rstrip("/") + "/"
        self.api_key = api_key

    def _get(self, path: str, **kwargs) -> httpx.Response:
        url = self.base_url + path.lstrip("/")
        headers = {}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return httpx.get(url, headers=headers, timeout=30, **kwargs)

    def fetch_history(self, scope_hosts: List[str]) -> List[RawRequest]:
        """Best-effort: tries a couple of known endpoints.

        If your Burp build exposes a different route, export proxy history as
        XML and use that path instead — the result is identical downstream.
        """
        candidates = ["proxy/history", "history"]
        last_err: Optional[Exception] = None
        for c in candidates:
            try:
                r = self._get(c, params={"scope": ",".join(scope_hosts)})
                if r.status_code == 200 and r.headers.get(
                    "content-type", ""
                ).startswith("application/json"):
                    return self._from_json(r.json(), scope_hosts)
            except Exception as e:  # noqa: BLE001
                last_err = e
        raise RuntimeError(
            f"Burp REST API did not return history. Last error: {last_err}. "
            f"Use the XML export path instead."
        )

    def _from_json(self, data, scope_hosts: List[str]) -> List[RawRequest]:
        items = data.get("items") if isinstance(data, dict) else data
        out: List[RawRequest] = []
        for it in items or []:
            url = it.get("url") or it.get("request_url") or ""
            host = urlparse(url).netloc
            if scope_hosts and not any(h in host for h in scope_hosts):
                continue
            raw = it.get("request") or it.get("raw_request") or ""
            method, path, headers, body = _parse_request_bytes(raw)
            out.append(
                RawRequest(
                    method=it.get("method") or method,
                    url=url,
                    host=host,
                    path=path,
                    headers=headers,
                    body=body,
                    status=it.get("status"),
                    response_len=int(it.get("response_length") or 0),
                    raw=raw,
                )
            )
        return out
