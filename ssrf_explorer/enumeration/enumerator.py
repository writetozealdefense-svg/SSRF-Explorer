"""Turn raw Burp traffic into deduped, SSRF-scored endpoints."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Tuple
from urllib.parse import parse_qsl, urlparse

from ssrf_explorer.burp.history_parser import RawRequest


SSRF_PARAM_RE = re.compile(
    r"(url|uri|src|dest|destination|redirect|redirect_uri|callback|feed|host|"
    r"hostname|path|target|proxy|image|img|file|document|fetch|load|next|"
    r"return|return_url|continue|data|site|domain|link|resource|endpoint|"
    r"webhook|avatar|thumbnail|preview)",
    re.IGNORECASE,
)

URL_VAL_RE = re.compile(r"^\s*(https?://|ftp://|//|/)", re.IGNORECASE)
IP_VAL_RE = re.compile(r"^\s*\d{1,3}(\.\d{1,3}){3}\b")
HOST_VAL_RE = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}")

IGNORE_EXTS = (
    ".css",
    ".js",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
)


@dataclass(frozen=True)
class ParamSpec:
    name: str
    location: str  # query|body-form|body-json|header
    sample_value: str = ""


@dataclass
class Endpoint:
    method: str
    url: str  # canonical URL with path-template applied
    host: str
    path: str
    params: List[ParamSpec] = field(default_factory=list)
    sample: RawRequest | None = None
    score: int = 0

    @property
    def param_names(self) -> List[str]:
        return [p.name for p in self.params]

    @property
    def is_candidate(self) -> bool:
        return self.score > 0


def _in_scope(host: str, scope: Iterable[str]) -> bool:
    if not scope:
        return True
    for s in scope:
        if not s:
            continue
        if host == s or host.endswith("." + s):
            return True
    return False


def _template_path(path: str) -> str:
    """Collapse numeric / uuid / hash segments into {id} placeholders."""
    uuid_re = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    out: list[str] = []
    for seg in path.split("/"):
        if not seg:
            out.append(seg)
            continue
        if seg.isdigit() or uuid_re.match(seg) or (
            len(seg) >= 16 and re.fullmatch(r"[0-9a-f]+", seg, re.IGNORECASE)
        ):
            out.append("{id}")
        else:
            out.append(seg)
    return "/".join(out)


def _extract_params(req: RawRequest) -> List[ParamSpec]:
    specs: list[ParamSpec] = []
    parsed = urlparse(req.url)
    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        specs.append(ParamSpec(k, "query", v))

    ctype = (req.headers.get("Content-Type") or req.headers.get("content-type") or "").lower()
    body = req.body or ""
    if body:
        if "application/json" in ctype:
            try:
                obj = json.loads(body)
                for k, v in _flatten(obj):
                    specs.append(ParamSpec(k, "body-json", str(v)[:200]))
            except Exception:
                pass
        elif "application/x-www-form-urlencoded" in ctype or (
            "=" in body and "\n" not in body[:200]
        ):
            try:
                for k, v in parse_qsl(body, keep_blank_values=True):
                    specs.append(ParamSpec(k, "body-form", v))
            except Exception:
                pass
    for h in ("Referer", "X-Forwarded-Host", "X-Forwarded-For", "Host", "X-Original-URL"):
        if h in req.headers:
            specs.append(ParamSpec(h, "header", req.headers[h]))
    return specs


def _flatten(obj, prefix: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, (dict, list)):
                yield from _flatten(v, key)
            else:
                yield key, v
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            key = f"{prefix}[{i}]"
            if isinstance(v, (dict, list)):
                yield from _flatten(v, key)
            else:
                yield key, v
    else:
        yield prefix or "value", obj


def _score(params: List[ParamSpec]) -> int:
    score = 0
    for p in params:
        name_hit = bool(SSRF_PARAM_RE.search(p.name))
        val = p.sample_value or ""
        val_hit = bool(
            URL_VAL_RE.match(val) or IP_VAL_RE.match(val) or HOST_VAL_RE.match(val)
        )
        if name_hit and val_hit:
            score += 5
        elif name_hit:
            score += 3
        elif val_hit and p.location != "header":
            score += 2
    return score


def enumerate_endpoints(
    reqs: Iterable[RawRequest], scope: Iterable[str] = ()
) -> List[Endpoint]:
    seen: Dict[Tuple[str, str, str, Tuple[str, ...]], Endpoint] = {}
    for r in reqs:
        host = r.host or urlparse(r.url).netloc
        if not _in_scope(host, scope):
            continue
        parsed = urlparse(r.url)
        path = parsed.path or r.path or "/"
        if path.lower().endswith(IGNORE_EXTS):
            continue
        templated = _template_path(path)
        params = _extract_params(r)
        pkey = tuple(sorted({p.name for p in params}))
        key = (r.method.upper(), host, templated, pkey)
        if key in seen:
            continue
        canonical = f"{parsed.scheme or 'https'}://{host}{templated}"
        seen[key] = Endpoint(
            method=r.method.upper() or "GET",
            url=canonical,
            host=host,
            path=templated,
            params=params,
            sample=r,
            score=_score(params),
        )
    out = list(seen.values())
    out.sort(key=lambda e: (-e.score, e.host, e.path))
    return out
