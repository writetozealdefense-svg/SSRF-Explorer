"""Render the HTML + JSON SSRF report."""
from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Tuple

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ssrf_explorer.config import AppConfig
from ssrf_explorer.enumeration.enumerator import Endpoint


_TEMPLATE_DIR = Path(__file__).parent


def _endpoint_view(e: Endpoint) -> dict:
    return {
        "method": e.method,
        "url": e.url,
        "score": e.score,
        "params": [asdict(p) for p in e.params],
    }


def write_report(
    cfg: AppConfig, endpoints: List[Endpoint], findings: List[dict]
) -> Tuple[Path, Path]:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    tpl = env.get_template("template.html")

    counts = {"Confirmed": 0, "Likely": 0, "Possible": 0, "None": 0}
    for f in findings:
        counts[f.get("severity", "None")] = counts.get(f.get("severity", "None"), 0) + 1

    ctx = {
        "auth": asdict(cfg.auth),
        "target": asdict(cfg.target),
        "burp": asdict(cfg.burp),
        "scan": asdict(cfg.scan),
        "endpoints": [_endpoint_view(e) for e in endpoints],
        "candidates": sum(1 for e in endpoints if e.is_candidate),
        "findings": findings,
        "counts": counts,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }

    cfg.report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    html_path = cfg.report_dir / f"ssrf-report-{stamp}.html"
    json_path = cfg.report_dir / f"ssrf-report-{stamp}.json"
    html_path.write_text(tpl.render(**ctx), encoding="utf-8")
    json_path.write_text(
        json.dumps(
            {
                "auth": ctx["auth"],
                "target": ctx["target"],
                "burp": {k: v for k, v in ctx["burp"].items() if k != "rest_api_key"},
                "scan": ctx["scan"],
                "endpoints": ctx["endpoints"],
                "findings": findings,
                "counts": counts,
                "generated_at": ctx["generated_at"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return html_path, json_path
