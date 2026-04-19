"""Orchestrate PowerShell-based SSRF probing.

For each (candidate endpoint, SSRF-shaped param), we:
  1. Fire a baseline request (unmodified param) to measure latency.
  2. For each payload, spawn pwsh running ``ssrf_runner.ps1`` with a JSON
     payload on stdin. Collect the JSON response.
  3. Feed the response to ``detector.classify`` to assign a severity.

Concurrency is a ThreadPool of subprocesses; each subprocess is a one-shot
PowerShell invocation that exits once the probe is complete.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable, Dict, List, Optional

from ssrf_explorer.config import AppConfig
from ssrf_explorer.enumeration.enumerator import Endpoint, ParamSpec, SSRF_PARAM_RE, URL_VAL_RE, HOST_VAL_RE, IP_VAL_RE
from ssrf_explorer.ssrf.detector import classify
from ssrf_explorer.ssrf.payloads import Payload, build as build_payloads


Logger = Callable[[str], None]
Progress = Callable[[int, int], None]

_RUNNER_PATH = Path(__file__).with_name("ssrf_runner.ps1")


def _noop(_: str) -> None:
    pass


def _find_pwsh() -> str:
    for c in ("pwsh", "pwsh.exe", "powershell", "powershell.exe"):
        p = shutil.which(c)
        if p:
            return p
    raise RuntimeError("No PowerShell binary found on PATH (pwsh/powershell).")


def _targetable(param: ParamSpec) -> bool:
    if SSRF_PARAM_RE.search(param.name):
        return True
    v = param.sample_value or ""
    return bool(
        URL_VAL_RE.match(v) or HOST_VAL_RE.match(v) or IP_VAL_RE.match(v)
    )


def _build_input(
    endpoint: Endpoint,
    param: ParamSpec,
    payload_value: str,
    cfg: AppConfig,
) -> str:
    sample = endpoint.sample
    headers = dict(sample.headers) if sample else {}
    # Do not send cookies we shouldn't; leave it to the user's Burp proxy
    # to append session state if they've configured a match/replace.
    method = endpoint.method
    body = (sample.body if sample else "") or ""
    payload = {
        "method": method,
        "url": endpoint.sample.url if endpoint.sample else endpoint.url,
        "headers": headers,
        "body": body,
        "param": {"name": param.name, "location": param.location},
        "payload": payload_value,
        "timeout": cfg.scan.request_timeout,
        "proxy": f"http://{cfg.burp.proxy_host}:{cfg.burp.proxy_port}",
    }
    return json.dumps(payload)


def _run_probe(
    pwsh: str,
    endpoint: Endpoint,
    param: ParamSpec,
    payload: Payload,
    cfg: AppConfig,
) -> Dict:
    payload_json = _build_input(endpoint, param, payload.value, cfg)
    t0 = time.time()
    try:
        proc = subprocess.run(
            [
                pwsh,
                "-NoLogo",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(_RUNNER_PATH),
            ],
            input=payload_json,
            capture_output=True,
            text=True,
            timeout=cfg.scan.request_timeout + 15,
        )
        stdout = (proc.stdout or "").strip().splitlines()
        # The script emits one JSON line; tolerate extra lines.
        line = next(
            (l for l in reversed(stdout) if l.startswith("{") and l.endswith("}")),
            None,
        )
        if not line:
            raise RuntimeError(
                f"pwsh produced no JSON. stderr={proc.stderr[:500]!r}"
            )
        data = json.loads(line)
    except subprocess.TimeoutExpired:
        data = {
            "status": 0,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "headers": {},
            "body_excerpt": "",
            "redirect": "",
            "error": "timeout",
        }
    except Exception as e:  # noqa: BLE001
        data = {
            "status": 0,
            "elapsed_ms": int((time.time() - t0) * 1000),
            "headers": {},
            "body_excerpt": "",
            "redirect": "",
            "error": f"runner error: {e}",
        }
    return data


def run_ssrf_scan(
    cfg: AppConfig,
    endpoints: List[Endpoint],
    log: Logger = _noop,
    progress: Progress = lambda d, t: None,
) -> List[Dict]:
    pwsh = _find_pwsh()
    log(f"[scan] using {pwsh}")
    payloads = build_payloads(cfg.scan.oob_canary_url or None)
    oob_host = ""
    if cfg.scan.oob_canary_url:
        m = re.match(r"https?://([^/]+)", cfg.scan.oob_canary_url)
        if m:
            oob_host = m.group(1)

    jobs = []
    for ep in endpoints:
        for p in ep.params:
            if not _targetable(p):
                continue
            for pl in payloads:
                jobs.append((ep, p, pl))
    total = len(jobs)
    log(f"[scan] {total} probes across {len(endpoints)} endpoints")

    # Baseline latency per endpoint (one request with original value) — rough.
    baselines: Dict[str, int] = {}

    def baseline(ep: Endpoint) -> int:
        if ep.url in baselines:
            return baselines[ep.url]
        if not ep.sample:
            baselines[ep.url] = 0
            return 0
        # Reuse the real sampled value as the "payload" for a no-op probe.
        real_val = ep.params[0].sample_value if ep.params else ""
        data = _run_probe(
            pwsh,
            ep,
            ep.params[0] if ep.params else ParamSpec("_", "query"),
            Payload(real_val or "http://example.com/", "baseline"),
            cfg,
        )
        baselines[ep.url] = int(data.get("elapsed_ms") or 0)
        return baselines[ep.url]

    findings: List[Dict] = []
    done = 0

    def worker(ep: Endpoint, param: ParamSpec, pl: Payload):
        b = baseline(ep)
        data = _run_probe(pwsh, ep, param, pl, cfg)
        oob_hit = False
        if oob_host:
            headers_blob = " ".join(
                f"{k}: {v}" for k, v in (data.get("headers") or {}).items()
            )
            oob_hit = oob_host in headers_blob or oob_host in (
                data.get("body_excerpt") or ""
            )
        severity, signals = classify(
            pl.category,
            data.get("status"),
            data.get("body_excerpt") or "",
            int(data.get("elapsed_ms") or 0),
            b or None,
            oob_hit=oob_hit,
        )
        return {
            "severity": severity,
            "signals": signals,
            "endpoint": f"{ep.method} {ep.url}",
            "param": f"{param.name} [{param.location}]",
            "payload": pl.value,
            "payload_category": pl.category,
            "status": data.get("status"),
            "elapsed_ms": data.get("elapsed_ms"),
            "redirect": data.get("redirect"),
            "body_excerpt": data.get("body_excerpt", "")[:2048],
            "error": data.get("error"),
        }

    with ThreadPoolExecutor(max_workers=cfg.scan.max_concurrency) as ex:
        futures = [ex.submit(worker, ep, p, pl) for (ep, p, pl) in jobs]
        for fut in as_completed(futures):
            done += 1
            try:
                result = fut.result()
            except Exception as e:  # noqa: BLE001
                log(f"[scan] worker error: {e}")
                progress(done, total)
                continue
            if result["severity"] != "None":
                findings.append(result)
                log(
                    f"[hit] {result['severity']} {result['endpoint']} "
                    f"param={result['param']} payload={result['payload']} "
                    f"signals={result['signals']}"
                )
            progress(done, total)

    findings.sort(
        key=lambda r: (
            {"Confirmed": 0, "Likely": 1, "Possible": 2, "None": 3}.get(
                r["severity"], 9
            ),
            r["endpoint"],
        )
    )
    return findings
