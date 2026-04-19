"""Playwright-driven stateful browser, routed through Burp.

Runs synchronously in a worker thread. Persists session state in ``profile_dir``
so login survives across runs. Attempts automatic credential fill; falls back
to the user completing login interactively.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable

from ssrf_explorer.config import AppConfig

Logger = Callable[[str], None]


def _ignore(_: str) -> None:
    pass


AUTO_LOGIN_JS = r"""
(async ({ user, pwd }) => {
  const pwdEl = document.querySelector('input[type="password"]');
  if (!pwdEl) return { ok: false, reason: 'no password field' };
  let userEl = pwdEl
    .closest('form')
    ?.querySelector('input[type="email"], input[type="text"], input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i]');
  if (!userEl) {
    userEl = document.querySelector(
      'input[type="email"], input[name*="user" i], input[name*="email" i], input[id*="user" i], input[id*="email" i]'
    );
  }
  const set = (el, v) => {
    const d = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    d.call(el, v);
    el.dispatchEvent(new Event('input', { bubbles: true }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
  };
  if (userEl) set(userEl, user);
  set(pwdEl, pwd);
  const submit = pwdEl.closest('form')?.querySelector(
    'button[type="submit"], input[type="submit"], button'
  );
  if (submit) submit.click();
  else pwdEl.form?.submit();
  return { ok: true };
})
"""


def launch_browser_and_login(cfg: AppConfig, log: Logger = _ignore) -> None:
    from playwright.sync_api import sync_playwright

    cfg.profile_dir.mkdir(parents=True, exist_ok=True)
    profile = str(Path(cfg.profile_dir).absolute())

    proxy = {"server": f"http://{cfg.burp.proxy_host}:{cfg.burp.proxy_port}"}
    args = ["--ignore-certificate-errors"]  # trust Burp's CA transparently

    log(f"[browser] launching Chromium via {proxy['server']} (profile: {profile})")

    with sync_playwright() as p:
        context = p.chromium.launch_persistent_context(
            user_data_dir=profile,
            headless=False,
            proxy=proxy,
            args=args,
            ignore_https_errors=True,
            accept_downloads=True,
        )
        page = context.pages[0] if context.pages else context.new_page()

        try:
            log(f"[browser] navigating to {cfg.target.url}")
            page.goto(cfg.target.url, wait_until="domcontentloaded", timeout=45000)
        except Exception as e:  # noqa: BLE001
            log(f"[browser] navigation error: {e}")

        if cfg.target.username and cfg.target.password:
            log("[browser] attempting automatic credential fill...")
            try:
                page.wait_for_selector('input[type="password"]', timeout=8000)
                res = page.evaluate(
                    AUTO_LOGIN_JS,
                    {"user": cfg.target.username, "pwd": cfg.target.password},
                )
                log(f"[browser] auto-login: {res}")
            except Exception as e:  # noqa: BLE001
                log(f"[browser] auto-login skipped: {e}")
        else:
            log("[browser] no credentials supplied; log in manually.")

        log(
            "[browser] Browser is open. Crawl the application, then CLOSE the window "
            "when done. Session will persist for the next run."
        )
        # Block until the user closes the window.
        try:
            page.wait_for_event("close", timeout=0)
        except Exception:
            pass
        try:
            context.close()
        except Exception:
            pass
        log("[browser] context closed.")
