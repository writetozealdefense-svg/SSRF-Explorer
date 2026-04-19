// Preload for the customized browser window (routed through Burp).
//
// Responsibilities:
//   1. Auto-fill staged credentials on any detected login form.
//   2. Detect the "user has logged in" transition and notify the main process
//      so it can kick off the automatic recon crawl. Heuristic:
//        - We previously saw a password field on the page, AND
//        - That password field is gone now, AND
//        - Either the URL has changed since we first saw it, or 2s of DOM
//          stability has passed (handles SPA logins that don't change URL).

const { ipcRenderer } = require('electron');

let staged = null;
let sawPassword = false;
let initialHref = null;
let firedLoggedIn = false;
let lastPwdGoneAt = null;

ipcRenderer.on('stage-credentials', (_evt, creds) => {
  staged = creds;
  tryFill();
});

function findFields() {
  const pwd = document.querySelector('input[type="password"]');
  if (!pwd) return null;
  const form = pwd.closest('form');
  const userSelector =
    'input[type="email"], input[type="text"], ' +
    'input[name*="user" i], input[name*="email" i], ' +
    'input[id*="user" i], input[id*="email" i]';
  const user = (form && form.querySelector(userSelector)) || document.querySelector(userSelector);
  const submit = (form && (form.querySelector('button[type="submit"], input[type="submit"], button'))) || null;
  return { user, pwd, submit, form };
}

function setValue(el, v) {
  const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
  descriptor.set.call(el, v);
  el.dispatchEvent(new Event('input', { bubbles: true }));
  el.dispatchEvent(new Event('change', { bubbles: true }));
}

function tryFill() {
  if (!staged) return false;
  const fields = findFields();
  if (!fields) return false;
  if (fields.user) setValue(fields.user, staged.username);
  setValue(fields.pwd, staged.password);
  if (fields.submit) fields.submit.click();
  else if (fields.form) fields.form.submit();
  staged = null;
  return true;
}

function checkLoginState() {
  if (firedLoggedIn) return;
  const hasPwd = !!document.querySelector('input[type="password"]');
  if (hasPwd) {
    sawPassword = true;
    lastPwdGoneAt = null;
    return;
  }
  if (!sawPassword) return;

  const urlChanged = initialHref !== null && location.href !== initialHref;
  if (urlChanged) {
    firedLoggedIn = true;
    ipcRenderer.send('browser:logged-in', { url: location.href });
    return;
  }
  // Same URL, no password — might be an SPA swap. Require 2s of stability.
  const now = Date.now();
  if (lastPwdGoneAt === null) { lastPwdGoneAt = now; return; }
  if (now - lastPwdGoneAt >= 2000) {
    firedLoggedIn = true;
    ipcRenderer.send('browser:logged-in', { url: location.href });
  }
}

window.addEventListener('DOMContentLoaded', () => {
  if (initialHref === null) initialHref = location.href;
  setTimeout(tryFill, 400);
  checkLoginState();

  const obs = new MutationObserver(() => {
    if (!firedLoggedIn) {
      // tryFill still benefits from mutation observation for slow-rendering
      // login forms; stop once we've filled or detected login.
      if (tryFill()) { /* no-op */ }
      checkLoginState();
    }
  });
  obs.observe(document.documentElement, { childList: true, subtree: true });

  // Safety-net periodic check — some SPAs mutate without firing DOM events we
  // observe, so poll every second for 30s.
  let ticks = 0;
  const pollId = setInterval(() => {
    ticks++;
    checkLoginState();
    if (firedLoggedIn || ticks > 30) { clearInterval(pollId); obs.disconnect(); }
  }, 1000);
});
