// Preload for the *customized browser* window (the one routed through Burp).
// Watches for a login form on each page load and attempts to auto-fill the
// staged credentials. Falls back silently on failure — user logs in manually.

const { ipcRenderer } = require('electron');

let staged = null;

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
  staged = null; // one-shot
  return true;
}

window.addEventListener('DOMContentLoaded', () => {
  setTimeout(tryFill, 400);
  const obs = new MutationObserver(() => {
    if (tryFill()) obs.disconnect();
  });
  obs.observe(document.documentElement, { childList: true, subtree: true });
  setTimeout(() => obs.disconnect(), 15000);
});
