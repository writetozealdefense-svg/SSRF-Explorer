# SSRF Explorer — MERN + Electron

Classic desktop app for **authorized** SSRF testing, built on the MERN stack and packaged as an Electron desktop application.

- **M**ongoDB — optional persistence (users, targets, endpoints, findings). Falls back to in-memory if `MONGODB_URI` is unset.
- **E**xpress — local API backed by Node services.
- **R**eact + Vite — desktop UI (sidebar-driven workflow).
- **N**ode — spawns Windows PowerShell to fire SSRF probes via `Invoke-WebRequest`.
- **Electron** — desktop shell + a second *customized browser* window routed through Burp.

> You may only run this tool against targets you **own** or have **written permission** to test. A mandatory in-app attestation gate blocks every scan action until it is signed.

---

## Layout

```
electron/        main.js, preload.js, browserPreload.js
server/          Express + Mongoose + services
  scripts/ssrf_probe.ps1      Windows PowerShell probe
  services/    burpParser.js, burpRest.js, enumerator.js, ssrfRunner.js, detector.js, payloads.js
  routes/      auth, targets, burp, enumerate, ssrf, report
client/          React + Vite
  src/components/  LoginView, TargetConfig, AuthGate, CustomBrowser, EndpointsView, SsrfResults, ReportView
legacy-python/   older PyQt6 prototype (kept for reference)
```

## Prerequisites

- Node 20+
- Windows PowerShell 5.1 (built-in) or PowerShell 7 (`pwsh`) on PATH
- Burp Suite Community/Pro listening on `127.0.0.1:8080` (configurable)
- (Optional) MongoDB running locally — set `MONGODB_URI=mongodb://localhost:27017/ssrf-explorer`

## Install & run

```
npm install
npm run dev          # runs Vite + Electron in dev mode
# or:
npm start            # builds the React bundle and launches Electron
```

## Workflow

The sidebar enforces the order.

1. **Sign in** — first launch creates the admin account; later runs log in.
2. **Target** — URL, scope hosts, creds, Burp proxy host/port, optional REST URL + key or XML history path, scan params.
3. **Authorize** — operator + written-authorization reference + attestation checkbox. Recorded in Mongo (or memory) and printed on every report. *On success, if a Burp source is configured, the app auto-pulls traffic and auto-runs enumeration.*
4. **Customized browser** — opens a new Electron `BrowserWindow` routed through `http://<proxyHost>:<proxyPort>`, trusts Burp's CA, auto-fills the target login form (falls back to manual), persists session state per target, and records every HTTP request via `session.webRequest`. **When you close the window, the captured traffic is automatically fed to enumeration and you jump to the Endpoints tab.**
5. **Enumerate** — dedupes `(method, host, path-template, param-set)`, scores each endpoint for attack surface.
6. **API Security Scan** — runs the **OWASP API Top 10 (2023)** test matrix against every enumerated endpoint via PowerShell `Invoke-WebRequest`, routed through Burp. Auth headers/cookies captured in the sample request are reused so probes run as the authenticated user. Pick which categories to run; every probe appears in your Burp history.
7. **Report** — HTML + JSON written to `./reports/`, including the authorization record and per-category breakdown.

## OWASP API Top 10 coverage

| ID           | Category                                         | How it's tested |
|--------------|--------------------------------------------------|-----------------|
| API1:2023    | Broken Object Level Authorization (BOLA)         | ID substitution on numeric / UUID params; compares body vs. baseline |
| API2:2023    | Broken Authentication                            | Strips `Authorization`, `Cookie`, `X-API-Key`, `X-Auth-Token`; 2xx → flag |
| API3:2023    | Broken Object Property Level Authorization (mass assignment) | Injects `isAdmin`, `role=admin`, `permissions=["*"]`, etc. into body on POST/PUT/PATCH |
| API4:2023    | Unrestricted Resource Consumption                | 30× rapid-fire; flags absence of 429/503 |
| API5:2023    | Broken Function Level Authorization (BFLA)       | Swaps HTTP method to DELETE / PUT / PATCH; 2xx → flag |
| API6:2023    | Sensitive Business Flows                         | *Not automated — needs human judgement.* |
| API7:2023    | Server-Side Request Forgery (SSRF)               | Loopback / private IP / AWS+GCP+Azure metadata / `file://` / `dict://` / `gopher://` / optional OOB canary |
| API8:2023    | Security Misconfiguration                        | Missing security headers; CORS `*` + credentials; verbose stack traces; version disclosure |
| API9:2023    | Improper Inventory Management                    | `/vN/` version swap + `/api/old\|dev\|debug\|internal\|beta/` siblings |
| API10:2023   | Unsafe Consumption of APIs                       | *Not automated — server-side behavior.* |

## Detection signals (examples)

- Cloud-metadata markers in body (`ami-id`, `computeMetadata`, `Metadata-Flavor`) → **Confirmed** (API7)
- Local-file markers (`root:x:0:0`, `[extensions]`) → **Confirmed** (API7)
- OOB canary callback → **Confirmed** (API7)
- Auth stripped → identical body → **Likely** (API2)
- DELETE/PUT returning 2xx → **Likely** (API5)
- `CORS *` + credentials true → **Likely** (API8)
- Stack trace in body → **Likely** (API8)
- No 429 across 30 requests → **Likely** (API4)
- BOLA: 2xx with different body on other IDs → **Possible** (API1)
- Timing delta > 1.5s → **Possible** (API7)

## Safety controls

- Attestation record required before `/api/ssrf/scan` executes.
- Scope hostnames enforced at enumeration time; out-of-scope traffic is filtered out.
- Every probe is routed through Burp, so you retain full visibility / kill-switch.
- MongoDB stores operator + engagement reference per authorization; both appear in every generated report.
