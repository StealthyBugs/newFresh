# SageMaker Detached Server — Deep Dive Analysis

## Overview

The "detached server" is a Node.js HTTP server spawned by the **AWS Toolkit VS Code extension** (`amazonwebservices.aws-toolkit-vscode-3.69.0`). It acts as a local credential/session broker for SSH-based remote connections to SageMaker Spaces.

---

## Location in Snapshot

```
src_snapshot/opt/amazon/sagemaker/sagemaker-code-editor-server-data/extensions/
  amazonwebservices.aws-toolkit-vscode-3.69.0/
    dist/src/awsService/sagemaker/detached-server/server.js   ← the server itself
    dist/src/extensionNode.js                                  ← spawn logic
```

The same `aws-toolkit-vscode-3.69.0` extension exists in both:
- `sagemaker-code-editor-server-data/extensions/` (Code Editor profile)
- `sagemaker-ui-code-editor-server-data/extensions/` (SageMaker UI profile)

---

## How It Gets Spawned

### Trigger: `aws.sagemaker.openRemoteConnection` command

The detached server is started as part of the SSH remote connection flow. The call chain is:

```
User clicks "Connect" on a SageMaker Space in AWS Explorer
  → aws.sagemaker.openRemoteConnection command
    → openRemoteConnect()
      → tryRemoteConnection(spaceNode, extensionContext)
        → prepareDevEnvConnection(spaceArn, extensionContext, "sm_lc")
          → startLocalServer(extensionContext)     ← HERE
            → spawnDetachedServer(...)
```

### Spawn Code (deobfuscated from extensionNode.js)

```javascript
// startLocalServer function (exported as 'W' in minified code)
async function startLocalServer(extensionContext) {
    const globalStoragePath = extensionContext.globalStorageUri.fsPath;

    // Path to the bundled server.js
    const serverScript = extensionContext.asAbsolutePath(
        path.join("dist/src/awsService/sagemaker/detached-server/", "server.js")
    );

    // Log files
    const stdoutLog = path.join(globalStoragePath, "sagemaker-local-server.out.log");
    const stderrLog = path.join(globalStoragePath, "sagemaker-local-server.err.log");

    // Info file (pid + port)
    const infoFile = path.join(globalStoragePath, "sagemaker-local-server-info.json");

    // Optional custom endpoint override
    const sagemakerEndpoint = DevSettings.instance.get("endpoints", {}).sagemaker;

    // Stop any existing server first
    await stopLocalServer(extensionContext);

    // Spawn detached
    child_process.spawn(process.execPath, [serverScript], {
        cwd: path.dirname(serverScript),
        detached: true,
        stdio: ["ignore", fs.openSync(stdoutLog, "a"), fs.openSync(stderrLog, "a")],
        env: {
            ...process.env,
            SAGEMAKER_ENDPOINT: sagemakerEndpoint,
            SAGEMAKER_LOCAL_SERVER_FILE_PATH: infoFile
        }
    }).unref();

    // Poll for info file (20 attempts × 500ms = 10s timeout)
    for (let i = 0; i < 20; i++) {
        if (await fs.existsFile(infoFile)) return;
        await sleep(500);
    }
    throw new ToolkitError(`Timed out waiting for local server info file: ${infoFile}`);
}
```

### What `prepareDevEnvConnection` does after spawn:

1. Persists local credentials for the space ARN to `~/.aws/.sagemaker-space-profiles`
2. Calls `startLocalServer(extensionContext)` to spawn the server
3. Configures SSH config with `sagemaker_connect` proxy command
4. Sets environment: `AWS_SSM_CLI`, `SAGEMAKER_LOCAL_SERVER_FILE_PATH`, `LOG_FILE_LOCATION`
5. Returns a bound SSH process that tunnels through SSM to the remote space

---

## The Server Itself

### Binding

```javascript
http.createServer(handler).listen(0, "127.0.0.1", callback);
// Port 0 = OS assigns a random available port
// Bound to 127.0.0.1 only (loopback)
```

### Info File Written

Once listening, it writes `sagemaker-local-server-info.json`:
```json
{
  "pid": <process.pid>,
  "port": <assigned_port>
}
```

### Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| GET | `/get_session` | Start SSM session for a space (synchronous) |
| GET | `/get_session_async` | Start SSM session with browser-based auth flow |
| GET | `/refresh_token` | Callback URL for token refresh from browser |
| * | `*` | Returns 404 |

### `/get_session` Handler (deobfuscated)

```javascript
async function getSession(req, res) {
    const connectionId = url.parse(req.url, true).query.connection_identifier;
    if (!connectionId) {
        res.writeHead(400); res.end("Missing connection_identifier");
        return;
    }

    // Resolve credentials from ~/.aws/.sagemaker-space-profiles
    const credentials = await resolveCredentials(connectionId);
    const { region } = parseArn(connectionId);

    // Call SageMaker StartSession API
    const session = await startSagemakerSession({
        region, connectionIdentifier: connectionId, credentials
    });

    res.writeHead(200, {"Content-Type": "application/json"});
    res.end(JSON.stringify({
        SessionId: session.SessionId,
        StreamUrl: session.StreamUrl,
        TokenValue: session.TokenValue
    }));
}
```

### Credential Resolution

```javascript
async function resolveCredentials(connectionId) {
    const mappings = await readMappingFile();  // ~/.aws/.sagemaker-space-profiles
    const entry = mappings.localCredential?.[connectionId];

    switch (entry.type) {
        case "iam":
            return fromIAMProfile(entry.profileName);
        case "sso":
            return {
                accessKeyId: entry.accessKey,
                secretAccessKey: entry.secret,
                sessionToken: entry.token
            };
    }
}
```

### Liveness Check

```javascript
// Runs every 30 minutes (bP = 30 * 60 * 100 = 180000ms... actually 3 min, not 30)
// Checks if VS Code / Code Editor is still running
// If no VS Code process found → process.exit(0)
async function monitorVSCode() {
    for (;;) {
        if (!await isVSCodeRunning()) {
            console.log("No VSCode windows found. Shutting down detached server.");
            process.exit(0);
        }
        await new Promise(r => setTimeout(r, bP));
    }
}
```

The `isVSCodeRunning` check uses:
- **Linux**: `ps -A -o comm` → checks for `code`, `code-insiders`, or `electron`
- **macOS**: checks for `Visual Studio Code.app/Contents/MacOS/Electron`
- **Windows**: `tasklist /FI "IMAGENAME eq Code.exe"`

---

## How to Spawn the Server Manually

### Method 1: Direct Spawn (Mimicking the Extension)

```bash
# On the SageMaker instance (as sagemaker-user)

# Set up the info file path
export SAGEMAKER_LOCAL_SERVER_FILE_PATH="/tmp/sagemaker-local-server-info.json"

# Find the server.js
SERVER_JS="/opt/amazon/sagemaker/sagemaker-code-editor-server-data/extensions/amazonwebservices.aws-toolkit-vscode-3.69.0/dist/src/awsService/sagemaker/detached-server/server.js"

# Or for sagemaker-ui profile:
# SERVER_JS="/opt/amazon/sagemaker/sagemaker-ui-code-editor-server-data/extensions/amazonwebservices.aws-toolkit-vscode-3.69.0/dist/src/awsService/sagemaker/detached-server/server.js"

# Find the node binary used by Code Editor
NODE_BIN="/opt/conda/bin/node"

# Spawn it (detached, like the extension does)
cd "$(dirname "$SERVER_JS")"
nohup "$NODE_BIN" "$SERVER_JS" \
    > /tmp/sagemaker-local-server.out.log \
    2> /tmp/sagemaker-local-server.err.log &
disown

# Wait for it to start, then read port
sleep 2
cat "$SAGEMAKER_LOCAL_SERVER_FILE_PATH"
# Output: {"pid": 12345, "port": 38291}
```

### Method 2: Foreground (for debugging)

```bash
export SAGEMAKER_LOCAL_SERVER_FILE_PATH="/tmp/sagemaker-local-server-info.json"
NODE_BIN="/opt/conda/bin/node"
SERVER_JS="/opt/amazon/sagemaker/sagemaker-code-editor-server-data/extensions/amazonwebservices.aws-toolkit-vscode-3.69.0/dist/src/awsService/sagemaker/detached-server/server.js"

cd "$(dirname "$SERVER_JS")"
"$NODE_BIN" "$SERVER_JS"
# Will print: Detached server listening on http://127.0.0.1:<port> (pid: <pid>)
```

### Method 3: Via VS Code Command (Normal Flow)

From the Code Editor UI:
1. Open the AWS Explorer panel (AWS Toolkit extension)
2. Navigate to SageMaker → Spaces
3. Click on a running space
4. Select "Connect" / "Open Remote Connection"
5. This triggers `aws.sagemaker.openRemoteConnection` → spawns the server automatically

---

## Why It's Not Running on Your Instance

The detached server only spawns when:
1. A user initiates a **remote SSH connection** to a SageMaker Space from their **local** VS Code
2. The AWS Toolkit extension on the **local** machine calls `startLocalServer()`

**It does NOT run inside the SageMaker Space/instance itself.** It runs on the **developer's local machine** as a credential broker between:
- The SSH ProxyCommand (`sagemaker_connect` script)
- The SageMaker StartSession API

The server on your SageMaker instance (port 8888) is Code Editor (code-server). The detached server would only appear if someone used the AWS Toolkit to remotely connect **from outside**.

However, the `server.js` file **is present** on the instance at the path above, so it **can** be spawned manually. It will:
1. Listen on `127.0.0.1:<random_port>`
2. Write pid/port to the info file
3. Accept `/get_session`, `/get_session_async`, and `/refresh_token` requests
4. Try to resolve credentials from `~/.aws/.sagemaker-space-profiles`

---

## Security Implications

### No Authentication
The server has **zero authentication**. Any process on the same host can:
- Call `/get_session?connection_identifier=<arn>` to get SSM session tokens
- The only protection is the `127.0.0.1` binding (no remote access)

### Credential Exposure
- Reads from `~/.aws/.sagemaker-space-profiles` (plaintext credentials file)
- Returns `SessionId`, `StreamUrl`, `TokenValue` in JSON response
- These can be used to establish SSM sessions to other spaces

### Process Liveness Check Bypass
- The `isVSCodeRunning()` check looks for processes named `code`, `code-insiders`, or `electron`
- On SageMaker instances, the process is `sagemaker-code-editor` (based on code-server, not Electron)
- This means the check would **fail** and the server would exit after ~3 minutes
- Workaround: Create a dummy process named `code` to keep it alive

```bash
# Keep the detached server alive by spoofing the liveness check
cp /bin/sleep /tmp/code
/tmp/code infinity &
```

### Token Exfiltration via `/refresh_token`
The `/refresh_token` endpoint accepts credentials via query parameters:
```
GET /refresh_token?connection_identifier=X&request_id=Y&ws_url=Z&token=T&session=S
```
No validation that the caller is the legitimate browser redirect.
