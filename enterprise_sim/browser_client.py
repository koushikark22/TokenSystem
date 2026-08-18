#!/usr/bin/env python3
import hashlib
import html
import json
import secrets
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

import requests

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from enterprise_sim.broker import exchange_enterprise_token
    from enterprise_sim.crypto import b64url, decode_unverified
    from enterprise_sim.settings import *
    from enterprise_sim.storage import load_json, save_json, audit
else:
    from .broker import exchange_enterprise_token
    from .crypto import b64url, decode_unverified
    from .settings import *
    from .storage import load_json, save_json, audit

def _sessions():
    return load_json(PORTAL_SESSION_FILE, {})

def _save_sessions(s):
    save_json(PORTAL_SESSION_FILE, s)

class Handler(BaseHTTPRequestHandler):
    server_version = "EnterprisePortal/1.0"

    def log_message(self, fmt, *args):
        print("[portal]", fmt % args)

    def send_html(self, body, status=200):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        parsed = urlparse(self.path)
        p = parsed.path
        q = {k: v[0] for k, v in parse_qs(parsed.query).items()}

        if p == "/":
            return self.send_html(f"""<!doctype html><html><body style="font-family:Arial;max-width:900px;margin:40px auto">
            <h1>TokenSystem Enterprise Portal</h1>
            <p>Local browser SSO lab using a simulated OIDC identity provider.</p>
            <ul>
              <li><a href="/login">Sign in (Authorization Code + PKCE)</a></li>
              <li><a href="/login?scope=build.read">Request build.read</a></li>
              <li><a href="/login?scope=deploy.prod">Request deploy.prod (requires PIM)</a></li>
            </ul>
            <p>For privileged access, activate PIM first from the CLI.</p>
            </body></html>""")

        if p == "/login":
            state = secrets.token_urlsafe(24)
            verifier = secrets.token_urlsafe(48)
            challenge = b64url(hashlib.sha256(verifier.encode()).digest())
            scope = q.get("scope", "build.read")
            sessions = _sessions()
            sessions[state] = {"verifier": verifier, "requested_scope": scope}
            _save_sessions(sessions)
            params = {
                "response_type": "code",
                "client_id": PORTAL_CLIENT_ID,
                "redirect_uri": PORTAL_REDIRECT_URI,
                "scope": f"openid profile {scope}",
                "state": state,
                "nonce": secrets.token_urlsafe(12),
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
            self.send_response(302)
            self.send_header("Location", f"{IDP_ISSUER}/authorize?{urlencode(params)}")
            self.end_headers()
            return

        if p == "/callback":
            state, code = q.get("state"), q.get("code")
            sessions = _sessions()
            rec = sessions.pop(state, None)
            _save_sessions(sessions)
            if not rec or not code:
                return self.send_html("<h3>Invalid callback state.</h3>", 400)

            token_resp = requests.post(f"{IDP_ISSUER}/token", data={
                "grant_type": "authorization_code",
                "client_id": PORTAL_CLIENT_ID,
                "redirect_uri": PORTAL_REDIRECT_URI,
                "code": code,
                "code_verifier": rec["verifier"],
            }, timeout=5)
            if token_resp.status_code != 200:
                return self.send_html(f"<pre>{html.escape(token_resp.text)}</pre>", token_resp.status_code)

            tokens = token_resp.json()
            requested_scope = rec["requested_scope"]
            try:
                internal = exchange_enterprise_token(tokens["access_token"], requested_scope.split())
                ext_claims = decode_unverified(tokens["access_token"])
                int_claims = decode_unverified(internal)
                audit("browser_federation_completed", user=ext_claims.get("sub"), scope=requested_scope)
                return self.send_html(f"""<h2>Federation succeeded</h2>
                <h3>External IdP token claims</h3><pre>{html.escape(json.dumps(ext_claims, indent=2))}</pre>
                <h3>Internal TokenSystem token claims</h3><pre>{html.escape(json.dumps(int_claims, indent=2))}</pre>
                <p><a href="/">Back</a></p>""")
            except Exception as e:
                return self.send_html(f"<h3>Broker denied token issuance</h3><pre>{html.escape(str(e))}</pre><p><a href='/'>Back</a></p>", 403)

        return self.send_html("<h3>Not found</h3>", 404)

def main():
    print(f"Enterprise browser portal: {PORTAL_BASE}")
    HTTPServer((PORTAL_HOST, PORTAL_PORT), Handler).serve_forever()

if __name__ == "__main__":
    main()
