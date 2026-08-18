#!/usr/bin/env python3
import hashlib
import html
import json
import secrets
import sys
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlparse

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from enterprise_sim.crypto import jwks, sign_jwt, b64url
    from enterprise_sim.directory import bootstrap_directory, get_user, get_device, effective_entitlements
    from enterprise_sim.conditional_access import evaluate
    from enterprise_sim.settings import *
    from enterprise_sim.storage import load_json, save_json, now, audit
else:
    from .crypto import jwks, sign_jwt, b64url
    from .directory import bootstrap_directory, get_user, get_device, effective_entitlements
    from .conditional_access import evaluate
    from .settings import *
    from .storage import load_json, save_json, now, audit

def _hash_pkce(verifier: str):
    return b64url(hashlib.sha256(verifier.encode()).digest())

def _issue_identity_tokens(rec):
    user = get_user(rec["user"])
    ent = effective_entitlements(rec["user"])
    device = get_device(rec["device_id"])
    issued = now()
    common = {
        "iss": IDP_ISSUER,
        "sub": rec["user"],
        "tid": TENANT_ID,
        "iat": issued,
        "nbf": issued - 2,
        "exp": issued + ACCESS_TOKEN_TTL,
        "jti": str(uuid.uuid4()),
        "preferred_username": user["upn"],
        "name": user["display_name"],
        "groups": ent["groups"],
        "roles": ent["roles"],
        "device_id": rec["device_id"],
        "device_managed": bool(device.get("managed")),
        "device_compliant": bool(device.get("compliant")),
        "device_attested": bool(device.get("attested")),
        "auth_strength": "mfa",
        "amr": ["pwd", "mfa"],
        "risk_level": rec.get("risk_level", user.get("risk_level", "low")),
    }
    access = sign_jwt({
        **common,
        "aud": BROKER_AUDIENCE,
        "client_id": rec["client_id"],
        "scope": " ".join(rec.get("scopes", [])),
        "token_use": "access",
    })
    id_token = sign_jwt({
        **common,
        "aud": rec["client_id"],
        "nonce": rec.get("nonce"),
        "token_use": "id",
    })
    return access, id_token

def _login_form(action, hidden, title):
    hidden_html = "".join(
        f'<input type="hidden" name="{html.escape(str(k))}" value="{html.escape(str(v))}">'
        for k, v in hidden.items() if v is not None
    )
    return f"""<!doctype html><html><body style="font-family:Arial;max-width:720px;margin:40px auto">
    <h2>{html.escape(title)}</h2>
    <p>This is a local Microsoft Entra-style simulator. No cloud tenant or license is used.</p>
    <form method="post" action="{action}">
      {hidden_html}
      <label>User</label><br><input name="user" value="{DEFAULT_USER}"><br><br>
      <label>Password</label><br><input type="password" name="password" value="{DEFAULT_PASSWORD}"><br><br>
      <label>MFA OTP</label><br><input name="otp" value="{DEFAULT_OTP}"><br><br>
      <label>Device</label><br><input name="device_id" value="{DEFAULT_DEVICE}"><br><br>
      <label>Risk</label><br><select name="risk_level"><option>low</option><option>medium</option><option>high</option></select><br><br>
      <button type="submit">Sign in</button>
    </form></body></html>"""

class Handler(BaseHTTPRequestHandler):
    server_version = "SimulatedEntraID/1.0"

    def log_message(self, fmt, *args):
        print("[sim-idp]", fmt % args)

    def send_json(self, obj, status=200):
        raw = json.dumps(obj, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_html(self, body, status=200):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def read_form(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        return {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}

    def do_GET(self):
        parsed = urlparse(self.path)
        p, q = parsed.path, {k: v[0] for k, v in parse_qs(parsed.query).items()}
        if p == "/.well-known/openid-configuration":
            return self.send_json({
                "issuer": IDP_ISSUER,
                "authorization_endpoint": f"{IDP_ISSUER}/authorize",
                "token_endpoint": f"{IDP_ISSUER}/token",
                "jwks_uri": IDP_JWKS_URL,
                "device_authorization_endpoint": f"{IDP_ISSUER}/device/start",
                "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })
        if p == "/jwks.json":
            return self.send_json(jwks())
        if p == "/authorize":
            required = ["client_id", "redirect_uri", "state", "code_challenge"]
            if not all(q.get(x) for x in required):
                return self.send_json({"error": "missing_authorization_parameters"}, 400)
            return self.send_html(_login_form("/authorize", q, "Simulated Enterprise Sign-in"))
        if p == "/device":
            code = q.get("user_code", "")
            return self.send_html(_login_form("/device/complete", {"user_code": code}, "Complete CLI Device Sign-in"))
        if p == "/health":
            return self.send_json({"status": "ok", "issuer": IDP_ISSUER})
        return self.send_json({"error": "not_found"}, 404)

    def _validate_credentials(self, form, requested_scopes):
        user = get_user(form.get("user", ""))
        if not user or user.get("status") != "active":
            raise PermissionError("user_not_active")
        if form.get("password") != user.get("password"):
            raise PermissionError("invalid_credentials")
        if form.get("otp") != user.get("mfa_secret"):
            raise PermissionError("invalid_mfa")
        device = get_device(form.get("device_id", ""))
        decision = evaluate(
            user=user,
            device=device,
            requested_scopes=requested_scopes,
            mfa=True,
            risk_level=form.get("risk_level") or user.get("risk_level"),
        )
        # Base login can continue if privileged scopes are not requested. A PIM
        # step-up is enforced again at the broker for privileged token issuance.
        if decision.decision == "deny":
            raise PermissionError(decision.reason)
        return user, device, decision

    def do_POST(self):
        parsed = urlparse(self.path)
        p = parsed.path
        form = self.read_form()

        try:
            if p == "/authorize":
                scopes = form.get("scope", "openid profile").split()
                user, device, decision = self._validate_credentials(form, scopes)
                code = secrets.token_urlsafe(32)
                db = load_json(AUTH_CODES_FILE, {})
                db[code] = {
                    "user": user["username"],
                    "client_id": form["client_id"],
                    "redirect_uri": form["redirect_uri"],
                    "scopes": scopes,
                    "code_challenge": form["code_challenge"],
                    "device_id": device["device_id"],
                    "risk_level": form.get("risk_level", "low"),
                    "nonce": form.get("nonce"),
                    "expires_at": now() + AUTH_CODE_TTL,
                    "used": False,
                }
                save_json(AUTH_CODES_FILE, db)
                audit("oidc_authorization_code_issued", user=user["username"], client_id=form["client_id"], device_id=device["device_id"])
                location = form["redirect_uri"] + "?" + urlencode({"code": code, "state": form["state"]})
                self.send_response(302)
                self.send_header("Location", location)
                self.end_headers()
                return

            if p == "/device/start":
                client_id = form.get("client_id", CLI_CLIENT_ID)
                scopes = form.get("scope", "openid profile").split()
                device_code = secrets.token_urlsafe(32)
                user_code = secrets.token_hex(4).upper()
                db = load_json(DEVICE_CODES_FILE, {})
                db[device_code] = {
                    "client_id": client_id,
                    "scopes": scopes,
                    "user_code": user_code,
                    "authorized": False,
                    "expires_at": now() + DEVICE_CODE_TTL,
                }
                save_json(DEVICE_CODES_FILE, db)
                audit("device_code_started", client_id=client_id, scopes=scopes)
                return self.send_json({
                    "device_code": device_code,
                    "user_code": user_code,
                    "verification_uri": f"{IDP_ISSUER}/device?user_code={user_code}",
                    "expires_in": DEVICE_CODE_TTL,
                    "interval": 1,
                })

            if p == "/device/complete":
                db = load_json(DEVICE_CODES_FILE, {})
                match_key, match = None, None
                for k, rec in db.items():
                    if rec.get("user_code") == form.get("user_code"):
                        match_key, match = k, rec
                        break
                if not match or match.get("expires_at", 0) < now():
                    return self.send_json({"error": "invalid_or_expired_user_code"}, 400)
                user, device, decision = self._validate_credentials(form, match.get("scopes", []))
                match.update({
                    "authorized": True,
                    "user": user["username"],
                    "device_id": device["device_id"],
                    "risk_level": form.get("risk_level", user.get("risk_level", "low")),
                })
                db[match_key] = match
                save_json(DEVICE_CODES_FILE, db)
                audit("device_code_authorized", user=user["username"], client_id=match["client_id"], device_id=device["device_id"])
                return self.send_html("<h3>CLI sign-in complete. You may return to the terminal.</h3>")

            if p == "/token":
                grant = form.get("grant_type")
                if grant == "authorization_code":
                    db = load_json(AUTH_CODES_FILE, {})
                    rec = db.get(form.get("code"))
                    if not rec or rec.get("used") or rec.get("expires_at", 0) < now():
                        return self.send_json({"error": "invalid_grant"}, 400)
                    if rec["client_id"] != form.get("client_id") or rec["redirect_uri"] != form.get("redirect_uri"):
                        return self.send_json({"error": "client_or_redirect_mismatch"}, 400)
                    if _hash_pkce(form.get("code_verifier", "")) != rec["code_challenge"]:
                        audit("pkce_validation_failed", client_id=rec["client_id"], user=rec["user"])
                        return self.send_json({"error": "invalid_code_verifier"}, 400)
                    rec["used"] = True
                    db[form["code"]] = rec
                    save_json(AUTH_CODES_FILE, db)
                    access, id_token = _issue_identity_tokens(rec)
                    audit("idp_token_issued", user=rec["user"], client_id=rec["client_id"], grant_type="authorization_code")
                    return self.send_json({"access_token": access, "id_token": id_token, "token_type": "Bearer", "expires_in": ACCESS_TOKEN_TTL})

                if grant == "urn:ietf:params:oauth:grant-type:device_code":
                    db = load_json(DEVICE_CODES_FILE, {})
                    rec = db.get(form.get("device_code"))
                    if not rec or rec.get("expires_at", 0) < now():
                        return self.send_json({"error": "invalid_grant"}, 400)
                    if rec.get("client_id") != form.get("client_id"):
                        return self.send_json({"error": "invalid_client"}, 400)
                    if not rec.get("authorized"):
                        return self.send_json({"error": "authorization_pending"}, 400)
                    access, id_token = _issue_identity_tokens(rec)
                    del db[form["device_code"]]
                    save_json(DEVICE_CODES_FILE, db)
                    audit("idp_token_issued", user=rec["user"], client_id=rec["client_id"], grant_type="device_code")
                    return self.send_json({"access_token": access, "id_token": id_token, "token_type": "Bearer", "expires_in": ACCESS_TOKEN_TTL})

                return self.send_json({"error": "unsupported_grant_type"}, 400)

            return self.send_json({"error": "not_found"}, 404)

        except PermissionError as e:
            audit("idp_authentication_denied", reason=str(e), user=form.get("user"), device_id=form.get("device_id"))
            return self.send_json({"error": str(e)}, 403)
        except Exception as e:
            audit("idp_error", reason=str(e))
            return self.send_json({"error": str(e)}, 500)

def main():
    bootstrap_directory()
    print(f"Simulated Entra/OIDC IdP: {IDP_ISSUER}")
    print(f"Discovery: {IDP_ISSUER}/.well-known/openid-configuration")
    HTTPServer((IDP_HOST, IDP_PORT), Handler).serve_forever()

if __name__ == "__main__":
    main()
