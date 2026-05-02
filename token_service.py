import json, secrets, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from token_utils import (
    AGENT_CERT_PATH, AGENT_TOKEN_TTL_SECONDS, ACCESS_TOKEN_TTL_SECONDS, DEVICE_CERT_PATH, INTERNAL_API_AUD,
    ISSUER, ISSUER_URL, ISSUER_ID, REGION, REFRESH_TOKEN_TTL_SECONDS, STEP_UP_TOKEN_TTL_SECONDS, TOKEN_SERVICE_AUD,
    cert_thumbprint_sha256_pem, cert_to_pem_string, decode_and_validate_jwt, decode_cert_header, issue_jwt, json_load, json_save,
    jwks, now, scopes_from_claims, STATE_DIR, validate_sender_constrained_proof
)

REFRESH_DB = STATE_DIR / "refresh_tokens.json"
AGENT_DB = STATE_DIR / "agents.json"
AUDIT_DB = STATE_DIR / "audit.json"
DEVICE_CODE_DB = STATE_DIR / "device_codes.json"
USER_ID = "developer01"; CLIENT_ID = "linux-devctl"; DEVICE_ID = "linux-laptop-001"
DEFAULT_DEVICE_SCOPES = ["obo.exchange", "build.read", "gpu.job.read", "gpu.job.submit"]

def db(path, default): return json_load(path, default)
def save(path, data): json_save(path, data)

def audit(event, **fields):
    events = db(AUDIT_DB, [])
    fields.update({"event_id":str(uuid.uuid4()),"event_type": event, "timestamp": now(),"region":REGION,"issuer_id":ISSUER_ID,"decision":fields.get("decision","allow")})
    events.append(fields); save(AUDIT_DB, events[-2000:])

def new_refresh_record(user, client_id, scopes, cert_thumbprint, family_id=None, actor_type="user"):
    token = secrets.token_urlsafe(48); records = db(REFRESH_DB, {})
    records[token] = {"user": user, "client_id": client_id, "scopes": scopes, "cnf_x5t": cert_thumbprint,
                      "family_id": family_id or str(uuid.uuid4()), "actor_type": actor_type,
                      "created": now(), "expires": now() + REFRESH_TOKEN_TTL_SECONDS, "used": False, "revoked": False}
    save(REFRESH_DB, records); return token

def device_cert_thumbprint(): return cert_thumbprint_sha256_pem(cert_to_pem_string(DEVICE_CERT_PATH))

def bearer(headers):
    a = headers.get("Authorization", "")
    return a.split(" ", 1)[1] if a.startswith("Bearer ") else None

class Handler(BaseHTTPRequestHandler):
    server_version = "TokenServiceDemo/1.0"
    def log_message(self, fmt, *args): print("[token_service]" , fmt % args)
    def read_json(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        if length == 0: return {}
        return json.loads(self.rfile.read(length).decode() or "{}")
    def send_json(self, data, status=200):
        raw = json.dumps(data, indent=2).encode()
        self.send_response(status); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def route_path(self): return urlparse(self.path).path
    def do_GET(self):
        p = self.route_path()
        try:
            if p == "/.well-known/jwks.json": return self.send_json(jwks())
            if p == "/.well-known/openid-configuration": return self.send_json({"issuer":ISSUER_URL,"jwks_uri":f"{ISSUER_URL}/.well-known/jwks.json","id_token_signing_alg_values_supported":["RS256"],"token_endpoint":f"{ISSUER_URL}/token/poll"})
            if p == "/audit": return self.send_json(db(AUDIT_DB, []))
            if p == "/health": return self.send_json({"status":"ok", "issuer": ISSUER})
            return self.send_json({"error":"not found"}, 404)
        except Exception as e: return self.send_json({"error": str(e)}, 500)
    def do_POST(self):
        p = self.route_path(); body = self.read_json()
        try:
            if p == "/device/start": return self.device_start(body)
            if p == "/device/complete": return self.device_complete(body)
            if p == "/token/poll": return self.token_poll(body)
            if p == "/token/refresh": return self.token_refresh(body)
            if p == "/obo/exchange": return self.obo_exchange(body)
            if p == "/stepup": return self.stepup(body)
            if p == "/agent/register": return self.agent_register(body)
            if p == "/agent/disable": return self.agent_disable(body, "disabled")
            if p == "/agent/enable": return self.agent_disable(body, "active")
            if p == "/agent/token": return self.agent_token(body)
            if p == "/introspect": return self.introspect(body)
            if p == "/revoke": return self.revoke(body)
            return self.send_json({"error":"not found"}, 404)
        except Exception as e:
            audit("handler_error", path=p, reason=str(e)); return self.send_json({"error": str(e)}, 500)
    def device_start(self, body):
        client_id = body.get("client_id", CLIENT_ID); scopes = body.get("scopes", DEFAULT_DEVICE_SCOPES)
        device_code = secrets.token_urlsafe(32); user_code = secrets.token_hex(4).upper(); codes = db(DEVICE_CODE_DB, {})
        codes[device_code] = {"client_id": client_id, "scopes": scopes, "user_code": user_code, "authorized": False, "user": USER_ID, "created": now()}
        save(DEVICE_CODE_DB, codes); audit("device_code_started", client_id=client_id, scopes=scopes)
        return self.send_json({"device_code": device_code, "user_code": user_code, "verification_uri": f"{ISSUER}/device/complete", "message": f"Open {ISSUER}/device/complete and enter code {user_code}. Demo supports --auto."})
    def device_complete(self, body):
        from token_utils import verify_proof
        from device_registry import check_device_posture
        from policy_engine import evaluate_policy
        user_code = body.get("user_code"); cert_pem = body.get("device_cert_pem"); proof_sig = body.get("proof_signature")
        proof_token = body.get("proof_token", "device-login-proof")
        if not user_code or not cert_pem or not proof_sig: return self.send_json({"error":"user_code, device_cert_pem, proof_signature required"}, 400)
        expected = device_cert_thumbprint()
        if cert_thumbprint_sha256_pem(cert_pem) != expected or not verify_proof(cert_pem, proof_sig, proof_token, "POST", "/device/complete"):
            audit("device_login_failed"); return self.send_json({"error":"device certificate/private key proof failed"}, 401)
        codes = db(DEVICE_CODE_DB, {})
        for code, rec in codes.items():
            if rec.get("user_code") == user_code:
                rec["authorized"] = True; rec["device_thumbprint"] = expected; save(DEVICE_CODE_DB, codes)
                audit("device_code_authorized", user=rec["user"], client_id=rec["client_id"], device_id=DEVICE_ID)
                return self.send_json({"status":"authorized", "user": rec["user"], "device_id": DEVICE_ID})
        return self.send_json({"error":"invalid user_code"}, 404)
    def token_poll(self, body):
        codes = db(DEVICE_CODE_DB, {}); rec = codes.get(body.get("device_code"))
        if not rec: return self.send_json({"error":"invalid device_code"}, 404)
        if not rec.get("authorized"): return self.send_json({"status":"authorization_pending"}, 202)
        access = issue_jwt(subject=rec["user"], audience=TOKEN_SERVICE_AUD, client_id=rec["client_id"], scopes=rec["scopes"], actor_type="user", cnf_x5t=rec["device_thumbprint"], extra_claims={"device_id": DEVICE_ID, "auth_strength":"mfa", "idp":"entra-simulated"})
        refresh = new_refresh_record(rec["user"], rec["client_id"], rec["scopes"], rec["device_thumbprint"])
        del codes[body.get("device_code")]; save(DEVICE_CODE_DB, codes)
        audit("token_issued", user=rec["user"], actor_type="user", audience=TOKEN_SERVICE_AUD, scope=" ".join(rec["scopes"]), device_id=DEVICE_ID, reason="ok", correlation_id=str(uuid.uuid4()))
        return self.send_json({"access_token": access, "refresh_token": refresh, "token_type":"Bearer", "expires_in": ACCESS_TOKEN_TTL_SECONDS})
    def token_refresh(self, body):
        from token_utils import verify_proof
        from device_registry import check_device_posture
        from policy_engine import evaluate_policy
        rt = body.get("refresh_token"); cert_pem = body.get("device_cert_pem"); proof_sig = body.get("proof_signature"); records = db(REFRESH_DB, {}); rec = records.get(rt)
        if not rec: return self.send_json({"error":"invalid refresh token"}, 401)
        if rec.get("revoked") or rec.get("expires",0) < now(): return self.send_json({"error":"refresh token expired/revoked"}, 401)
        if rec.get("used"):
            fam = rec["family_id"]
            for r in records.values():
                if r.get("family_id") == fam: r["revoked"] = True
            save(REFRESH_DB, records); audit("refresh_reuse_detected_family_revoked", family_id=fam, user=rec["user"])
            return self.send_json({"error":"refresh token reuse detected; token family revoked"}, 401)
        if not cert_pem or cert_thumbprint_sha256_pem(cert_pem) != rec["cnf_x5t"] or not verify_proof(cert_pem, proof_sig, rt, "POST", "/token/refresh"):
            return self.send_json({"error":"device proof failed"}, 401)
        rec["used"] = True
        access = issue_jwt(subject=rec["user"], audience=TOKEN_SERVICE_AUD, client_id=rec["client_id"], scopes=rec["scopes"], actor_type=rec.get("actor_type","user"), cnf_x5t=rec["cnf_x5t"], extra_claims={"device_id": DEVICE_ID, "auth_strength":"mfa", "idp":"entra-simulated"})
        new_rt = new_refresh_record(rec["user"], rec["client_id"], rec["scopes"], rec["cnf_x5t"], family_id=rec["family_id"])
        save(REFRESH_DB, records); audit("token_refreshed", user=rec["user"], family_id=rec["family_id"])
        return self.send_json({"access_token": access, "refresh_token": new_rt, "token_type":"Bearer", "expires_in": ACCESS_TOKEN_TTL_SECONDS})
    def obo_exchange(self, body):
        incoming = bearer(self.headers); requested = body.get("scopes", ["build.read"]); target_aud = body.get("audience", INTERNAL_API_AUD)
        try:
            claims = decode_and_validate_jwt(incoming, TOKEN_SERVICE_AUD)
            validate_sender_constrained_proof(claims, decode_cert_header(self.headers.get("X-Client-Cert", "")), self.headers.get("X-Proof-Signature"), incoming, "POST", "/obo/exchange")
            if "obo.exchange" not in scopes_from_claims(claims): raise ValueError("missing obo.exchange scope")
            allowed = scopes_from_claims(claims)
            if not set(requested).issubset(allowed): raise ValueError("requested OBO scopes exceed user/client grant")
            downstream = issue_jwt(subject=claims["sub"], audience=target_aud, client_id="central-token-service-obo", scopes=requested, actor_type="user", cnf_x5t=(claims.get("cnf") or {}).get("x5t#S256"), extra_claims={"obo": True, "original_client_id": claims.get("client_id"), "device_id": claims.get("device_id"), "auth_strength": claims.get("auth_strength","mfa")})
            audit("obo_token_issued", user=claims["sub"], scopes=requested, audience=target_aud)
            return self.send_json({"access_token": downstream, "token_type":"Bearer", "expires_in": ACCESS_TOKEN_TTL_SECONDS})
        except Exception as e: audit("obo_failed", reason=str(e)); return self.send_json({"error": str(e)}, 401)
    def stepup(self, body):
        incoming = bearer(self.headers); requested = body.get("scopes", ["deploy.prod"]); audience = body.get("audience", INTERNAL_API_AUD)
        try:
            claims = decode_and_validate_jwt(incoming, TOKEN_SERVICE_AUD)
            validate_sender_constrained_proof(claims, decode_cert_header(self.headers.get("X-Client-Cert", "")), self.headers.get("X-Proof-Signature"), incoming, "POST", "/stepup")
            token = issue_jwt(subject=claims["sub"], audience=audience, client_id="central-token-service-stepup", scopes=requested, actor_type="user", ttl_seconds=STEP_UP_TOKEN_TTL_SECONDS, cnf_x5t=(claims.get("cnf") or {}).get("x5t#S256"), extra_claims={"pim": True, "auth_strength":"step_up_mfa", "approval_id": f"APR-{secrets.token_hex(4).upper()}", "reason": body.get("reason", "privileged operation"), "device_id": claims.get("device_id")})
            audit("stepup_token_issued", user=claims["sub"], scopes=requested); return self.send_json({"access_token": token, "token_type":"Bearer", "expires_in": STEP_UP_TOKEN_TTL_SECONDS})
        except Exception as e: audit("stepup_failed", reason=str(e)); return self.send_json({"error": str(e)}, 401)
    def agent_register(self, body):
        agent_id = body.get("agent_id", "agent-gpu-planner-dev"); agents = db(AGENT_DB, {}); cert_pem = cert_to_pem_string(AGENT_CERT_PATH)
        agents[agent_id] = {"agent_id": agent_id, "agent_owner": body.get("agent_owner", "platform-security"), "environment": body.get("environment", "dev"), "purpose": body.get("purpose", "submit controlled GPU jobs and comment on PRs"), "allowed_scopes": body.get("allowed_scopes", ["repo.read", "pr.comment", "gpu.job.submit", "gpu.job.read"]), "gpu_quota_max_jobs": body.get("gpu_quota_max_jobs", 1), "cnf_x5t": cert_thumbprint_sha256_pem(cert_pem), "status": body.get("status","active")}
        save(AGENT_DB, agents); audit("agent_registered", agent_id=agent_id, scopes=agents[agent_id]["allowed_scopes"]); return self.send_json(agents[agent_id])
    def agent_token(self, body):
        from token_utils import verify_proof
        from device_registry import check_device_posture
        from policy_engine import evaluate_policy
        agent_id = body.get("agent_id"); requested = body.get("scopes", ["pr.comment"]); cert_pem = decode_cert_header(self.headers.get("X-Client-Cert", "")); proof_sig = self.headers.get("X-Proof-Signature"); proof_token = body.get("proof_token", "agent-token-proof")
        agents = db(AGENT_DB, {}); agent = agents.get(agent_id)
        if not agent: return self.send_json({"error":"agent_not_found"}, 404)
        if agent.get("status") != "active": return self.send_json({"error":"agent_not_active"}, 403)
        try:
            if cert_thumbprint_sha256_pem(cert_pem) != agent["cnf_x5t"] or not verify_proof(cert_pem, proof_sig, proof_token, "POST", "/agent/token"): raise ValueError("certificate_binding_failed")
            if not body.get("initiating_user"): raise ValueError("initiating_user_missing")
            if not set(requested).issubset(set(agent["allowed_scopes"])): raise ValueError("requested scopes exceed agent policy")
            token = issue_jwt(subject=f"agent:{agent_id}", audience=INTERNAL_API_AUD, client_id="agent-runtime", scopes=requested, actor_type="agent", ttl_seconds=AGENT_TOKEN_TTL_SECONDS, cnf_x5t=agent["cnf_x5t"], extra_claims={"agent_id": agent_id, "agent_owner": agent["agent_owner"], "environment": agent["environment"], "initiating_user": body.get("initiating_user", "developer01"), "delegation_type":"user_delegated", "gpu_quota_max_jobs": agent["gpu_quota_max_jobs"]})
            audit("agent_token_issued", actor_type="agent", agent_id=agent_id, user=body.get("initiating_user"), scope=" ".join(requested), reason="ok", correlation_id=str(uuid.uuid4())); return self.send_json({"access_token": token, "token_type":"Bearer", "expires_in": AGENT_TOKEN_TTL_SECONDS})
        except Exception as e: audit("agent_token_failed", agent_id=agent_id, reason=str(e)); return self.send_json({"error": str(e)}, 401)
    def agent_disable(self, body, status):
        agents = db(AGENT_DB, {})
        aid = body.get("agent_id")
        if aid not in agents:
            return self.send_json({"error":"agent_not_found"}, 404)
        agents[aid]["status"] = status
        save(AGENT_DB, agents)
        audit("agent_status_changed", agent_id=aid, reason=status)
        return self.send_json(agents[aid])

    def introspect(self, body):
        try:
            claims = decode_and_validate_jwt(body.get("token"), body.get("audience", INTERNAL_API_AUD)); return self.send_json({"active": True, "claims": claims})
        except Exception as e: return self.send_json({"active": False, "error": str(e)})
    def revoke(self, body):
        fam = body.get("family_id"); records = db(REFRESH_DB, {}); count = 0
        for r in records.values():
            if fam is None or r.get("family_id") == fam: r["revoked"] = True; count += 1
        save(REFRESH_DB, records); audit("refresh_tokens_revoked", count=count, family_id=fam); return self.send_json({"revoked_count": count})

if __name__ == "__main__":
    print("Centralized token service running on http://127.0.0.1:8000")
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()


    