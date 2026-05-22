import json, secrets, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from user_registry import ensure_default_user, get_user, list_users, register_user, set_user_status
from device_registry import check_device_posture

from token_utils import (
    AGENT_CERT_PATH, AGENT_TOKEN_TTL_SECONDS, ACCESS_TOKEN_TTL_SECONDS, DEVICE_CERT_PATH, INTERNAL_API_AUD,
    ISSUER, ISSUER_URL, ISSUER_ID, REGION, REFRESH_TOKEN_TTL_SECONDS, STEP_UP_TOKEN_TTL_SECONDS, TOKEN_SERVICE_AUD,
    cert_thumbprint_sha256_pem, cert_to_pem_string, decode_and_validate_jwt, decode_cert_header, issue_jwt, json_load, json_save,
    jwks, now, scopes_from_claims, STATE_DIR, validate_sender_constrained_proof, write_audit_event, revoke_jti, is_jti_revoked
)
from device_attestation import validate_attestation
import os

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
    write_audit_event(event, fields)


def _decision(reason="ok", decision="allow", risk_level="low"):
    return {"policy_id": "jwt-demo-policy", "policy_version": "2026.05", "decision_id": f"dec-{uuid.uuid4()}", "decision": decision, "risk_level": risk_level, "reason": reason}

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
            if p == "/agents": return self.send_json({"agents": list(db(AGENT_DB, {}).values())})
            if p.startswith("/agent/status/"):
                agent_id = p.split("/agent/status/",1)[1]
                agent = db(AGENT_DB, {}).get(agent_id)
                return self.send_json(agent or {"error":"agent_not_found"}, 200 if agent else 404)
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
            if p == "/agent/task/create": return self.agent_task_create(body)
            if p == "/agent/task/approve": return self.agent_task_approve(body)
            if p == "/agent/task/token": return self.agent_task_token(body)
            if p == "/agent/rotate-cert": return self.agent_rotate_cert(body)
            if p == "/introspect": return self.introspect(body)
            if p == "/revoke": return self.revoke(body)
            return self.send_json({"error":"not found"}, 404)
        except Exception as e:
            audit("handler_error", path=p, reason=str(e)); return self.send_json({"error": str(e)}, 500)
    def device_start(self, body):
        ensure_default_user()
        client_id = body.get("client_id", CLIENT_ID); scopes = body.get("scopes", DEFAULT_DEVICE_SCOPES)
        user_id = body.get("user", USER_ID)
        device_code = secrets.token_urlsafe(32); user_code = secrets.token_hex(4).upper(); codes = db(DEVICE_CODE_DB, {})
        codes[device_code] = {"client_id": client_id, "scopes": scopes, "user_code": user_code, "authorized": False, "user": user_id, "created": now()}
        save(DEVICE_CODE_DB, codes); audit("device_code_started", client_id=client_id, scopes=scopes)
        return self.send_json({"device_code": device_code, "user_code": user_code, "verification_uri": f"{ISSUER}/device/complete", "message": f"Device code: {user_code}"})
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
        ensure_default_user()
        codes = db(DEVICE_CODE_DB, {}); rec = codes.get(body.get("device_code"))
        if not rec: return self.send_json({"error":"invalid device_code"}, 404)
        if not rec.get("authorized"): return self.send_json({"status":"authorization_pending"}, 202)
        u=get_user(rec["user"])
        if not u or u.get("status")!="active":
            return self.send_json({"error":"user_not_active"},403)
        access = issue_jwt(subject=rec["user"], audience=TOKEN_SERVICE_AUD, client_id=rec["client_id"], scopes=rec["scopes"], actor_type="user", cnf_x5t=rec["device_thumbprint"], extra_claims={"device_id": DEVICE_ID, "auth_strength":"mfa", "idp":"entra-simulated"})
        evidence = _decision()
        access = issue_jwt(subject=rec["user"], audience=TOKEN_SERVICE_AUD, client_id=rec["client_id"], scopes=rec["scopes"], actor_type="user", cnf_x5t=rec["device_thumbprint"], extra_claims={"device_id": DEVICE_ID, "auth_strength":"mfa", "idp":"entra-simulated", **evidence})
        refresh = new_refresh_record(rec["user"], rec["client_id"], rec["scopes"], rec["device_thumbprint"])
        del codes[body.get("device_code")]; save(DEVICE_CODE_DB, codes)
        audit("token_issued", user=rec["user"], actor_type="user", audience=TOKEN_SERVICE_AUD, scope=" ".join(rec["scopes"]), device_id=DEVICE_ID, correlation_id=str(uuid.uuid4()), **evidence)
        return self.send_json({"access_token": access, "refresh_token": refresh, "token_type":"Bearer", "expires_in": ACCESS_TOKEN_TTL_SECONDS})
    def token_refresh(self, body):
        ensure_default_user()
        from token_utils import verify_proof
        from device_registry import check_device_posture
        from policy_engine import evaluate_policy
        rt = body.get("refresh_token"); cert_pem = body.get("device_cert_pem"); proof_sig = body.get("proof_signature"); records = db(REFRESH_DB, {}); rec = records.get(rt)
        if not rec: return self.send_json({"error":"invalid refresh token"}, 401)
        if rec.get("revoked") or rec.get("expires",0) < now(): return self.send_json({"error":"refresh token expired/revoked"}, 401)
        u=get_user(rec.get("user"))
        if not u or u.get("status") in ["disabled","revoked"]: return self.send_json({"error":"user_not_active"},403)
        if rec.get("used"):
            fam = rec["family_id"]
            for r in records.values():
                if r.get("family_id") == fam: r["revoked"] = True
            save(REFRESH_DB, records); audit("refresh_replay_detected", family_id=fam, user=rec["user"], **_decision("refresh_replay_detected", "deny", "high"))
            return self.send_json({"error":"refresh_replay_detected: refresh token reuse detected"}, 401)
        posture_ok, posture_reason = check_device_posture(DEVICE_ID, rec["cnf_x5t"])
        if not posture_ok:
            audit("token_refresh_denied", user=rec["user"], **_decision("conditional_rotation_denied", "deny", "high"))
            return self.send_json({"error":"conditional_rotation_denied"}, 403)
        att_ok, att_reason, att = validate_attestation(DEVICE_ID, rec["cnf_x5t"])
        if ("gpu.job.submit" in rec.get("scopes", [])) and not att_ok:
            audit("token_refresh_denied", user=rec["user"], **_decision(att_reason, "deny", "high"))
            return self.send_json({"error": att_reason}, 403)
        if not cert_pem or cert_thumbprint_sha256_pem(cert_pem) != rec["cnf_x5t"] or not verify_proof(cert_pem, proof_sig, rt, "POST", "/token/refresh"):
            return self.send_json({"error":"device proof failed"}, 401)
        rec["used"] = True
        save(REFRESH_DB, records)
        evidence = _decision("conditional_rotation_allow", "allow", "low")
        access = issue_jwt(subject=rec["user"], audience=TOKEN_SERVICE_AUD, client_id=rec["client_id"], scopes=rec["scopes"], actor_type=rec.get("actor_type","user"), cnf_x5t=rec["cnf_x5t"], extra_claims={"device_id": DEVICE_ID, "auth_strength":"mfa", "idp":"entra-simulated", "attestation_evidence_id": (att or {}).get("evidence_id"), "device_trust_level": "trusted" if att_ok else "unknown", **evidence})
        new_rt = new_refresh_record(rec["user"], rec["client_id"], rec["scopes"], rec["cnf_x5t"], family_id=rec["family_id"])
        audit("token_refreshed", user=rec["user"], family_id=rec["family_id"], **evidence)
        return self.send_json({"access_token": access, "refresh_token": new_rt, "token_type":"Bearer", "expires_in": ACCESS_TOKEN_TTL_SECONDS})
    def obo_exchange(self, body):
        incoming = bearer(self.headers); requested = body.get("scopes", ["build.read"]); target_aud = body.get("audience", INTERNAL_API_AUD); agent_id = body.get("agent_id")
        action_claims = body.get("action_claims", {}) if isinstance(body.get("action_claims", {}), dict) else {}
        if not action_claims and isinstance(body.get("gpu_context", {}), dict):
            action_claims = body.get("gpu_context", {})
        token_profile = body.get("token_profile")
        try:
            claims = decode_and_validate_jwt(incoming, TOKEN_SERVICE_AUD)
            validate_sender_constrained_proof(claims, decode_cert_header(self.headers.get("X-Client-Cert", "")), self.headers.get("X-Proof-Signature"), incoming, "POST", "/obo/exchange")
            if "obo.exchange" not in scopes_from_claims(claims): raise ValueError("missing obo.exchange scope")
            user_allowed = scopes_from_claims(claims)
            agent_allowed = set()
            if agent_id:
                agent = db(AGENT_DB, {}).get(agent_id)
                if not agent or agent.get("status") != "active":
                    audit("scope_denied", user=claims.get("sub"), agent_id=agent_id, scopes=requested, decision="deny", reason="agent_not_active")
                    return self.send_json({"error": "scope_not_allowed", "reason": "requested scope is not allowed for this user or agent"}, 403)
                agent_allowed = set(agent.get("allowed_scopes", []))
            if not set(requested).issubset(user_allowed) or (agent_id and not set(requested).issubset(agent_allowed)):
                audit("scope_denied", user=claims.get("sub"), agent_id=agent_id, scopes=requested, decision="deny", reason="requested scope is not allowed for this user or agent")
                return self.send_json({"error": "scope_not_allowed", "reason": "requested scope is not allowed for this user or agent"}, 403)
            base_claims = {"obo": True, "original_client_id": claims.get("client_id"), "device_id": claims.get("device_id"), "auth_strength": claims.get("auth_strength","mfa"), "act": {"sub": f"user:{claims['sub']}"}, "obo_chain": [f"user:{claims['sub']}", f"agent:{agent_id}" if agent_id else f"user:{claims['sub']}", f"service:{target_aud}"], "target_service": target_aud, "target_action": ",".join(requested), "original_user": claims["sub"], "acting_agent": agent_id, "agent_id": agent_id, "initiating_user": claims["sub"], "delegation_type": "on_behalf_of"}
            if "gpu_context" in body and "gpu.job.submit" not in requested:
                return self.send_json({"error": "invalid_gpu_context", "reason": "gpu_context_requires_gpu_job_submit_scope"}, 400)
            if "gpu.job.submit" in requested:
                required_gpu_fields = ["job_id", "dataset_id", "gpu_action", "gpu_quota", "environment"]
                if action_claims:
                    missing_gpu = [k for k in required_gpu_fields if action_claims.get(k) in [None, ""]]
                    if missing_gpu:
                        return self.send_json({"error": "invalid_gpu_context", "missing": missing_gpu}, 400)
                for key in ["job_id", "dataset_id", "gpu_action", "gpu_quota", "environment", "model_id", "max_runtime_seconds", "policy_id", "policy_version", "decision_id", "risk_level"]:
                    if key in action_claims:
                        base_claims[key] = action_claims[key]
                if action_claims:
                    base_claims.setdefault("policy_id", "gpu.action.policy")
                    base_claims.setdefault("policy_version", "2026.05")
                    base_claims.setdefault("decision_id", f"dec-{uuid.uuid4()}")
                    base_claims.setdefault("risk_level", "low")
                    base_claims.setdefault("reason", "action_specific_gpu_token_issued")
                if token_profile == "action_specific_gpu":
                    base_claims["token_profile"] = token_profile
            ttl_seconds = min(ACCESS_TOKEN_TTL_SECONDS, 180) if action_claims else ACCESS_TOKEN_TTL_SECONDS
            downstream = issue_jwt(subject=f"agent:{agent_id}" if agent_id else claims["sub"], audience=target_aud, client_id="central-token-service-obo", scopes=requested, actor_type="agent" if agent_id else "user", ttl_seconds=ttl_seconds, cnf_x5t=(claims.get("cnf") or {}).get("x5t#S256"), extra_claims=base_claims)
            audit("obo_token_issued", user=claims["sub"], agent_id=agent_id, scopes=requested, audience=target_aud)
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
        agents[agent_id] = {"agent_id": agent_id, "agent_owner": body.get("agent_owner", "platform-security"), "environment": body.get("environment", "dev"), "purpose": body.get("purpose", "submit controlled GPU jobs and comment on PRs"), "allowed_scopes": body.get("allowed_scopes", ["repo.read", "pr.comment", "gpu.job.submit", "gpu.job.read"]), "gpu_quota_max_jobs": body.get("gpu_quota_max_jobs", 1), "cert_thumbprint": cert_thumbprint_sha256_pem(cert_pem), "status": body.get("status","active"), "actor_type":"agent", "owner": body.get("agent_owner", "platform-security"), "created": now()}
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
            if cert_thumbprint_sha256_pem(cert_pem) != agent["cert_thumbprint"] or not verify_proof(cert_pem, proof_sig, proof_token, "POST", "/agent/token"): raise ValueError("certificate_binding_failed")
            if not body.get("initiating_user"): raise ValueError("initiating_user_missing")
            if not set(requested).issubset(set(agent["allowed_scopes"])): raise ValueError("requested scopes exceed agent policy")
            token = issue_jwt(subject=f"agent:{agent_id}", audience=INTERNAL_API_AUD, client_id="agent-runtime", scopes=requested, actor_type="agent", ttl_seconds=AGENT_TOKEN_TTL_SECONDS, cnf_x5t=agent["cert_thumbprint"], extra_claims={"agent_id": agent_id, "agent_owner": agent["agent_owner"], "environment": agent["environment"], "initiating_user": body.get("initiating_user", "developer01"), "delegation_type":"user_delegated", "gpu_quota_max_jobs": agent["gpu_quota_max_jobs"]})
            audit("agent_token_issued", actor_type="agent", agent_id=agent_id, user=body.get("initiating_user"), scope=" ".join(requested), reason="ok", correlation_id=str(uuid.uuid4())); return self.send_json({"access_token": token, "token_type":"Bearer", "expires_in": AGENT_TOKEN_TTL_SECONDS})
        except Exception as e: audit("agent_token_failed", agent_id=agent_id, reason=str(e)); return self.send_json({"error": str(e)}, 401)
    def agent_task_create(self, body):
        import tool_registry
        from agent_tasks import persist_task
        agents = db(AGENT_DB, {})
        agent_id = body.get("agent_id")
        agent = agents.get(agent_id)
        if not agent:
            return self.send_json({"error": "agent_not_found"}, 404)
        if agent.get("status") != "active":
            return self.send_json({"error": "agent_not_active"}, 403)

        agent_mode = body.get("agent_mode")
        initiating_user = body.get("initiating_user")
        requested_tools = body.get("requested_tools", [])
        environment = body.get("environment", agent.get("environment"))
        if not requested_tools:
            audit("agent_task_denied", decision="deny", agent_id=agent_id, user=initiating_user, reason="requested_tools_required")
            return self.send_json({"error": "requested_tools_required"}, 400)
        try:
            gpu_quota = int(body.get("gpu_quota", 1))
        except (TypeError, ValueError):
            audit("agent_task_denied", decision="deny", agent_id=agent_id, user=initiating_user, reason="invalid_gpu_quota", gpu_quota=body.get("gpu_quota"))
            return self.send_json({"error": "invalid_gpu_quota"}, 400)

        if agent_mode not in ["manual", "autonomous"]:
            audit("agent_task_denied", decision="deny", agent_id=agent_id, reason="invalid_agent_mode", agent_mode=agent_mode)
            return self.send_json({"error": "invalid_agent_mode"}, 400)
        if not initiating_user:
            audit("agent_task_denied", decision="deny", agent_id=agent_id, reason="initiating_user_missing")
            return self.send_json({"error": "initiating_user_missing"}, 400)
        try:
            scope_resolution = tool_registry.scopes_for_tools(requested_tools)
            if isinstance(scope_resolution, tuple) and len(scope_resolution) == 2:
                requested_scopes, unknown_tools = scope_resolution
                if unknown_tools:
                    audit("agent_task_denied", decision="deny", agent_id=agent_id, user=initiating_user, reason="unknown_tools", unknown_tools=unknown_tools)
                    return self.send_json({"error": "unknown_tools"}, 400)
            elif isinstance(scope_resolution, dict):
                requested_scopes = scope_resolution.get("scopes", [])
                unknown_tools = scope_resolution.get("unknown_tools", [])
                if unknown_tools:
                    audit("agent_task_denied", decision="deny", agent_id=agent_id, user=initiating_user, reason="unknown_tools", unknown_tools=unknown_tools)
                    return self.send_json({"error": "unknown_tools"}, 400)
            else:
                requested_scopes = scope_resolution
            if not isinstance(requested_scopes, list):
                raise ValueError("invalid_scope_resolution")
        except Exception:
            audit("agent_task_denied", decision="deny", agent_id=agent_id, user=initiating_user, reason="unknown_tools", requested_tools=requested_tools)
            return self.send_json({"error": "unknown_tools"}, 400)
        if not set(requested_scopes).issubset(set(agent.get("allowed_scopes", []))):
            audit("agent_task_denied", decision="deny", agent_id=agent_id, user=initiating_user, reason="requested_scopes_exceed_agent_policy", requested_scopes=requested_scopes)
            return self.send_json({"error": "requested_scopes_exceed_agent_policy"}, 403)
        if "gpu.submit.dev" in requested_tools and agent_mode == "autonomous":
            if environment != "dev" or gpu_quota > 1:
                audit("agent_task_denied", decision="deny", agent_id=agent_id, user=initiating_user, reason="autonomous_gpu_policy_denied", environment=environment, gpu_quota=gpu_quota)
                return self.send_json({"error": "autonomous_gpu_policy_denied"}, 403)

        task = {
            "task_id": f"task-{uuid.uuid4()}",
            "agent_id": agent_id,
            "agent_mode": agent_mode,
            "initiating_user": initiating_user,
            "requested_scopes": requested_scopes,
            "requested_tools": requested_tools,
            "environment": environment,
            "gpu_quota": gpu_quota,
            "status": "created",
            "created": now(),
        }
        persist_task(task)
        audit("agent_task_created", agent_id=agent_id, user=initiating_user, agent_mode=agent_mode, requested_scopes=requested_scopes, requested_tools=requested_tools, environment=environment, gpu_quota=gpu_quota)
        return self.send_json(task, 201)
    def agent_task_approve(self, body):
        from agent_tasks import load_tasks, save_tasks
        task_id = body.get("task_id")
        if not task_id:
            return self.send_json({"error": "task_id_required"}, 400)
        tasks = load_tasks()
        task = tasks.get(task_id)
        if not task:
            return self.send_json({"error": "task_not_found"}, 404)
        task["approval_status"] = "approved"
        task["status"] = "approved"
        task["approved_at"] = now()
        tasks[task_id] = task
        save_tasks(tasks)
        audit("agent_task_approved", task_id=task_id, agent_id=task.get("agent_id"), user=task.get("initiating_user"))
        return self.send_json(task, 200)
    def agent_task_token(self, body):
        from token_utils import verify_proof
        from agent_tasks import load_tasks
        task_id = body.get("task_id")
        if not task_id:
            return self.send_json({"error": "task_id_required"}, 400)
        tasks = load_tasks()
        task = tasks.get(task_id)
        if not task:
            return self.send_json({"error": "task_not_found"}, 404)
        agent_id = task.get("agent_id")
        agent = db(AGENT_DB, {}).get(agent_id)
        if not agent:
            return self.send_json({"error": "agent_not_found"}, 404)
        if agent.get("status") != "active":
            return self.send_json({"error": "agent_not_active"}, 403)
        if task.get("approval_required", True) and task.get("approval_status") != "approved":
            return self.send_json({"error": "approval_required"}, 403)
        cert_pem = decode_cert_header(self.headers.get("X-Client-Cert", ""))
        proof_sig = self.headers.get("X-Proof-Signature")
        if not cert_pem or not proof_sig:
            return self.send_json({"error": "client_certificate_and_proof_required"}, 400)
        proof_token = body.get("proof_token", "agent-task-token-proof")
        if cert_thumbprint_sha256_pem(cert_pem) != agent.get("cert_thumbprint"):
            return self.send_json({"error": "certificate_binding_failed"}, 401)
        if not verify_proof(cert_pem, proof_sig, proof_token, "POST", "/agent/task/token"):
            return self.send_json({"error": "invalid_proof_signature"}, 401)
        token = issue_jwt(subject=f"agent:{agent_id}", audience=INTERNAL_API_AUD, client_id="agent-task-runtime", scopes=task.get("requested_scopes", []), actor_type="agent", ttl_seconds=min(AGENT_TOKEN_TTL_SECONDS, 180), cnf_x5t=agent["cert_thumbprint"], extra_claims={"task_id": task_id, "agent_id": agent_id, "initiating_user": task.get("initiating_user"), "agent_mode": task.get("agent_mode"), "delegation_type": "agent_task", "allowed_tools": task.get("requested_tools", []), "environment": task.get("environment"), "gpu_quota": task.get("gpu_quota"), "approval_status": task.get("approval_status", "pending"), "requested_scopes": task.get("requested_scopes", [])})
        audit("agent_task_token_issued", task_id=task_id, agent_id=agent_id, user=task.get("initiating_user"), scope=" ".join(task.get("requested_scopes", [])))
        return self.send_json({"access_token": token, "token_type": "Bearer", "expires_in": min(AGENT_TOKEN_TTL_SECONDS, 180)})
    def agent_disable(self, body, status):
        agents = db(AGENT_DB, {})
        aid = body.get("agent_id")
        if aid not in agents:
            return self.send_json({"error":"agent_not_found"}, 404)
        agents[aid]["status"] = status
        save(AGENT_DB, agents)
        audit("agent_disabled" if status == "disabled" else "agent_enabled", agent_id=aid, reason=status)
        return self.send_json(agents[aid])

    def agent_rotate_cert(self, body):
        aid = body.get("agent_id")
        agents = db(AGENT_DB, {})
        if aid not in agents: return self.send_json({"error":"agent_not_found"},404)
        agents[aid]["cert_thumbprint"] = cert_thumbprint_sha256_pem(cert_to_pem_string(AGENT_CERT_PATH))
        save(AGENT_DB, agents)
        audit("cert_rotated", agent_id=aid)
        return self.send_json(agents[aid])

    def introspect(self, body):
        try:
            claims = decode_and_validate_jwt(body.get("token"), body.get("audience", INTERNAL_API_AUD))
            if is_jti_revoked(claims.get("jti")):
                return self.send_json({"active": False, "error": "jti_revoked"})
            audit("token_introspected", user=claims.get("sub"), token_id=claims.get("jti"), scopes=claims.get("scope"))
            return self.send_json({"active": True, "sub": claims.get("sub"), "aud": claims.get("aud"), "scope": claims.get("scope"), "jti": claims.get("jti"), "device_id": claims.get("device_id"), "agent_id": claims.get("agent_id"), "policy_id": claims.get("policy_id"), "decision_id": claims.get("decision_id"), "risk_level": claims.get("risk_level")})
        except Exception as e:
            audit("token_introspected", decision="deny", reason=str(e))
            return self.send_json({"active": False, "error": str(e)})
    def revoke(self, body):
        fam = body.get("family_id"); records = db(REFRESH_DB, {}); count = 0
        for r in records.values():
            if fam is None or r.get("family_id") == fam: r["revoked"] = True; count += 1
        save(REFRESH_DB, records)
        audit("token_revoked", count=count, family_id=fam)
        return self.send_json({"revoked_count": count})

if __name__ == "__main__":
    if os.getenv("ENV") == "prod":
        from token_utils import UNSAFE_DEV_MODE_CERT_HEADER, UNSAFE_ALLOW_LOCAL_SIGNING_CERT_FALLBACK, ACCESS_TOKEN_TTL_SECONDS
        if UNSAFE_DEV_MODE_CERT_HEADER or UNSAFE_ALLOW_LOCAL_SIGNING_CERT_FALLBACK or ACCESS_TOKEN_TTL_SECONDS > 900:
            raise SystemExit("Production safety guard failed")
    print("Centralized token service running on http://127.0.0.1:8000")
    HTTPServer(("127.0.0.1", 8000), Handler).serve_forever()


    
