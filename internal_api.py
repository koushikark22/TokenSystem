import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from device_registry import check_device_posture
from policy_engine import evaluate_policy
from quota_manager import QuotaManager
from rate_limiter import InMemoryRateLimiter
from token_utils import (
    INTERNAL_API_AUD,
    cert_thumbprint_sha256_pem,
    decode_and_validate_jwt,
    decode_cert_header,
    has_scopes,
    validate_sender_constrained_proof,
    write_audit_event,
    is_jti_revoked,
)

GPU_JOBS = []
GPU_QUOTAS = {"developer01": 2, "agent-gpu-planner-dev": 1}
RL = InMemoryRateLimiter(limit=120, window_seconds=60)
QM = QuotaManager(GPU_QUOTAS)


def actor_from_claims(c):
    return c.get("agent_id", c.get("sub")) if c.get("actor_type") == "agent" else c.get("sub")


def bearer(headers):
    a = headers.get("Authorization", "")
    return a.split(" ", 1)[1] if a.startswith("Bearer ") else None


def posture_allowed_for_action(claims, action):
    sec = claims.get("security_context", {})
    reason = sec.get("device_posture_reason")
    if claims.get("actor_type") != "agent":
        return reason == "allowed", reason

    # Agent delegated actions may run without explicit device context
    # when identity is strongly bound to agent certificate and user delegation.
    if action in {"agent.comment", "gpu.job.submit"}:
        if reason == "allowed":
            return True, reason
        if reason == "no_device_context" and claims.get("agent_id") and sec.get("cert_bound") and claims.get("initiating_user"):
            return True, reason
    return False, reason


class Handler(BaseHTTPRequestHandler):
    server_version = "InternalAPIGPUDemo/2.1"

    def log_message(self, fmt, *args):
        print("[internal_api]", fmt % args)

    def route_path(self):
        return urlparse(self.path).path

    def read_json(self):
        n = int(self.headers.get("Content-Length", "0") or 0)
        return json.loads(self.rfile.read(n).decode() or "{}") if n else {}

    def send_json(self, data, status=200):
        raw = json.dumps(data, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def validate(self, scopes, require_pim=False):
        token = bearer(self.headers)
        if not token:
            raise PermissionError("missing bearer token")

        claims = decode_and_validate_jwt(token, INTERNAL_API_AUD)
        if self.route_path() in {"/gpu/jobs/submit", "/agent/comment"} and is_jti_revoked(claims.get("jti")):
            write_audit_event("jwt_replay_or_revoked_jti_detected", {"decision": "deny", "reason": "jti_revoked", "jti": claims.get("jti")})
            raise PermissionError("jwt_replay_or_revoked_jti_detected")
        cert_pem = decode_cert_header(self.headers.get("X-Client-Cert", "")) if self.headers.get("X-Client-Cert") else ""
        computed_thumbprint = cert_thumbprint_sha256_pem(cert_pem) if cert_pem else None

        try:
            validate_sender_constrained_proof(
                claims,
                cert_pem,
                self.headers.get("X-Proof-Signature"),
                token,
                self.command,
                self.route_path(),
                dev_header_thumbprint=self.headers.get("X-Cert-Thumbprint"),
            )
            cert_bound = True
        except Exception as e:
            write_audit_event("certificate_binding_failed", {"decision": "deny", "reason": str(e), "request_path": self.route_path()})
            raise PermissionError(str(e))

        if not has_scopes(claims, scopes):
            raise PermissionError(f"missing required scope {scopes}; token has {claims.get('scope')}")
        if require_pim and not claims.get("pim"):
            raise PermissionError("PIM/step-up token required")

        device_id = claims.get("device_id")
        posture_ok, posture_reason = (True, "no_device_context")
        if device_id and computed_thumbprint:
            posture_ok, posture_reason = check_device_posture(device_id, computed_thumbprint)

        claims["security_context"] = {
            "cert_bound": cert_bound,
            "device_managed": posture_ok,
            "device_posture_reason": posture_reason,
            "computed_cert_thumbprint": computed_thumbprint,
            "device_id": device_id,
        }
        return claims

    def _policy_context(self, claims, body):
        sec = claims.get("security_context", {})
        return {
            "actor_type": claims.get("actor_type"),
            "user": claims.get("sub"),
            "agent_id": claims.get("agent_id"),
            "initiating_user": claims.get("initiating_user"),
            "device_id": sec.get("device_id"),
            "device_managed": sec.get("device_managed"),
            "cert_bound": sec.get("cert_bound"),
            "scope": claims.get("scope"),
            "audience": claims.get("aud"),
            "gpu_count": int(body.get("gpu_count", 1)),
            "pim": claims.get("pim"),
            "step_up_mfa": claims.get("auth_strength") == "step_up_mfa",
            "approval_id": claims.get("approval_id"),
            "ticket_id": claims.get("ticket_id"),
        }

    def do_GET(self):
        p = self.route_path()
        try:
            if p == "/health": return self.send_json({"status": "ok", "audience": INTERNAL_API_AUD})
            if p == "/build/status":
                c = self.validate(["build.read"])
                return self.send_json({"status": "green", "user": c.get("sub")})
            if p == "/gpu/jobs":
                c = self.validate(["gpu.job.read"])
                return self.send_json({"gpu_jobs": GPU_JOBS, "requested_by": actor_from_claims(c)})
            return self.send_json({"error": "not found"}, 404)
        except PermissionError as e:
            return self.send_json({"error": str(e)}, 403)
        except Exception as e:
            return self.send_json({"error": str(e)}, 401)

    def do_POST(self):
        p = self.route_path(); body = self.read_json()
        try:
            if p == "/deploy/prod":
                c = self.validate(["deploy.prod"], require_pim=True)
                ok_posture, reason = posture_allowed_for_action(c, "deploy.prod")
                if not ok_posture:
                    return self.send_json({"error": reason}, 403)
                ok, reason = evaluate_policy("deploy.prod", self._policy_context(c, body))
                if not ok: return self.send_json({"error": reason}, 403)
                return self.send_json({"result": "production deployment accepted", "user": c.get("sub")})

            if p == "/gpu/jobs/submit":
                c = self.validate(["gpu.job.submit"])
                ok_posture, reason = posture_allowed_for_action(c, "gpu.job.submit")
                if not ok_posture:
                    return self.send_json({"error": reason}, 403)
                actor = actor_from_claims(c)
                evidence = {"policy_id": c.get("policy_id"), "policy_version": c.get("policy_version"), "decision_id": c.get("decision_id"), "risk_level": c.get("risk_level"), "job_id": c.get("job_id"), "dataset_id": c.get("dataset_id"), "gpu_action": c.get("gpu_action"), "environment": c.get("environment"), "gpu_quota": c.get("gpu_quota"), "model_id": c.get("model_id"), "jti": c.get("jti")}
                required_claims = ["job_id", "dataset_id", "gpu_action", "gpu_quota", "environment", "policy_id", "policy_version", "decision_id", "risk_level"]
                missing = [k for k in required_claims if c.get(k) is None]
                if missing:
                    write_audit_event("gpu_submit_denied", {"decision": "deny", "reason": "action_specific_claims_required", "missing": missing, "requested_gpu_count": body.get("gpu_count"), **evidence})
                    return self.send_json({"error": "action_specific_claims_required", "missing": missing}, 403)
                if c.get("job_id") and body.get("job_id") != c.get("job_id"):
                    write_audit_event("gpu_submit_denied", {"decision": "deny", "reason": "job_id_mismatch", **evidence})
                    return self.send_json({"error": "job_id_mismatch"}, 403)
                if c.get("dataset_id") and body.get("dataset_id") != c.get("dataset_id"):
                    write_audit_event("gpu_submit_denied", {"decision": "deny", "reason": "dataset_id_mismatch", **evidence})
                    return self.send_json({"error": "dataset_id_mismatch"}, 403)
                if c.get("gpu_action") and body.get("gpu_action") != c.get("gpu_action"):
                    write_audit_event("gpu_submit_denied", {"decision": "deny", "reason": "gpu_action_mismatch", **evidence})
                    return self.send_json({"error": "gpu_action_mismatch"}, 403)
                if c.get("environment") and body.get("environment") != c.get("environment"):
                    write_audit_event("gpu_submit_denied", {"decision": "deny", "reason": "environment_mismatch", **evidence})
                    return self.send_json({"error": "environment_mismatch"}, 403)
                if c.get("gpu_quota") is not None:
                    claim_quota = int(c.get("gpu_quota"))
                    if int(body.get("gpu_count", 1)) > claim_quota:
                        write_audit_event("gpu_submit_denied", {"decision": "deny", "reason": "gpu_quota_exceeded", "requested_gpu_count": body.get("gpu_count"), **evidence})
                        return self.send_json({"error": "gpu_quota_exceeded"}, 403)
                requested_model = body.get("model_id") or body.get("model")
                if c.get("model_id") and requested_model != c.get("model_id"):
                    write_audit_event("gpu_submit_denied", {"decision": "deny", "reason": "model_id_mismatch", **evidence})
                    return self.send_json({"error": "model_id_mismatch"}, 403)
                if c.get("max_runtime_seconds") is not None and int(body.get("max_runtime_seconds", c.get("max_runtime_seconds"))) > int(c.get("max_runtime_seconds")):
                    write_audit_event("gpu_submit_denied", {"decision": "deny", "reason": "runtime_exceeded", **evidence})
                    return self.send_json({"error": "runtime_exceeded"}, 403)
                for key in [f"user:{c.get('sub')}", f"device:{c.get('device_id')}", f"agent:{c.get('agent_id')}", "scope:gpu.job.submit"]:
                    ok, reason = RL.allow(key)
                    if not ok: return self.send_json({"error": reason, "key": key}, 429)
                ok, reason = evaluate_policy("gpu.job.submit", self._policy_context(c, body))
                if not ok: return self.send_json({"error": reason}, 403)
                active = [j for j in GPU_JOBS if j["owner"] == actor and j["state"] in {"queued", "running"}]
                qok, qreason, limit = QM.allow_gpu(actor, len(active))
                if not qok:
                    write_audit_event("gpu_submit_denied", {"decision": "deny", "reason": qreason, "actor": actor, "user": c.get("sub"), "agent_id": c.get("agent_id"), "scopes": c.get("scope")})
                    return self.send_json({"error": qreason, "actor": actor, "max_jobs": limit}, 429)
                job = {"job_id": f"gpu-job-{len(GPU_JOBS)+1:04d}", "owner": actor, "model": body.get("model", "demo-transformer"), "dataset": body.get("dataset", "synthetic-dev-data"), "gpu_count": int(body.get("gpu_count", 1)), "state": "queued"}
                GPU_JOBS.append(job)
                write_audit_event("gpu_submit_allowed", {"decision": "allow", "reason": "action_specific_claims_matched", "actor": actor, "user": c.get("sub"), "agent_id": c.get("agent_id"), "token_id": c.get("jti"), "scopes": c.get("scope"), "requested_gpu_count": body.get("gpu_count"), **evidence})
                return self.send_json({"result": "GPU job submitted", "job": job})

            if p == "/gpu/quota/update":
                c = self.validate(["gpu.quota.update"], require_pim=True)
                ok_posture, reason = posture_allowed_for_action(c, "gpu.quota.update")
                if not ok_posture:
                    return self.send_json({"error": reason}, 403)
                ok, reason = evaluate_policy("gpu.quota.update", self._policy_context(c, body))
                if not ok: return self.send_json({"error": reason}, 403)
                subject = body.get("subject", "developer01"); quota = int(body.get("quota", 3)); GPU_QUOTAS[subject] = quota
                return self.send_json({"result": "GPU quota updated", "subject": subject, "quota": quota})

            if p == "/agent/comment":
                c = self.validate(["pr.comment"])
                if c.get("actor_type") != "agent" or not c.get("agent_id"):
                    return self.send_json({"error": "agent token with explicit agent_id required"}, 403)
                ok_posture, reason = posture_allowed_for_action(c, "agent.comment")
                if not ok_posture:
                    return self.send_json({"error": reason}, 403)
                return self.send_json({"result": "agent comment accepted", "agent_id": c.get("agent_id")})
            return self.send_json({"error": "not found"}, 404)
        except PermissionError as e:
            return self.send_json({"error": str(e)}, 403)
        except Exception as e:
            return self.send_json({"error": str(e)}, 401)


if __name__ == "__main__":
    print("Protected internal API/GPU API running on http://127.0.0.1:9000")
    HTTPServer(("127.0.0.1", 9000), Handler).serve_forever()
