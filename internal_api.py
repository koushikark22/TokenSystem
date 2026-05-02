import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from policy_engine import evaluate_policy
from quota_manager import QuotaManager
from rate_limiter import InMemoryRateLimiter
from token_utils import INTERNAL_API_AUD, decode_and_validate_jwt, decode_cert_header, has_scopes, validate_sender_constrained_proof

GPU_JOBS = []
GPU_QUOTAS = {"developer01": 2, "agent-gpu-planner-dev": 1}
RL = InMemoryRateLimiter(limit=120, window_seconds=60)
QM = QuotaManager(GPU_QUOTAS)

def actor_from_claims(c): return c.get("agent_id", c.get("sub")) if c.get("actor_type") == "agent" else c.get("sub")
def bearer(headers):
    a = headers.get("Authorization", "")
    return a.split(" ",1)[1] if a.startswith("Bearer ") else None

class Handler(BaseHTTPRequestHandler):
    server_version = "InternalAPIGPUDemo/2.0"
    def log_message(self, fmt,*args): print("[internal_api]", fmt % args)
    def route_path(self): return urlparse(self.path).path
    def read_json(self):
        n=int(self.headers.get("Content-Length","0") or 0)
        return json.loads(self.rfile.read(n).decode() or "{}") if n else {}
    def send_json(self,data,status=200):
        raw=json.dumps(data,indent=2).encode(); self.send_response(status); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def validate(self, scopes, require_pim=False):
        token=bearer(self.headers)
        if not token: raise PermissionError("missing bearer token")
        c=decode_and_validate_jwt(token, INTERNAL_API_AUD)
        presented_tp = self.headers.get("X-Cert-Thumbprint")
        cert = decode_cert_header(self.headers.get("X-Client-Cert", "")) if self.headers.get("X-Client-Cert") else ""
        validate_sender_constrained_proof(c, cert, self.headers.get("X-Proof-Signature"), token, self.command, self.route_path(), presented_thumbprint=presented_tp)
        if not has_scopes(c, scopes): raise PermissionError(f"missing required scope {scopes}; token has {c.get('scope')}")
        if require_pim and not c.get("pim"): raise PermissionError("PIM/step-up token required")
        return c
    def do_GET(self):
        p=self.route_path()
        try:
            if p == "/health": return self.send_json({"status":"ok", "audience": INTERNAL_API_AUD})
            if p == "/build/status":
                c=self.validate(["build.read"]); return self.send_json({"status":"green","user":c.get("sub")})
            if p == "/gpu/jobs":
                c=self.validate(["gpu.job.read"]); return self.send_json({"gpu_jobs":GPU_JOBS,"requested_by":actor_from_claims(c)})
            return self.send_json({"error":"not found"},404)
        except PermissionError as e: return self.send_json({"error":str(e)},403)
        except Exception as e: return self.send_json({"error":str(e)},401)
    def do_POST(self):
        p=self.route_path(); body=self.read_json()
        try:
            if p == "/deploy/prod":
                c=self.validate(["deploy.prod"], require_pim=True)
                ok, reason = evaluate_policy("deploy.prod", {"actor_type":c.get("actor_type"),"step_up_mfa":c.get("auth_strength") == "step_up_mfa","pim":c.get("pim"),"approval_id":c.get("approval_id"),"cert_bound":True})
                if not ok: return self.send_json({"error":reason},403)
                return self.send_json({"result":"production deployment accepted", "user":c.get("sub")})
            if p == "/gpu/jobs/submit":
                c=self.validate(["gpu.job.submit"]); actor=actor_from_claims(c)
                for key in [f"user:{c.get('sub')}", f"device:{c.get('device_id')}", f"agent:{c.get('agent_id')}", "scope:gpu.job.submit"]:
                    ok, reason = RL.allow(key)
                    if not ok: return self.send_json({"error":reason,"key":key},429)
                ok, reason = evaluate_policy("gpu.job.submit", {"actor_type":c.get("actor_type"),"device_managed":True,"cert_bound":True,"gpu_count":int(body.get("gpu_count",1))})
                if not ok: return self.send_json({"error":reason},403)
                active=[j for j in GPU_JOBS if j["owner"]==actor and j["state"] in {"queued","running"}]
                qok, qreason, limit = QM.allow_gpu(actor, len(active))
                if not qok: return self.send_json({"error":qreason,"actor":actor,"max_jobs":limit},429)
                job={"job_id":f"gpu-job-{len(GPU_JOBS)+1:04d}","owner":actor,"model":body.get("model","demo-transformer"),"dataset":body.get("dataset","synthetic-dev-data"),"gpu_count":int(body.get("gpu_count",1)),"state":"queued"}
                GPU_JOBS.append(job); return self.send_json({"result":"GPU job submitted","job":job})
            if p == "/gpu/quota/update":
                c=self.validate(["gpu.quota.update"], require_pim=True)
                ok, reason = evaluate_policy("gpu.quota.update", {"actor_type":c.get("actor_type"),"step_up_mfa":c.get("auth_strength") == "step_up_mfa","pim":c.get("pim"),"approval_id":c.get("approval_id"),"device_managed":True,"cert_bound":True,"token_ttl_seconds":180})
                if not ok: return self.send_json({"error":reason},403)
                subject=body.get("subject","developer01"); quota=int(body.get("quota",3)); GPU_QUOTAS[subject]=quota
                return self.send_json({"result":"GPU quota updated","subject":subject,"quota":quota})
            if p == "/agent/comment":
                c=self.validate(["pr.comment"])
                if c.get("actor_type") != "agent" or not c.get("agent_id"): return self.send_json({"error":"agent token with explicit agent_id required"},403)
                return self.send_json({"result":"agent comment accepted","agent_id":c.get("agent_id")})
            return self.send_json({"error":"not found"},404)
        except PermissionError as e: return self.send_json({"error":str(e)},403)
        except Exception as e: return self.send_json({"error":str(e)},401)

if __name__ == "__main__":
    print("Protected internal API/GPU API running on http://127.0.0.1:9000")
    HTTPServer(("127.0.0.1", 9000), Handler).serve_forever()
