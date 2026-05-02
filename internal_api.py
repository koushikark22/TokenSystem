import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
from token_utils import INTERNAL_API_AUD, decode_and_validate_jwt, decode_cert_header, has_scopes, validate_sender_constrained_proof

GPU_JOBS = []
GPU_QUOTAS = {"developer01": 2, "agent-gpu-planner-dev": 1}

def actor_from_claims(c): return c.get("agent_id", c.get("sub")) if c.get("actor_type") == "agent" else c.get("sub")
def bearer(headers):
    a = headers.get("Authorization", "")
    return a.split(" ",1)[1] if a.startswith("Bearer ") else None

class Handler(BaseHTTPRequestHandler):
    server_version = "InternalAPIGPUDemo/1.0"
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
        validate_sender_constrained_proof(c, decode_cert_header(self.headers.get("X-Client-Cert", "")), self.headers.get("X-Proof-Signature"), token, self.command, self.route_path())
        if not has_scopes(c, scopes): raise PermissionError(f"missing required scope {scopes}; token has {c.get('scope')}")
        if require_pim and not c.get("pim"): raise PermissionError("PIM/step-up token required")
        return c
    def do_GET(self):
        p=self.route_path()
        try:
            if p == "/health": return self.send_json({"status":"ok", "audience": INTERNAL_API_AUD})
            if p == "/build/status":
                c=self.validate(["build.read"]); return self.send_json({"status":"green", "message":"Build system access allowed using OBO downstream token.", "user":c.get("sub"), "obo":c.get("obo",False), "device_id":c.get("device_id"), "scopes":c.get("scope")})
            if p == "/gpu/jobs":
                c=self.validate(["gpu.job.read"]); return self.send_json({"gpu_jobs":GPU_JOBS,"requested_by":actor_from_claims(c),"actor_type":c.get("actor_type")})
            return self.send_json({"error":"not found"},404)
        except PermissionError as e: return self.send_json({"error":str(e)},403)
        except Exception as e: return self.send_json({"error":str(e)},401)
    def do_POST(self):
        p=self.route_path(); body=self.read_json()
        try:
            if p == "/deploy/prod":
                c=self.validate(["deploy.prod"], require_pim=True); return self.send_json({"result":"production deployment accepted", "user":c.get("sub"), "approval_id":c.get("approval_id"), "auth_strength":c.get("auth_strength")})
            if p == "/gpu/jobs/submit":
                c=self.validate(["gpu.job.submit"]); actor=actor_from_claims(c); active=[j for j in GPU_JOBS if j["owner"]==actor and j["state"] in {"queued","running"}]
                max_jobs=int(c.get("gpu_quota_max_jobs") or GPU_QUOTAS.get(actor, GPU_QUOTAS.get(c.get("sub"),1)))
                if len(active) >= max_jobs: return self.send_json({"error":"GPU quota exceeded", "actor":actor, "max_jobs":max_jobs},429)
                job={"job_id":f"gpu-job-{len(GPU_JOBS)+1:04d}","owner":actor,"actor_type":c.get("actor_type"),"initiating_user":c.get("initiating_user",c.get("sub")),"model":body.get("model","demo-transformer"),"dataset":body.get("dataset","synthetic-dev-data"),"gpu_count":int(body.get("gpu_count",1)),"state":"queued","scope":c.get("scope")}
                GPU_JOBS.append(job); return self.send_json({"result":"GPU job submitted","job":job})
            if p == "/gpu/jobs/cancel":
                self.validate(["gpu.job.cancel"]); job_id=body.get("job_id")
                for job in GPU_JOBS:
                    if job["job_id"] == job_id: job["state"]="cancelled"; return self.send_json({"result":"GPU job cancelled","job":job})
                return self.send_json({"error":"job not found"},404)
            if p == "/gpu/quota/update":
                c=self.validate(["gpu.quota.update"], require_pim=True); subject=body.get("subject","developer01"); quota=int(body.get("quota",3)); GPU_QUOTAS[subject]=quota
                return self.send_json({"result":"GPU quota updated","subject":subject,"quota":quota,"approved_by":c.get("sub"),"approval_id":c.get("approval_id")})
            if p == "/agent/comment":
                c=self.validate(["pr.comment"])
                if c.get("actor_type") != "agent" or not c.get("agent_id"): return self.send_json({"error":"agent token with explicit agent_id required"},403)
                return self.send_json({"result":"agent comment accepted","agent_id":c.get("agent_id"),"agent_owner":c.get("agent_owner"),"initiating_user":c.get("initiating_user"),"audit_context":{"actor_type":c.get("actor_type"),"scope":c.get("scope"),"environment":c.get("environment")}})
            return self.send_json({"error":"not found"},404)
        except PermissionError as e: return self.send_json({"error":str(e)},403)
        except Exception as e: return self.send_json({"error":str(e)},401)

if __name__ == "__main__":
    print("Protected internal API/GPU API running on http://127.0.0.1:9000")
    HTTPServer(("127.0.0.1", 9000), Handler).serve_forever()
