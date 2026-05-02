import argparse, json, sys
import requests
from token_utils import AGENT_CERT_PATH, AGENT_KEY_PATH, DEVICE_CERT_PATH, DEVICE_KEY_PATH, INTERNAL_API_AUD, cert_thumbprint_sha256_pem, cert_to_pem_string, encode_cert_header, json_load, json_save, sign_proof, STATE_DIR

TOKEN_URL = "http://127.0.0.1:8000"
API_URL = "http://127.0.0.1:9000"
CLI_STATE = STATE_DIR / "devctl_tokens.json"

def pp(obj): print(json.dumps(obj, indent=2, sort_keys=True))
def state(): return json_load(CLI_STATE, {})
def save_state(s): json_save(CLI_STATE, s)

def proof_headers(access_token: str, method: str, path: str, *, agent: bool = False, cert_thumbprint: str | None = None):
    cert_path = AGENT_CERT_PATH if agent else DEVICE_CERT_PATH
    key_path = AGENT_KEY_PATH if agent else DEVICE_KEY_PATH
    cert_pem = cert_to_pem_string(cert_path)
    return {"Authorization": f"Bearer {access_token}","X-Client-Cert": encode_cert_header(cert_pem),"X-Proof-Signature": sign_proof(key_path, access_token, method, path),"X-Cert-Thumbprint": cert_thumbprint or cert_thumbprint_sha256_pem(cert_pem)}

# existing flows kept
# ...
def login(args):
    r = requests.post(f"{TOKEN_URL}/device/start", json={"client_id": "linux-devctl"}); r.raise_for_status(); data=r.json(); print(data["message"])
    if not args.auto: input("Press Enter after completing browser login. For demo use --auto. ")
    proof_token = "device-login-proof"
    c = requests.post(f"{TOKEN_URL}/device/complete", json={"user_code":data["user_code"],"device_cert_pem": cert_to_pem_string(DEVICE_CERT_PATH),"proof_signature": sign_proof(DEVICE_KEY_PATH, proof_token, "POST", "/device/complete"),"proof_token": proof_token}); c.raise_for_status(); pp(c.json())
    t = requests.post(f"{TOKEN_URL}/token/poll", json={"device_code": data["device_code"]}); t.raise_for_status(); save_state(t.json())

def gpu_quota_update(args):
    token=state().get("access_token"); headers=proof_headers(token,"POST","/stepup")
    elevated=requests.post(f"{TOKEN_URL}/stepup",headers=headers,json={"audience":INTERNAL_API_AUD,"scopes":["gpu.quota.update"],"reason":"GPU quota admin change"}).json()["access_token"]
    a=requests.post(f"{API_URL}/gpu/quota/update",headers=proof_headers(elevated,"POST","/gpu/quota/update", cert_thumbprint=args.cert_thumbprint),json={"subject":args.subject,"quota":args.quota}); pp(a.json()); a.raise_for_status()

def register_agent(args): pp(requests.post(f"{TOKEN_URL}/agent/register", json={"agent_id":"agent-gpu-planner-dev","agent_owner":"platform-security","environment":"dev","allowed_scopes":["repo.read","pr.comment","gpu.job.submit","gpu.job.read"],"gpu_quota_max_jobs":1}).json())
def agent_token(scopes):
    proof_token="agent-token-proof"; headers={"X-Client-Cert":encode_cert_header(cert_to_pem_string(AGENT_CERT_PATH)),"X-Proof-Signature":sign_proof(AGENT_KEY_PATH,proof_token,"POST","/agent/token")}
    r=requests.post(f"{TOKEN_URL}/agent/token",headers=headers,json={"agent_id":"agent-gpu-planner-dev","initiating_user":"developer01","scopes":scopes,"proof_token":proof_token}); pp(r.json()); r.raise_for_status(); return r.json()["access_token"]
def agent_comment(args): a=requests.post(f"{API_URL}/agent/comment",headers=proof_headers(agent_token(["pr.comment"]),"POST","/agent/comment",agent=True, cert_thumbprint=args.cert_thumbprint),json={"pr":123}); pp(a.json()); a.raise_for_status()
def agent_gpu_submit(args): a=requests.post(f"{API_URL}/gpu/jobs/submit",headers=proof_headers(agent_token(["gpu.job.submit"]),"POST","/gpu/jobs/submit",agent=True, cert_thumbprint=args.cert_thumbprint),json={"model":"agent-planned-model","dataset":"approved-dev-dataset","gpu_count":1}); pp(a.json()); a.raise_for_status()
def audit(args):
    events = requests.get(f"{TOKEN_URL}/audit").json()
    if args.event_type: events=[e for e in events if e.get("event_type")==args.event_type]
    if args.user: events=[e for e in events if e.get("user")==args.user]
    if args.agent_id: events=[e for e in events if e.get("agent_id")==args.agent_id]
    if args.format=="jsonl": print("\n".join(json.dumps(e) for e in events))
    else: pp(events)
def jwks_cmd(args): pp(requests.get(f"{TOKEN_URL}/.well-known/jwks.json").json())
def validate_token(args): pp(requests.post(f"{TOKEN_URL}/introspect",json={"token":args.token,"audience":INTERNAL_API_AUD,"cert_thumbprint":args.cert_thumbprint}).json())
def device_status(args): from device_registry import get_device; pp(get_device(args.device_id) or {"error":"device_not_found"})
def disable_agent(args): pp(requests.post(f"{TOKEN_URL}/agent/disable",json={"agent_id":args.agent_id}).json())
def enable_agent(args): pp(requests.post(f"{TOKEN_URL}/agent/enable",json={"agent_id":args.agent_id}).json())

def main():
    p = argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd", required=True)
    s=sub.add_parser("login"); s.add_argument("--auto", action="store_true"); s.set_defaults(func=login)
    q=sub.add_parser("gpu-quota-update"); q.add_argument("--subject",default="developer01"); q.add_argument("--quota",type=int,default=3); q.add_argument("--cert-thumbprint"); q.set_defaults(func=gpu_quota_update)
    sub.add_parser("register-agent").set_defaults(func=register_agent)
    ac=sub.add_parser("agent-comment"); ac.add_argument("--cert-thumbprint"); ac.set_defaults(func=agent_comment)
    ag=sub.add_parser("agent-gpu-submit"); ag.add_argument("--cert-thumbprint"); ag.set_defaults(func=agent_gpu_submit)
    a=sub.add_parser("audit"); a.add_argument("--format", choices=["json","jsonl"], default="json"); a.add_argument("--event-type"); a.add_argument("--user"); a.add_argument("--agent-id"); a.set_defaults(func=audit)
    sub.add_parser("jwks").set_defaults(func=jwks_cmd)
    v=sub.add_parser("validate-token"); v.add_argument("--token", required=True); v.add_argument("--cert-thumbprint", required=True); v.set_defaults(func=validate_token)
    d=sub.add_parser("device-status"); d.add_argument("--device-id", required=True); d.set_defaults(func=device_status)
    dis=sub.add_parser("disable-agent"); dis.add_argument("--agent-id", required=True); dis.set_defaults(func=disable_agent)
    en=sub.add_parser("enable-agent"); en.add_argument("--agent-id", required=True); en.set_defaults(func=enable_agent)
    args=p.parse_args(); args.func(args)
if __name__=="__main__": main()
