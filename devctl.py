import argparse
import json
import os
import sys

import requests

from device_registry import bootstrap_device_registry, get_device, list_devices, register_device, rotate_device_cert, set_device_status
from token_utils import (
    AGENT_CERT_PATH,
    AGENT_KEY_PATH,
    DEVICE_CERT_PATH,
    DEVICE_KEY_PATH,
    INTERNAL_API_AUD,
    STATE_DIR,
    cert_thumbprint_sha256_pem,
    cert_to_pem_string,
    encode_cert_header,
    json_load,
    json_save,
    now,
    sign_proof,
)
from user_registry import ensure_default_user, list_users, register_user as reg_user_local, set_user_status

TOKEN_URL = "http://127.0.0.1:8000"
API_URL = "http://127.0.0.1:9000"
CLI_STATE = STATE_DIR / "devctl_tokens.json"
AUDIT_DB = STATE_DIR / "audit.json"


def pp(obj): print(json.dumps(obj, indent=2, sort_keys=True))
def state(): return json_load(CLI_STATE, {})
def save_state(s): json_save(CLI_STATE, s)

def _audit(event_type, **fields):
    events = json_load(AUDIT_DB, [])
    evt = {"event_type": event_type, "timestamp": now()}
    evt.update(fields)
    events.append(evt)
    json_save(AUDIT_DB, events[-2000:])

def token_preview(token: str) -> str:
    if not token:
        return ""
    if len(token) <= 24:
        return "***"
    return f"{token[:12]}...{token[-8:]}"

def token_output(token_response):
    if os.getenv("SHOW_FULL_TOKENS", "0") == "1":
        return token_response
    return {"access_token": "issued", "access_token_preview": token_preview(token_response.get("access_token", "")), "refresh_token": "stored_locally" if token_response.get("refresh_token") else "", "expires_in": token_response.get("expires_in"), "token_type": token_response.get("token_type")}

def proof_headers(access_token, method, path, *, agent=False):
    cert_path = AGENT_CERT_PATH if agent else DEVICE_CERT_PATH
    key_path = AGENT_KEY_PATH if agent else DEVICE_KEY_PATH
    cert_pem = cert_to_pem_string(cert_path)
    return {"Authorization": f"Bearer {access_token}", "X-Client-Cert": encode_cert_header(cert_pem), "X-Proof-Signature": sign_proof(key_path, access_token, method, path)}

def login(args):
    r = requests.post(f"{TOKEN_URL}/device/start", json={"client_id": "linux-devctl"}); r.raise_for_status(); data = r.json(); print(data["message"])
    if not args.auto: input("Press Enter after completing browser login. For demo use --auto. ")
    proof_token = "device-login-proof"
    c = requests.post(f"{TOKEN_URL}/device/complete", json={"user_code": data["user_code"], "device_cert_pem": cert_to_pem_string(DEVICE_CERT_PATH), "proof_signature": sign_proof(DEVICE_KEY_PATH, proof_token, "POST", "/device/complete"), "proof_token": proof_token}); c.raise_for_status()
    t = requests.post(f"{TOKEN_URL}/token/poll", json={"device_code": data["device_code"]}); t.raise_for_status(); token_data = t.json(); save_state(token_data); pp(token_output(token_data))

def refresh(args):
    rt = state().get("refresh_token")
    if not rt: sys.exit("No refresh token. Run login first.")
    r = requests.post(f"{TOKEN_URL}/token/refresh", json={"refresh_token": rt, "device_cert_pem": cert_to_pem_string(DEVICE_CERT_PATH), "proof_signature": sign_proof(DEVICE_KEY_PATH, rt, "POST", "/token/refresh"), "proof_token": rt})
    r.raise_for_status(); token_data = r.json(); save_state(token_data); pp(token_output(token_data))

def obo_build(args):
    token = state().get("access_token")
    r = requests.post(f"{TOKEN_URL}/obo/exchange", headers=proof_headers(token, "POST", "/obo/exchange"), json={"audience": INTERNAL_API_AUD, "scopes": ["build.read"]}); r.raise_for_status()
    a = requests.get(f"{API_URL}/build/status", headers=proof_headers(r.json()["access_token"], "GET", "/build/status")); pp(a.json()); a.raise_for_status()

def gpu_submit(args):
    token = state().get("access_token")
    r = requests.post(f"{TOKEN_URL}/obo/exchange", headers=proof_headers(token, "POST", "/obo/exchange"), json={"audience": INTERNAL_API_AUD, "scopes": ["gpu.job.submit"]}); r.raise_for_status()
    a = requests.post(f"{API_URL}/gpu/jobs/submit", headers=proof_headers(r.json()["access_token"], "POST", "/gpu/jobs/submit"), json={"model": args.model, "dataset": args.dataset, "gpu_count": args.gpu_count}); pp(a.json()); a.raise_for_status()

def gpu_jobs(args):
    token = state().get("access_token")
    r = requests.post(f"{TOKEN_URL}/obo/exchange", headers=proof_headers(token, "POST", "/obo/exchange"), json={"audience": INTERNAL_API_AUD, "scopes": ["gpu.job.read"]}); r.raise_for_status()
    a = requests.get(f"{API_URL}/gpu/jobs", headers=proof_headers(r.json()["access_token"], "GET", "/gpu/jobs")); pp(a.json()); a.raise_for_status()

def deploy_prod(args):
    token = state().get("access_token")
    r = requests.post(f"{TOKEN_URL}/stepup", headers=proof_headers(token, "POST", "/stepup"), json={"audience": INTERNAL_API_AUD, "scopes": ["deploy.prod"], "reason": "production deployment"})
    r.raise_for_status()
    a = requests.post(f"{API_URL}/deploy/prod", headers=proof_headers(r.json()["access_token"], "POST", "/deploy/prod"), json={"change": "demo"})
    pp(a.json()); a.raise_for_status()

def gpu_quota_update(args):
    token = state().get("access_token")
    r = requests.post(f"{TOKEN_URL}/stepup", headers=proof_headers(token, "POST", "/stepup"), json={"audience": INTERNAL_API_AUD, "scopes": ["gpu.quota.update"], "reason": "GPU quota admin change"})
    r.raise_for_status()
    a = requests.post(f"{API_URL}/gpu/quota/update", headers=proof_headers(r.json()["access_token"], "POST", "/gpu/quota/update"), json={"subject": args.subject, "quota": args.quota})
    pp(a.json()); a.raise_for_status()

def register_agent(args):
    payload={"agent_id": args.agent_id or "agent-gpu-planner-dev", "agent_owner":"platform-security", "environment":"dev", "allowed_scopes":["repo.read","pr.comment","gpu.job.submit","gpu.job.read"], "gpu_quota_max_jobs": getattr(args, "gpu_quota_max_jobs", 1)}
    pp(requests.post(f"{TOKEN_URL}/agent/register", json=payload).json())

def agent_token(scopes, agent_id="agent-gpu-planner-dev"):
    proof_token = "agent-token-proof"
    headers = {"X-Client-Cert": encode_cert_header(cert_to_pem_string(AGENT_CERT_PATH)), "X-Proof-Signature": sign_proof(AGENT_KEY_PATH, proof_token, "POST", "/agent/token")}
    r = requests.post(f"{TOKEN_URL}/agent/token", headers=headers, json={"agent_id": agent_id, "initiating_user": "developer01", "scopes": scopes, "proof_token": proof_token}); r.raise_for_status(); return r.json()["access_token"]

def agent_comment(args): a = requests.post(f"{API_URL}/agent/comment", headers=proof_headers(agent_token(["pr.comment"]), "POST", "/agent/comment", agent=True), json={"pr": 123}); pp(a.json()); a.raise_for_status()
def agent_gpu_submit(args):
    agent_id = getattr(args, "agent_id", "agent-gpu-planner-dev")
    a = requests.post(f"{API_URL}/gpu/jobs/submit", headers=proof_headers(agent_token(["gpu.job.submit"], agent_id=agent_id), "POST", "/gpu/jobs/submit", agent=True), json={"model": "agent-planned-model", "dataset": "approved-dev-dataset", "gpu_count": 1})
    pp(a.json()); a.raise_for_status()

def audit(args):
    events = requests.get(f"{TOKEN_URL}/audit").json()
    if getattr(args, "event_type", None): events = [e for e in events if e.get("event_type") == args.event_type]
    if getattr(args, "user", None): events = [e for e in events if e.get("user") == args.user]
    if getattr(args, "agent_id", None): events = [e for e in events if e.get("agent_id") == args.agent_id]
    pp(events)


def _agent_gpu_submit_for_demo(agent_id):
    try:
        agent_gpu_submit(argparse.Namespace(agent_id=agent_id))
    except requests.HTTPError as exc:
        rsp = getattr(exc, "response", None)
        data = rsp.json() if rsp is not None and rsp.content else {"error": str(exc)}
        if rsp is not None and rsp.status_code == 429 and data.get("error") == "gpu_quota_exceeded":
            pp({"status": "expected_policy_enforcement", "detail": data, "agent_id": agent_id})
            return
        raise

def users_cmd(args): ensure_default_user(); pp({"users": list_users()})
def register_user_cmd(args): pp(reg_user_local(args.user)); _audit("user_registered", user=args.user)
def disable_user_cmd(args): pp(set_user_status(args.user, "disabled") or {"error":"user_not_found"}); _audit("user_disabled", user=args.user)
def enable_user_cmd(args): pp(set_user_status(args.user, "active") or {"error":"user_not_found"}); _audit("user_enabled", user=args.user)
def revoke_user_cmd(args): pp(set_user_status(args.user, "revoked") or {"error":"user_not_found"}); _audit("user_revoked", user=args.user)
def devices_cmd(args): pp({"devices": list_devices(), "runtime_note": "multi-device login beyond linux-laptop-001 is simulated lifecycle only unless cert/key paths are switched"})
def register_device_cmd(args): pp(register_device(args.user, args.device)); _audit("device_registered", user=args.user, device_id=args.device)
def disable_device_cmd(args): pp(set_device_status(args.device, "disabled") or {"error":"device_not_found"}); _audit("device_disabled", device_id=args.device)
def enable_device_cmd(args): pp(set_device_status(args.device, "active") or {"error":"device_not_found"}); _audit("device_enabled", device_id=args.device)
def rotate_device_cert_cmd(args): thumb = cert_thumbprint_sha256_pem(cert_to_pem_string(DEVICE_CERT_PATH)); pp(rotate_device_cert(args.device, thumb) or {"error":"device_not_found"}); _audit("device_cert_rotated", device_id=args.device)
def agents_cmd(args): r=requests.get(f"{TOKEN_URL}/agents"); r.raise_for_status(); pp(r.json())
def rotate_agent_cert(args): r=requests.post(f"{TOKEN_URL}/agent/rotate-cert", json={"agent_id":args.agent_id}); r.raise_for_status(); pp(r.json()); _audit("agent_cert_rotated", agent_id=args.agent_id)
def agent_status(args): r=requests.get(f"{TOKEN_URL}/agent/status/{args.agent_id}"); r.raise_for_status(); pp(r.json())
def device_status(args): pp(get_device(args.device_id) or {"error":"device_not_found"})
def disable_agent(args): pp(requests.post(f"{TOKEN_URL}/agent/disable", json={"agent_id": args.agent_id}).json())
def enable_agent(args): pp(requests.post(f"{TOKEN_URL}/agent/enable", json={"agent_id": args.agent_id}).json())
def bootstrap_device_registry_cmd(args): pp(bootstrap_device_registry())

def demo_full(args):
    bootstrap_device_registry_cmd(args)
    login(argparse.Namespace(auto=True))
    obo_build(args)
    gpu_submit(argparse.Namespace(model="demo-transformer", dataset="synthetic-dev-data", gpu_count=1))
    gpu_jobs(args)
    refresh(args)
    refresh(args)
    deploy_prod(args)
    gpu_quota_update(argparse.Namespace(subject="developer01", quota=3))
    demo_agent_id = f"agent-gpu-planner-demo-full-{now()}"
    register_agent(argparse.Namespace(agent_id=demo_agent_id, gpu_quota_max_jobs=3))
    agent_comment(args)
    _agent_gpu_submit_for_demo(demo_agent_id)
    audit(argparse.Namespace(event_type=None, user=None, agent_id=None))
    _audit("demo_full_completed")

def demo_enterprise(args):
    users_cmd(args)
    register_user_cmd(argparse.Namespace(user="developer02"))
    register_device_cmd(argparse.Namespace(user="developer02", device="linux-laptop-002"))
    devices_cmd(args)
    disable_device_cmd(argparse.Namespace(device="linux-laptop-002"))
    device_status(argparse.Namespace(device_id="linux-laptop-002"))
    enable_device_cmd(argparse.Namespace(device="linux-laptop-002"))
    demo_agent_id = f"agent-gpu-planner-demo-enterprise-{now()}"
    register_agent(argparse.Namespace(agent_id=demo_agent_id, gpu_quota_max_jobs=3))
    agents_cmd(args)
    agent_status(argparse.Namespace(agent_id=demo_agent_id))
    _agent_gpu_submit_for_demo(demo_agent_id)
    audit(argparse.Namespace(event_type=None, user=None, agent_id=None))
    _audit("demo_enterprise_completed")

def main():
    p=argparse.ArgumentParser(); sub=p.add_subparsers(dest="cmd", required=True)
    s=sub.add_parser("login"); s.add_argument("--auto", action="store_true"); s.set_defaults(func=login)
    sub.add_parser("refresh").set_defaults(func=refresh); sub.add_parser("obo-build").set_defaults(func=obo_build)
    gs=sub.add_parser("gpu-submit"); gs.add_argument("--model", default="demo-transformer"); gs.add_argument("--dataset", default="synthetic-dev-data"); gs.add_argument("--gpu-count", type=int, default=1); gs.set_defaults(func=gpu_submit)
    sub.add_parser("gpu-jobs").set_defaults(func=gpu_jobs)
    sub.add_parser("deploy-prod").set_defaults(func=deploy_prod)
    q=sub.add_parser("gpu-quota-update"); q.add_argument("--subject", default="developer01"); q.add_argument("--quota", type=int, default=3); q.set_defaults(func=gpu_quota_update)
    ra=sub.add_parser("register-agent"); ra.add_argument("--agent-id", default="agent-gpu-planner-dev"); ra.add_argument("--gpu-quota-max-jobs", type=int, default=1); ra.set_defaults(func=register_agent)
    sub.add_parser("agent-comment").set_defaults(func=agent_comment); sub.add_parser("agent-gpu-submit").set_defaults(func=agent_gpu_submit)
    a=sub.add_parser("audit"); a.add_argument("--event-type"); a.add_argument("--user"); a.add_argument("--agent-id"); a.set_defaults(func=audit)
    d=sub.add_parser("device-status"); d.add_argument("--device-id", required=True); d.set_defaults(func=device_status)
    dis=sub.add_parser("disable-agent"); dis.add_argument("--agent-id", required=True); dis.set_defaults(func=disable_agent)
    en=sub.add_parser("enable-agent"); en.add_argument("--agent-id", required=True); en.set_defaults(func=enable_agent)
    sub.add_parser("bootstrap-device-registry").set_defaults(func=bootstrap_device_registry_cmd)
    sub.add_parser("users").set_defaults(func=users_cmd); ru=sub.add_parser("register-user"); ru.add_argument("--user", required=True); ru.set_defaults(func=register_user_cmd)
    du=sub.add_parser("disable-user"); du.add_argument("--user", required=True); du.set_defaults(func=disable_user_cmd)
    eu=sub.add_parser("enable-user"); eu.add_argument("--user", required=True); eu.set_defaults(func=enable_user_cmd)
    rv=sub.add_parser("revoke-user"); rv.add_argument("--user", required=True); rv.set_defaults(func=revoke_user_cmd)
    sub.add_parser("devices").set_defaults(func=devices_cmd); rd=sub.add_parser("register-device"); rd.add_argument("--user", required=True); rd.add_argument("--device", required=True); rd.set_defaults(func=register_device_cmd)
    dd=sub.add_parser("disable-device"); dd.add_argument("--device", required=True); dd.set_defaults(func=disable_device_cmd)
    ed=sub.add_parser("enable-device"); ed.add_argument("--device", required=True); ed.set_defaults(func=enable_device_cmd)
    rdc=sub.add_parser("rotate-device-cert"); rdc.add_argument("--device", required=True); rdc.set_defaults(func=rotate_device_cert_cmd)
    sub.add_parser("agents").set_defaults(func=agents_cmd); rac=sub.add_parser("rotate-agent-cert"); rac.add_argument("--agent-id", required=True); rac.set_defaults(func=rotate_agent_cert)
    ast=sub.add_parser("agent-status"); ast.add_argument("--agent-id", required=True); ast.set_defaults(func=agent_status)
    sub.add_parser("demo-full").set_defaults(func=demo_full); sub.add_parser("demo-enterprise").set_defaults(func=demo_enterprise)
    args=p.parse_args(); args.func(args)

if __name__ == '__main__':
    main()
