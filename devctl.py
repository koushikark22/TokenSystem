import argparse
import json
import os
import sys
from pathlib import Path

import requests

from device_registry import bootstrap_device_registry, get_device
from token_utils import (
    AGENT_CERT_PATH,
    AGENT_KEY_PATH,
    DEVICE_CERT_PATH,
    DEVICE_KEY_PATH,
    INTERNAL_API_AUD,
    TOKEN_SERVICE_AUD,
    cert_thumbprint_sha256_pem,
    cert_to_pem_string,
    encode_cert_header,
    json_load,
    json_save,
    sign_proof,
    STATE_DIR,
)

TOKEN_URL = "http://127.0.0.1:8000"
API_URL = "http://127.0.0.1:9000"
CLI_STATE = STATE_DIR / "devctl_tokens.json"

def pp(obj): print(json.dumps(obj, indent=2, sort_keys=True))
def state(): return json_load(CLI_STATE, {})
def save_state(s): json_save(CLI_STATE, s)

def token_preview(token: str) -> str:
    if not token:
        return ""
    if len(token) <= 24:
        return "***"
    return f"{token[:12]}...{token[-8:]}"


def token_output(token_response):
    if os.getenv("SHOW_FULL_TOKENS", "0") == "1":
        return token_response
    return {
        "access_token": "issued",
        "access_token_preview": token_preview(token_response.get("access_token", "")),
        "refresh_token": "stored_locally" if token_response.get("refresh_token") else "",
        "expires_in": token_response.get("expires_in"),
        "token_type": token_response.get("token_type"),
    }


def proof_headers(access_token, method, path, *, agent=False):
    cert_path = AGENT_CERT_PATH if agent else DEVICE_CERT_PATH
    key_path = AGENT_KEY_PATH if agent else DEVICE_KEY_PATH
    cert_pem = cert_to_pem_string(cert_path)
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Client-Cert": encode_cert_header(cert_pem),
        "X-Proof-Signature": sign_proof(key_path, access_token, method, path),
    }

def login(args):
    r = requests.post(f"{TOKEN_URL}/device/start", json={"client_id": "linux-devctl"}); r.raise_for_status(); data = r.json(); print(data["message"])
    if not args.auto: input("Press Enter after completing browser login. For demo use --auto. ")
    proof_token = "device-login-proof"
    c = requests.post(f"{TOKEN_URL}/device/complete", json={"user_code": data["user_code"], "device_cert_pem": cert_to_pem_string(DEVICE_CERT_PATH), "proof_signature": sign_proof(DEVICE_KEY_PATH, proof_token, "POST", "/device/complete"), "proof_token": proof_token, "proof_method": "POST", "proof_path": "/device/complete"}); c.raise_for_status()
    t = requests.post(f"{TOKEN_URL}/token/poll", json={"device_code": data["device_code"]}); t.raise_for_status(); token_data = t.json(); save_state(token_data); pp(token_output(token_data))

def refresh(args):
    s = state(); rt = s.get("refresh_token")
    if not rt: sys.exit("No refresh token. Run login first.")
    r = requests.post(f"{TOKEN_URL}/token/refresh", json={"refresh_token": rt, "device_cert_pem": cert_to_pem_string(DEVICE_CERT_PATH), "proof_signature": sign_proof(DEVICE_KEY_PATH, rt, "POST", "/token/refresh"), "proof_token": rt})
    r.raise_for_status(); token_data = r.json(); save_state(token_data); pp(token_output(token_data))

def obo_build(args):
    token = state().get("access_token"); headers = proof_headers(token, "POST", "/obo/exchange")
    r = requests.post(f"{TOKEN_URL}/obo/exchange", headers=headers, json={"audience": INTERNAL_API_AUD, "scopes": ["build.read"]}); r.raise_for_status()
    downstream = r.json()["access_token"]
    a = requests.get(f"{API_URL}/build/status", headers=proof_headers(downstream, "GET", "/build/status")); pp(a.json()); a.raise_for_status()

def gpu_submit(args):
    token = state().get("access_token")
    r = requests.post(f"{TOKEN_URL}/obo/exchange", headers=proof_headers(token, "POST", "/obo/exchange"), json={"audience": INTERNAL_API_AUD, "scopes": ["gpu.job.submit"]}); r.raise_for_status()
    a = requests.post(f"{API_URL}/gpu/jobs/submit", headers=proof_headers(r.json()["access_token"], "POST", "/gpu/jobs/submit"), json={"model": args.model, "dataset": args.dataset, "gpu_count": args.gpu_count})
    pp(a.json()); a.raise_for_status()

def gpu_jobs(args):
    token = state().get("access_token")
    r = requests.post(f"{TOKEN_URL}/obo/exchange", headers=proof_headers(token, "POST", "/obo/exchange"), json={"audience": INTERNAL_API_AUD, "scopes": ["gpu.job.read"]}); r.raise_for_status()
    a = requests.get(f"{API_URL}/gpu/jobs", headers=proof_headers(r.json()["access_token"], "GET", "/gpu/jobs")); pp(a.json()); a.raise_for_status()

def deploy_prod(args):
    token = state().get("access_token")
    r = requests.post(f"{TOKEN_URL}/stepup", headers=proof_headers(token, "POST", "/stepup"), json={"audience": INTERNAL_API_AUD, "scopes": ["deploy.prod"], "reason": "production deployment"}); r.raise_for_status()
    a = requests.post(f"{API_URL}/deploy/prod", headers=proof_headers(r.json()["access_token"], "POST", "/deploy/prod"), json={"change": "demo"}); pp(a.json()); a.raise_for_status()

def gpu_quota_update(args):
    token = state().get("access_token")
    r = requests.post(f"{TOKEN_URL}/stepup", headers=proof_headers(token, "POST", "/stepup"), json={"audience": INTERNAL_API_AUD, "scopes": ["gpu.quota.update"], "reason": "GPU quota admin change"}); r.raise_for_status()
    a = requests.post(f"{API_URL}/gpu/quota/update", headers=proof_headers(r.json()["access_token"], "POST", "/gpu/quota/update"), json={"subject": args.subject, "quota": args.quota}); pp(a.json()); a.raise_for_status()

def register_agent(args): pp(requests.post(f"{TOKEN_URL}/agent/register", json={"agent_id": "agent-gpu-planner-dev", "agent_owner": "platform-security", "environment": "dev", "allowed_scopes": ["repo.read", "pr.comment", "gpu.job.submit", "gpu.job.read"], "gpu_quota_max_jobs": 1}).json())
def agent_token(scopes):
    proof_token = "agent-token-proof"
    headers = {"X-Client-Cert": encode_cert_header(cert_to_pem_string(AGENT_CERT_PATH)), "X-Proof-Signature": sign_proof(AGENT_KEY_PATH, proof_token, "POST", "/agent/token")}
    r = requests.post(f"{TOKEN_URL}/agent/token", headers=headers, json={"agent_id": "agent-gpu-planner-dev", "initiating_user": "developer01", "scopes": scopes, "proof_token": proof_token}); r.raise_for_status(); return r.json()["access_token"]
def agent_comment(args): a = requests.post(f"{API_URL}/agent/comment", headers=proof_headers(agent_token(["pr.comment"]), "POST", "/agent/comment", agent=True), json={"pr": 123}); pp(a.json()); a.raise_for_status()
def agent_gpu_submit(args): a = requests.post(f"{API_URL}/gpu/jobs/submit", headers=proof_headers(agent_token(["gpu.job.submit"]), "POST", "/gpu/jobs/submit", agent=True), json={"model": "agent-planned-model", "dataset": "approved-dev-dataset", "gpu_count": 1}); pp(a.json()); a.raise_for_status()

def audit(args):
    events = requests.get(f"{TOKEN_URL}/audit").json()
    if args.event_type: events = [e for e in events if e.get("event_type") == args.event_type]
    if args.user: events = [e for e in events if e.get("user") == args.user]
    if args.agent_id: events = [e for e in events if e.get("agent_id") == args.agent_id]
    if args.format == "jsonl": print("\n".join(json.dumps(e) for e in events))
    else: pp(events)

def jwks_cmd(args): pp(requests.get(f"{TOKEN_URL}/.well-known/jwks.json").json())
def validate_token(args): pp(requests.post(f"{TOKEN_URL}/introspect", json={"token": args.token, "audience": INTERNAL_API_AUD}).json())
def device_status(args): pp(get_device(args.device_id) or {"error":"device_not_found"})
def disable_agent(args): pp(requests.post(f"{TOKEN_URL}/agent/disable", json={"agent_id": args.agent_id}).json())
def enable_agent(args): pp(requests.post(f"{TOKEN_URL}/agent/enable", json={"agent_id": args.agent_id}).json())
def bootstrap_device_registry_cmd(args): pp(bootstrap_device_registry())

def main():
    p = argparse.ArgumentParser()
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("login"); s.add_argument("--auto", action="store_true"); s.set_defaults(func=login)
    sub.add_parser("refresh").set_defaults(func=refresh)
    sub.add_parser("obo-build").set_defaults(func=obo_build)
    gs = sub.add_parser("gpu-submit"); gs.add_argument("--model", default="demo-transformer"); gs.add_argument("--dataset", default="synthetic-dev-data"); gs.add_argument("--gpu-count", type=int, default=1); gs.set_defaults(func=gpu_submit)
    sub.add_parser("gpu-jobs").set_defaults(func=gpu_jobs)
    sub.add_parser("deploy-prod").set_defaults(func=deploy_prod)
    q = sub.add_parser("gpu-quota-update"); q.add_argument("--subject", default="developer01"); q.add_argument("--quota", type=int, default=3); q.set_defaults(func=gpu_quota_update)
    sub.add_parser("register-agent").set_defaults(func=register_agent)
    sub.add_parser("agent-comment").set_defaults(func=agent_comment)
    sub.add_parser("agent-gpu-submit").set_defaults(func=agent_gpu_submit)
    a = sub.add_parser("audit"); a.add_argument("--format", choices=["json","jsonl"], default="json"); a.add_argument("--event-type"); a.add_argument("--user"); a.add_argument("--agent-id"); a.set_defaults(func=audit)
    sub.add_parser("jwks").set_defaults(func=jwks_cmd)
    v = sub.add_parser("validate-token"); v.add_argument("--token", required=True); v.set_defaults(func=validate_token)
    d = sub.add_parser("device-status"); d.add_argument("--device-id", required=True); d.set_defaults(func=device_status)
    dis = sub.add_parser("disable-agent"); dis.add_argument("--agent-id", required=True); dis.set_defaults(func=disable_agent)
    en = sub.add_parser("enable-agent"); en.add_argument("--agent-id", required=True); en.set_defaults(func=enable_agent)
    sub.add_parser("bootstrap-device-registry").set_defaults(func=bootstrap_device_registry_cmd)
    args = p.parse_args(); args.func(args)

if __name__ == "__main__":
    main()
