import argparse, json, sys
from pathlib import Path

import requests

from token_utils import (
    AGENT_CERT_PATH,
    AGENT_KEY_PATH,
    DEVICE_CERT_PATH,
    DEVICE_KEY_PATH,
    INTERNAL_API_AUD,
    TOKEN_SERVICE_AUD,
    cert_to_pem_string,
    json_load,
    json_save,
    sign_proof,
    STATE_DIR,
)

TOKEN_URL = "http://127.0.0.1:8000"
API_URL = "http://127.0.0.1:9000"
CLI_STATE = STATE_DIR / "devctl_tokens.json"


def pp(obj):
    print(json.dumps(obj, indent=2, sort_keys=True))


def state():
    return json_load(CLI_STATE, {})


def save_state(s):
    json_save(CLI_STATE, s)


def proof_headers(access_token: str, method: str, path: str, *, agent: bool = False):
    cert_path = AGENT_CERT_PATH if agent else DEVICE_CERT_PATH
    key_path = AGENT_KEY_PATH if agent else DEVICE_KEY_PATH
    return {
        "Authorization": f"Bearer {access_token}",
        "X-Client-Cert": cert_to_pem_string(cert_path),
        "X-Proof-Signature": sign_proof(key_path, access_token, method, path),
    }


def login(args):
    r = requests.post(f"{TOKEN_URL}/device/start", json={"client_id": "linux-devctl"})
    r.raise_for_status()
    data = r.json()
    print(data["message"])
    if not args.auto:
        input("Press Enter after completing browser login. For demo use --auto. ")
    # Auto-complete simulated Entra login using Linux device certificate proof.
    proof_token = "device-login-proof"
    complete_payload = {
        "user_code": data["user_code"],
        "device_cert_pem": cert_to_pem_string(DEVICE_CERT_PATH),
        "proof_signature": sign_proof(DEVICE_KEY_PATH, proof_token, "POST", "/device/complete"),
        "proof_token": proof_token,
        "proof_method": "POST",
        "proof_path": "/device/complete",
    }
    c = requests.post(f"{TOKEN_URL}/device/complete", json=complete_payload)
    c.raise_for_status()
    print("Login authorized:"); pp(c.json())
    t = requests.post(f"{TOKEN_URL}/token/poll", json={"device_code": data["device_code"]})
    t.raise_for_status()
    tokens = t.json()
    save_state(tokens)
    print("Tokens saved to demo state store. Access token is short-lived; refresh token rotates.")
    pp({k: v for k, v in tokens.items() if k != "access_token" and k != "refresh_token"})


def refresh(args):
    s = state()
    rt = s.get("refresh_token")
    if not rt:
        sys.exit("No refresh token. Run login first.")
    payload = {
        "refresh_token": rt,
        "device_cert_pem": cert_to_pem_string(DEVICE_CERT_PATH),
        "proof_signature": sign_proof(DEVICE_KEY_PATH, rt, "POST", "/token/refresh"),
        "proof_token": rt,
    }
    r = requests.post(f"{TOKEN_URL}/token/refresh", json=payload)
    pp(r.json())
    r.raise_for_status()
    save_state(r.json())


def obo_build(args):
    s = state(); token = s.get("access_token")
    if not token: sys.exit("Run login first.")
    headers = proof_headers(token, "POST", "/obo/exchange")
    r = requests.post(f"{TOKEN_URL}/obo/exchange", headers=headers, json={"audience": INTERNAL_API_AUD, "scopes": ["build.read"]})
    pp(r.json()); r.raise_for_status()
    downstream = r.json()["access_token"]
    api_headers = proof_headers(downstream, "GET", "/build/status")
    a = requests.get(f"{API_URL}/build/status", headers=api_headers)
    pp(a.json()); a.raise_for_status()


def gpu_submit(args):
    s = state(); token = s.get("access_token")
    if not token: sys.exit("Run login first.")
    headers = proof_headers(token, "POST", "/obo/exchange")
    r = requests.post(f"{TOKEN_URL}/obo/exchange", headers=headers, json={"audience": INTERNAL_API_AUD, "scopes": ["gpu.job.submit"]})
    pp(r.json()); r.raise_for_status()
    gpu_token = r.json()["access_token"]
    api_headers = proof_headers(gpu_token, "POST", "/gpu/jobs/submit")
    a = requests.post(f"{API_URL}/gpu/jobs/submit", headers=api_headers, json={"model": args.model, "dataset": args.dataset, "gpu_count": args.gpu_count})
    pp(a.json()); a.raise_for_status()


def gpu_jobs(args):
    s = state(); token = s.get("access_token")
    if not token: sys.exit("Run login first.")
    headers = proof_headers(token, "POST", "/obo/exchange")
    r = requests.post(f"{TOKEN_URL}/obo/exchange", headers=headers, json={"audience": INTERNAL_API_AUD, "scopes": ["gpu.job.read"]})
    r.raise_for_status()
    gpu_token = r.json()["access_token"]
    api_headers = proof_headers(gpu_token, "GET", "/gpu/jobs")
    a = requests.get(f"{API_URL}/gpu/jobs", headers=api_headers)
    pp(a.json()); a.raise_for_status()


def deploy_prod(args):
    s = state(); token = s.get("access_token")
    if not token: sys.exit("Run login first.")
    headers = proof_headers(token, "POST", "/stepup")
    r = requests.post(f"{TOKEN_URL}/stepup", headers=headers, json={"audience": INTERNAL_API_AUD, "scopes": ["deploy.prod"], "reason": "production deployment"})
    pp(r.json()); r.raise_for_status()
    elevated = r.json()["access_token"]
    api_headers = proof_headers(elevated, "POST", "/deploy/prod")
    a = requests.post(f"{API_URL}/deploy/prod", headers=api_headers, json={"change": "demo"})
    pp(a.json()); a.raise_for_status()


def gpu_quota_update(args):
    s = state(); token = s.get("access_token")
    if not token: sys.exit("Run login first.")
    headers = proof_headers(token, "POST", "/stepup")
    r = requests.post(f"{TOKEN_URL}/stepup", headers=headers, json={"audience": INTERNAL_API_AUD, "scopes": ["gpu.quota.update"], "reason": "GPU quota admin change"})
    pp(r.json()); r.raise_for_status()
    elevated = r.json()["access_token"]
    api_headers = proof_headers(elevated, "POST", "/gpu/quota/update")
    a = requests.post(f"{API_URL}/gpu/quota/update", headers=api_headers, json={"subject": args.subject, "quota": args.quota})
    pp(a.json()); a.raise_for_status()


def register_agent(args):
    r = requests.post(f"{TOKEN_URL}/agent/register", json={
        "agent_id": "agent-gpu-planner-dev",
        "agent_owner": "platform-security",
        "environment": "dev",
        "allowed_scopes": ["repo.read", "pr.comment", "gpu.job.submit", "gpu.job.read"],
        "gpu_quota_max_jobs": 1,
    })
    pp(r.json()); r.raise_for_status()


def agent_token(scopes):
    proof_token = "agent-token-proof"
    headers = {
        "X-Client-Cert": cert_to_pem_string(AGENT_CERT_PATH),
        "X-Proof-Signature": sign_proof(AGENT_KEY_PATH, proof_token, "POST", "/agent/token"),
    }
    r = requests.post(f"{TOKEN_URL}/agent/token", headers=headers, json={
        "agent_id": "agent-gpu-planner-dev",
        "initiating_user": "developer01",
        "scopes": scopes,
        "proof_token": proof_token,
    })
    pp(r.json()); r.raise_for_status()
    return r.json()["access_token"]


def agent_comment(args):
    token = agent_token(["pr.comment"])
    headers = proof_headers(token, "POST", "/agent/comment", agent=True)
    a = requests.post(f"{API_URL}/agent/comment", headers=headers, json={"pr": 123})
    pp(a.json()); a.raise_for_status()


def agent_gpu_submit(args):
    token = agent_token(["gpu.job.submit"])
    headers = proof_headers(token, "POST", "/gpu/jobs/submit", agent=True)
    a = requests.post(f"{API_URL}/gpu/jobs/submit", headers=headers, json={"model": "agent-planned-model", "dataset": "approved-dev-dataset", "gpu_count": 1})
    pp(a.json()); a.raise_for_status()


def audit(args):
    r = requests.get(f"{TOKEN_URL}/audit")
    r.raise_for_status(); pp(r.json())


def main():
    p = argparse.ArgumentParser(description="devctl Linux CLI demo for centralized token service + PKI + OBO + GPU + agent identity")
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
    sub.add_parser("audit").set_defaults(func=audit)
    args = p.parse_args(); args.func(args)

if __name__ == "__main__":
    main()
