#!/usr/bin/env python3
import argparse
import json
import sys
import webbrowser
from pathlib import Path

import requests

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from enterprise_sim.api_client import call_internal_api
    from enterprise_sim.broker import exchange_enterprise_token
    from enterprise_sim.bootstrap import main as bootstrap
    from enterprise_sim.crypto import decode_unverified
    from enterprise_sim.directory import set_device_compliance, set_user_risk, sync_ad_to_cloud, enable_user
    from enterprise_sim.pim import activate as pim_activate, revoke as pim_revoke, status as pim_status
    from enterprise_sim.scim import provision, deprovision, list_target
    from enterprise_sim.settings import *
    from enterprise_sim.storage import load_json, save_json
else:
    from .api_client import call_internal_api
    from .broker import exchange_enterprise_token
    from .bootstrap import main as bootstrap
    from .crypto import decode_unverified
    from .directory import set_device_compliance, set_user_risk, sync_ad_to_cloud, enable_user
    from .pim import activate as pim_activate, revoke as pim_revoke, status as pim_status
    from .scim import provision, deprovision, list_target
    from .settings import *
    from .storage import load_json, save_json

def _tokens():
    return load_json(CLI_TOKEN_FILE, {})

def _save_tokens(data):
    save_json(CLI_TOKEN_FILE, data)

def login(args):
    start = requests.post(f"{IDP_ISSUER}/device/start", data={
        "client_id": CLI_CLIENT_ID,
        "scope": "openid profile obo.exchange build.read gpu.job.read gpu.job.submit deploy.prod",
    }, timeout=5)
    start.raise_for_status()
    info = start.json()
    print("User code:", info["user_code"])
    print("Verification URL:", info["verification_uri"])

    if args.auto:
        complete = requests.post(f"{IDP_ISSUER}/device/complete", data={
            "user_code": info["user_code"],
            "user": args.user,
            "password": args.password,
            "otp": args.otp,
            "device_id": args.device,
            "risk_level": args.risk,
        }, timeout=5)
        if complete.status_code >= 400:
            print(complete.text)
            raise SystemExit(1)
    elif args.open_browser:
        webbrowser.open(info["verification_uri"])
        input("Complete sign-in in the browser, then press Enter... ")
    else:
        print("Open the URL above and complete sign-in, then press Enter.")
        input()

    token = requests.post(f"{IDP_ISSUER}/token", data={
        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        "client_id": CLI_CLIENT_ID,
        "device_code": info["device_code"],
    }, timeout=5)
    if token.status_code != 200:
        print(token.text)
        raise SystemExit(1)
    data = token.json()
    state = _tokens()
    state["external_access_token"] = data["access_token"]
    state["id_token"] = data["id_token"]
    _save_tokens(state)
    print("External enterprise sign-in succeeded.")
    print(json.dumps(decode_unverified(data["access_token"]), indent=2))

def exchange(args):
    state = _tokens()
    ext = state.get("external_access_token")
    if not ext:
        raise SystemExit("Run login first.")
    action_claims = None
    if args.action_claims:
        action_claims = json.loads(args.action_claims)
    token = exchange_enterprise_token(ext, args.scopes, action_claims=action_claims)
    state["internal_access_token"] = token
    _save_tokens(state)
    print("Internal token issued.")
    print(json.dumps(decode_unverified(token), indent=2))

def call_api(args):
    token = _tokens().get("internal_access_token")
    if not token:
        raise SystemExit("Run exchange first.")
    body = json.loads(args.body) if args.body else None
    status, payload = call_internal_api(token, args.method, args.path, json_body=body)
    print("HTTP", status)
    print(json.dumps(payload, indent=2))

def main():
    p = argparse.ArgumentParser(description="License-free enterprise IAM lab CLI")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("bootstrap")

    s = sub.add_parser("login")
    s.add_argument("--user", default=DEFAULT_USER)
    s.add_argument("--password", default=DEFAULT_PASSWORD)
    s.add_argument("--otp", default=DEFAULT_OTP)
    s.add_argument("--device", default=DEFAULT_DEVICE)
    s.add_argument("--risk", default="low", choices=["low", "medium", "high"])
    s.add_argument("--auto", action="store_true")
    s.add_argument("--open-browser", action="store_true")

    s = sub.add_parser("exchange")
    s.add_argument("--scopes", nargs="+", required=True)
    s.add_argument("--action-claims", help="JSON object merged into internal token claims")

    s = sub.add_parser("call-api")
    s.add_argument("--method", default="GET")
    s.add_argument("--path", required=True)
    s.add_argument("--body")

    s = sub.add_parser("pim-activate")
    s.add_argument("--user", default=DEFAULT_USER)
    s.add_argument("--role", default="Production-Admin")
    s.add_argument("--device", default=DEFAULT_DEVICE)
    s.add_argument("--justification", default="local enterprise lab privileged task")
    s.add_argument("--ttl", type=int, default=900)

    s = sub.add_parser("pim-status")
    s.add_argument("--user", default=DEFAULT_USER)

    s = sub.add_parser("pim-revoke")
    s.add_argument("--user", default=DEFAULT_USER)
    s.add_argument("--role", default="Production-Admin")

    s = sub.add_parser("set-risk")
    s.add_argument("--user", default=DEFAULT_USER)
    s.add_argument("risk", choices=["low", "medium", "high"])

    s = sub.add_parser("set-device-compliance")
    s.add_argument("--device", default=DEFAULT_DEVICE)
    s.add_argument("state", choices=["true", "false"])

    s = sub.add_parser("directory-sync")

    s = sub.add_parser("scim-provision")
    s.add_argument("--user", default=DEFAULT_USER)

    s = sub.add_parser("scim-deprovision")
    s.add_argument("--user", default=DEFAULT_USER)
    s.add_argument("--disable-source", action="store_true")

    sub.add_parser("scim-list")

    s = sub.add_parser("enable-user")
    s.add_argument("--user", default=DEFAULT_USER)

    args = p.parse_args()
    if args.cmd == "bootstrap":
        return bootstrap()
    if args.cmd == "login":
        return login(args)
    if args.cmd == "exchange":
        return exchange(args)
    if args.cmd == "call-api":
        return call_api(args)
    if args.cmd == "pim-activate":
        print(json.dumps(pim_activate(args.user, args.role, mfa=True, device_id=args.device, justification=args.justification, ttl=args.ttl), indent=2)); return
    if args.cmd == "pim-status":
        print(json.dumps(pim_status(args.user), indent=2)); return
    if args.cmd == "pim-revoke":
        print({"revoked": pim_revoke(args.user, args.role)}); return
    if args.cmd == "set-risk":
        set_user_risk(args.user, args.risk); print("updated"); return
    if args.cmd == "set-device-compliance":
        set_device_compliance(args.device, args.state == "true"); print("updated"); return
    if args.cmd == "directory-sync":
        sync_ad_to_cloud(); print("synced"); return
    if args.cmd == "scim-provision":
        print(json.dumps(provision(args.user), indent=2)); return
    if args.cmd == "scim-deprovision":
        print(json.dumps(deprovision(args.user, disable_source=args.disable_source), indent=2)); return
    if args.cmd == "scim-list":
        print(json.dumps(list_target(), indent=2)); return
    if args.cmd == "enable-user":
        enable_user(args.user); print("enabled"); return

if __name__ == "__main__":
    main()
