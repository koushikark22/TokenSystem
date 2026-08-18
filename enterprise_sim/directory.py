from copy import deepcopy
from typing import Dict, Any

from .settings import (
    DIRECTORY_FILE, DEFAULT_USER, DEFAULT_PASSWORD, DEFAULT_OTP, DEFAULT_DEVICE
)
from .storage import load_json, save_json, audit, now

DEFAULT_DIRECTORY = {
    "ad": {
        "domain": "nvidialab.local",
        "users": {
            "developer01": {
                "username": "developer01",
                "upn": "developer01@nvidialab.local",
                "display_name": "Developer One",
                "password": DEFAULT_PASSWORD,
                "mfa_secret": DEFAULT_OTP,
                "department": "AI Platform",
                "status": "active",
                "groups": ["AI-Developers", "GPU-Users"],
                "eligible_roles": ["Production-Admin"],
                "risk_level": "low",
            },
            "security01": {
                "username": "security01",
                "upn": "security01@nvidialab.local",
                "display_name": "Security Engineer",
                "password": DEFAULT_PASSWORD,
                "mfa_secret": DEFAULT_OTP,
                "department": "Cybersecurity",
                "status": "active",
                "groups": ["Security-Engineers", "AI-Developers"],
                "eligible_roles": ["Production-Admin", "Policy-Admin"],
                "risk_level": "low",
            },
            "contractor01": {
                "username": "contractor01",
                "upn": "contractor01@nvidialab.local",
                "display_name": "Contractor One",
                "password": DEFAULT_PASSWORD,
                "mfa_secret": DEFAULT_OTP,
                "department": "Contractor",
                "status": "active",
                "groups": ["AI-Developers"],
                "eligible_roles": [],
                "risk_level": "medium",
            },
        },
        "groups": {
            "AI-Developers": {
                "roles": ["Developer"],
                "scopes": ["obo.exchange", "build.read", "gpu.job.read", "gpu.job.submit"],
            },
            "GPU-Users": {
                "roles": ["GPUUser"],
                "scopes": ["gpu.job.read", "gpu.job.submit"],
            },
            "Security-Engineers": {
                "roles": ["SecurityEngineer"],
                "scopes": ["audit.read", "policy.read", "agent.register"],
            },
            "Production-Admins": {
                "roles": ["ProductionAdmin"],
                "scopes": ["deploy.prod", "gpu.quota.update"],
            },
            "Policy-Admins": {
                "roles": ["PolicyAdmin"],
                "scopes": ["policy.admin", "agent.rotate_cert"],
            },
        },
        "devices": {
            "linux-laptop-001": {
                "device_id": "linux-laptop-001",
                "owner": "developer01",
                "managed": True,
                "compliant": True,
                "attested": True,
                "os": "Linux",
                "status": "active",
            },
            "security-laptop-001": {
                "device_id": "security-laptop-001",
                "owner": "security01",
                "managed": True,
                "compliant": True,
                "attested": True,
                "os": "Linux",
                "status": "active",
            },
            "personal-laptop-001": {
                "device_id": "personal-laptop-001",
                "owner": "developer01",
                "managed": False,
                "compliant": False,
                "attested": False,
                "os": "Linux",
                "status": "active",
            },
        },
    },
    "cloud": {"users": {}, "groups": {}},
    "last_sync": None,
}

def bootstrap_directory(force=False):
    if force or not DIRECTORY_FILE.exists():
        save_json(DIRECTORY_FILE, deepcopy(DEFAULT_DIRECTORY))
    sync_ad_to_cloud()
    return load_directory()

def load_directory():
    return load_json(DIRECTORY_FILE, deepcopy(DEFAULT_DIRECTORY))

def save_directory(data):
    save_json(DIRECTORY_FILE, data)

def sync_ad_to_cloud():
    data = load_directory()
    ad = data.setdefault("ad", {})
    cloud = data.setdefault("cloud", {})
    cloud["groups"] = deepcopy(ad.get("groups", {}))
    synced_users = {}
    for username, user in ad.get("users", {}).items():
        u = deepcopy(user)
        u["source"] = "hybrid-ad-sync"
        u["synced_at"] = now()
        synced_users[username] = u
    cloud["users"] = synced_users
    data["last_sync"] = now()
    save_directory(data)
    audit("directory_sync_completed", users=len(synced_users), source="nvidialab.local")
    return data

def get_user(username: str, cloud=True):
    data = load_directory()
    section = "cloud" if cloud else "ad"
    return deepcopy(data.get(section, {}).get("users", {}).get(username))

def get_device(device_id: str):
    return deepcopy(load_directory().get("ad", {}).get("devices", {}).get(device_id))

def group_entitlements(groups):
    d = load_directory()
    group_db = d.get("cloud", {}).get("groups", {})
    scopes, roles = set(), set()
    for group in groups or []:
        rec = group_db.get(group, {})
        scopes.update(rec.get("scopes", []))
        roles.update(rec.get("roles", []))
    return sorted(scopes), sorted(roles)

def effective_entitlements(username: str):
    user = get_user(username)
    if not user:
        return {"scopes": [], "roles": [], "groups": []}
    scopes, roles = group_entitlements(user.get("groups", []))
    return {"scopes": scopes, "roles": roles, "groups": user.get("groups", [])}

def set_user_risk(username: str, risk_level: str):
    if risk_level not in {"low", "medium", "high"}:
        raise ValueError("risk_level must be low, medium, or high")
    data = load_directory()
    user = data["ad"]["users"].get(username)
    if not user:
        raise KeyError(username)
    user["risk_level"] = risk_level
    save_directory(data)
    sync_ad_to_cloud()
    audit("user_risk_changed", user=username, risk_level=risk_level)

def set_device_compliance(device_id: str, compliant: bool):
    data = load_directory()
    device = data["ad"]["devices"].get(device_id)
    if not device:
        raise KeyError(device_id)
    device["compliant"] = bool(compliant)
    device["managed"] = bool(compliant)
    device["attested"] = bool(compliant)
    save_directory(data)
    audit("device_compliance_changed", device_id=device_id, compliant=bool(compliant))

def disable_user(username: str):
    data = load_directory()
    user = data["ad"]["users"].get(username)
    if not user:
        raise KeyError(username)
    user["status"] = "disabled"
    save_directory(data)
    sync_ad_to_cloud()
    audit("directory_user_disabled", user=username)

def enable_user(username: str):
    data = load_directory()
    user = data["ad"]["users"].get(username)
    if not user:
        raise KeyError(username)
    user["status"] = "active"
    save_directory(data)
    sync_ad_to_cloud()
    audit("directory_user_enabled", user=username)
