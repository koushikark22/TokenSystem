import uuid

from .settings import PIM_FILE
from .storage import load_json, save_json, now, audit
from .directory import get_user, get_device

DEFAULT_TTL = 900
MAX_TTL = 1800

def _db():
    return load_json(PIM_FILE, {"activations": []})

def _save(db):
    save_json(PIM_FILE, db)

def activate(username: str, role: str, *, mfa=True, device_id=None, justification="", ttl=DEFAULT_TTL):
    user = get_user(username)
    if not user or user.get("status") != "active":
        raise PermissionError("user_not_active")
    if role not in user.get("eligible_roles", []):
        raise PermissionError("role_not_eligible")
    if not mfa:
        raise PermissionError("mfa_required")
    if not justification.strip():
        raise PermissionError("justification_required")
    device = get_device(device_id) if device_id else None
    if not device or not all([device.get("managed"), device.get("compliant"), device.get("attested")]):
        raise PermissionError("trusted_device_required")
    ttl = min(max(int(ttl), 60), MAX_TTL)
    db = _db()
    activation = {
        "activation_id": f"pim-{uuid.uuid4()}",
        "user": username,
        "role": role,
        "device_id": device_id,
        "justification": justification,
        "activated_at": now(),
        "expires_at": now() + ttl,
        "status": "active",
    }
    db["activations"].append(activation)
    _save(db)
    audit("pim_role_activated", **activation)
    return activation

def active_roles(username: str):
    current = now()
    db = _db()
    changed = False
    roles = []
    for rec in db.get("activations", []):
        if rec.get("status") == "active" and rec.get("expires_at", 0) <= current:
            rec["status"] = "expired"
            changed = True
        if rec.get("user") == username and rec.get("status") == "active":
            roles.append(rec["role"])
    if changed:
        _save(db)
    return sorted(set(roles))

def revoke(username: str, role: str):
    db = _db()
    changed = False
    for rec in db.get("activations", []):
        if rec.get("user") == username and rec.get("role") == role and rec.get("status") == "active":
            rec["status"] = "revoked"
            rec["revoked_at"] = now()
            changed = True
    if changed:
        _save(db)
        audit("pim_role_revoked", user=username, role=role)
    return changed

def status(username: str):
    active = active_roles(username)
    return {"user": username, "active_roles": active, "activations": [x for x in _db().get("activations", []) if x.get("user") == username]}
