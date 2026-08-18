from copy import deepcopy

from .settings import SCIM_FILE
from .storage import load_json, save_json, audit, now
from .directory import get_user, effective_entitlements, disable_user

def _db():
    return load_json(SCIM_FILE, {"applications": {"developer-portal": {"users": {}}}})

def _save(db):
    save_json(SCIM_FILE, db)

def provision(username: str, app="developer-portal"):
    user = get_user(username)
    if not user:
        raise KeyError(username)
    ent = effective_entitlements(username)
    db = _db()
    app_db = db.setdefault("applications", {}).setdefault(app, {"users": {}})
    record = {
        "userName": user["upn"],
        "externalId": username,
        "displayName": user["display_name"],
        "active": user.get("status") == "active",
        "groups": deepcopy(user.get("groups", [])),
        "roles": ent["roles"],
        "provisioned_at": now(),
    }
    app_db.setdefault("users", {})[username] = record
    _save(db)
    audit("scim_user_provisioned", user=username, app=app, groups=record["groups"], roles=record["roles"])
    return record

def deprovision(username: str, app="developer-portal", disable_source=False):
    db = _db()
    rec = db.setdefault("applications", {}).setdefault(app, {"users": {}}).setdefault("users", {}).get(username)
    if rec:
        rec["active"] = False
        rec["deprovisioned_at"] = now()
        _save(db)
    if disable_source:
        disable_user(username)
        quarantine_owned_agents(username)
    audit("scim_user_deprovisioned", user=username, app=app, source_disabled=disable_source)
    return rec

def sync_user(username: str, app="developer-portal"):
    return provision(username, app)

def quarantine_owned_agents(username: str):
    # Integrates with TokenSystem's existing local agent registry when present.
    try:
        from token_utils import STATE_DIR, json_load, json_save
        path = STATE_DIR / "agents.json"
        agents = json_load(path, {})
        changed = []
        for agent_id, agent in agents.items():
            if agent.get("owner") == username and agent.get("status") == "active":
                agent["status"] = "disabled"
                agent["disabled_reason"] = "owner_deprovisioned"
                changed.append(agent_id)
        if changed:
            json_save(path, agents)
            audit("owned_agents_quarantined", user=username, agent_ids=changed)
        return changed
    except Exception:
        return []

def list_target(app="developer-portal"):
    return _db().get("applications", {}).get(app, {"users": {}})
