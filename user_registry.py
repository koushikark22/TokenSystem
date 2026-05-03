from pathlib import Path
from token_utils import json_load, json_save, now

USERS_PATH = Path(__file__).resolve().parent / ".state" / "users.json"
DEFAULT_SCOPES = ["obo.exchange", "build.read", "gpu.job.read", "gpu.job.submit"]


def _db():
    return json_load(USERS_PATH, {"users": []})


def _save(data):
    USERS_PATH.parent.mkdir(parents=True, exist_ok=True)
    json_save(USERS_PATH, data)


def ensure_default_user():
    register_user("developer01")


def list_users():
    ensure_default_user()
    return _db()["users"]


def get_user(user_id):
    for u in _db().get("users", []):
        if u.get("user_id") == user_id:
            return u
    return None


def register_user(user_id, allowed_scopes=None, quota=1):
    data = _db()
    users = [u for u in data.get("users", []) if u.get("user_id") != user_id]
    existing = get_user(user_id)
    users.append(existing or {
        "user_id": user_id,
        "status": "active",
        "allowed_scopes": allowed_scopes or list(DEFAULT_SCOPES),
        "quota": quota,
        "devices": [],
        "created": now(),
    })
    data["users"] = users
    _save(data)
    return get_user(user_id)


def set_user_status(user_id, status):
    data = _db()
    for u in data.get("users", []):
        if u.get("user_id") == user_id:
            u["status"] = status
            _save(data)
            return u
    return None


def add_user_device(user_id, device_id):
    data = _db()
    for u in data.get("users", []):
        if u.get("user_id") == user_id:
            if device_id not in u.get("devices", []):
                u.setdefault("devices", []).append(device_id)
            _save(data)
            return u
    return None
