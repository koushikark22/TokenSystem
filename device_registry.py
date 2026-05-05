from pathlib import Path

from token_utils import DEBUG_CERT_BINDING, DEVICE_CERT_PATH, cert_thumbprint_sha256_pem, cert_to_pem_string, json_load, json_save, now
from user_registry import add_user_device, ensure_default_user

DEVICE_REGISTRY_PATH = Path(__file__).resolve().parent / "device_registry.json"


def _db():
    return json_load(DEVICE_REGISTRY_PATH, {"devices": []})


def _save(data):
    DEVICE_REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    json_save(DEVICE_REGISTRY_PATH, data)


def bootstrap_device_registry():
    ensure_default_user()
    thumbprint = cert_thumbprint_sha256_pem(cert_to_pem_string(DEVICE_CERT_PATH))
    device = register_device("developer01", "linux-laptop-001", thumbprint=thumbprint)
    return {"status": "ok", "device_id": device["device_id"], "cert_thumbprint": thumbprint}


def list_devices():
    return _db().get("devices", [])


def register_device(owner, device_id, thumbprint=None):
    data = _db()
    thumbprint = thumbprint or cert_thumbprint_sha256_pem(cert_to_pem_string(DEVICE_CERT_PATH))
    devices = [d for d in data.get("devices", []) if d.get("device_id") != device_id]
    existing = get_device(device_id)
    if existing:
        existing.update({"owner": owner, "cert_thumbprint": thumbprint, "status": existing.get("status","active")})
        existing.setdefault("posture", {"managed": True, "edr_healthy": True, "disk_encrypted": True, "risk": "low"})
        devices.append(existing)
    else:
        devices.append({
        "device_id": device_id,
        "owner": owner,
        "cert_thumbprint": thumbprint,
        "status": "active",
        "posture": {"managed": True, "edr_healthy": True, "disk_encrypted": True, "risk": "low"},
        "created": now(),
    })
    data["devices"] = devices
    _save(data)
    add_user_device(owner, device_id)
    return get_device(device_id)


def set_device_status(device_id, status):
    data = _db()
    for d in data.get("devices", []):
        if d.get("device_id") == device_id:
            d["status"] = status
            _save(data)
            return d
    return None


def rotate_device_cert(device_id, cert_thumbprint):
    data = _db()
    for d in data.get("devices", []):
        if d.get("device_id") == device_id:
            d["cert_thumbprint"] = cert_thumbprint
            _save(data)
            return d
    return None


def get_device(device_id: str):
    for d in _db().get("devices", []):
        if d.get("device_id") == device_id:
            return d
    return None


def check_device_posture(device_id: str, cert_thumbprint: str):
    device = get_device(device_id)
    if not device: return False, "device_not_found"
    posture = device.get("posture") or {"managed": device.get("managed", True), "edr_healthy": device.get("edr_healthy", True), "disk_encrypted": device.get("disk_encrypted", True), "risk": device.get("risk", "low")}
    if device.get("status") != "active": return False, "device_inactive"
    if not posture.get("managed", True): return False, "device_not_managed"
    if not posture.get("edr_healthy", True): return False, "edr_unhealthy"
    if not posture.get("disk_encrypted", True): return False, "disk_not_encrypted"
    if str(posture.get("risk", "low")).lower() == "high": return False, "device_risk_high"
    expected_thumbprint = device.get("cert_thumbprint")
    if expected_thumbprint != cert_thumbprint:
        if DEBUG_CERT_BINDING:
            return False, f"certificate_binding_failed: device_id={device_id} expected={expected_thumbprint} actual={cert_thumbprint}"
        return False, "certificate_binding_failed"
    return True, "allowed"
