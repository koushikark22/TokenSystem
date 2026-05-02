from pathlib import Path

from token_utils import DEVICE_CERT_PATH, cert_thumbprint_sha256_pem, cert_to_pem_string, json_load, json_save

DEVICE_REGISTRY_PATH = Path(__file__).resolve().parent / "device_registry.json"

def bootstrap_device_registry():
    data = json_load(DEVICE_REGISTRY_PATH, {"devices": []})
    thumbprint = cert_thumbprint_sha256_pem(cert_to_pem_string(DEVICE_CERT_PATH))
    device = {
        "device_id": "linux-laptop-001",
        "owner": "developer01",
        "os": "linux",
        "managed": True,
        "edr_healthy": True,
        "disk_encrypted": True,
        "cert_thumbprint": thumbprint,
        "risk": "low",
        "status": "active",
    }
    devices = [d for d in data.get("devices", []) if d.get("device_id") != device["device_id"]]
    devices.append(device)
    data["devices"] = devices
    json_save(DEVICE_REGISTRY_PATH, data)
    return {"status": "ok", "device_id": device["device_id"], "cert_thumbprint": thumbprint}

def get_device(device_id: str):
    for d in json_load(DEVICE_REGISTRY_PATH, {"devices": []}).get("devices", []):
        if d.get("device_id") == device_id:
            return d
    return None

def check_device_posture(device_id: str, cert_thumbprint: str):
    device = get_device(device_id)
    if not device: return False, "device_not_found"
    if device.get("status") != "active": return False, "device_inactive"
    if not device.get("managed"): return False, "device_not_managed"
    if not device.get("edr_healthy"): return False, "edr_unhealthy"
    if not device.get("disk_encrypted"): return False, "disk_not_encrypted"
    if str(device.get("risk", "")).lower() == "high": return False, "device_risk_high"
    if device.get("cert_thumbprint") != cert_thumbprint: return False, "certificate_binding_failed"
    return True, "allowed"
