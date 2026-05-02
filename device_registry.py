from pathlib import Path
from token_utils import json_load

DEVICE_REGISTRY_PATH = Path(__file__).resolve().parent / "device_registry.json"


def get_device(device_id: str):
    data = json_load(DEVICE_REGISTRY_PATH, {"devices": []})
    for d in data.get("devices", []):
        if d.get("device_id") == device_id:
            return d
    return None


def check_device_posture(device_id: str, cert_thumbprint: str):
    device = get_device(device_id)
    if not device:
        return False, "device_not_found"
    if device.get("status") != "active":
        return False, "device_inactive"
    if not device.get("managed"):
        return False, "device_not_managed"
    if not device.get("edr_healthy"):
        return False, "edr_unhealthy"
    if not device.get("disk_encrypted"):
        return False, "disk_not_encrypted"
    if str(device.get("risk", "")).lower() == "high":
        return False, "device_risk_high"
    if device.get("cert_thumbprint") != cert_thumbprint:
        return False, "certificate_binding_failed"
    return True, "allowed"
