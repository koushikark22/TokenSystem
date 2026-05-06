import uuid
from token_utils import STATE_DIR, json_load, json_save, now

ATTESTATION_DB = STATE_DIR / "device_attestation.json"


def set_attestation(device_id: str, cert_thumbprint: str, trusted: bool, boot_state: str = "verified", os_name: str = "linux", ttl_seconds: int = 600):
    recs = json_load(ATTESTATION_DB, {})
    evidence_id = f"att-{uuid.uuid4()}"
    recs[device_id] = {
        "device_id": device_id,
        "trusted": trusted,
        "boot_state": boot_state,
        "os": os_name,
        "cert_thumbprint": cert_thumbprint,
        "expires_at": now() + ttl_seconds,
        "evidence_id": evidence_id,
        "simulated": True,
    }
    json_save(ATTESTATION_DB, recs)
    return recs[device_id]


def get_attestation(device_id: str):
    return json_load(ATTESTATION_DB, {}).get(device_id)


def validate_attestation(device_id: str, cert_thumbprint: str):
    rec = get_attestation(device_id)
    if not rec:
        return False, "device_attestation_required", None
    if rec.get("expires_at", 0) < now():
        return False, "device_attestation_required", rec
    if not rec.get("trusted") or rec.get("boot_state") != "verified":
        return False, "device_untrusted", rec
    if rec.get("cert_thumbprint") != cert_thumbprint:
        return False, "device_untrusted", rec
    return True, "trusted", rec
