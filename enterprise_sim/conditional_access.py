from dataclasses import dataclass, asdict

from .settings import PRIVILEGED_SCOPES, GPU_SENSITIVE_SCOPES
from .pim import active_roles

@dataclass
class Decision:
    decision: str
    reason: str
    risk_level: str
    policy_id: str = "ca-sim-v1"
    requires_step_up: bool = False

    def to_dict(self):
        return asdict(self)

def evaluate(*, user: dict, device: dict, requested_scopes, mfa: bool, risk_level=None):
    scopes = set(requested_scopes or [])
    risk = risk_level or user.get("risk_level", "low")

    if user.get("status") != "active":
        return Decision("deny", "user_not_active", risk)
    if not mfa:
        return Decision("deny", "mfa_required", risk)
    if risk == "high":
        return Decision("deny", "high_user_risk", risk)
    if not device or device.get("status") != "active":
        return Decision("deny", "unknown_or_disabled_device", risk)

    sensitive = bool(scopes & (PRIVILEGED_SCOPES | GPU_SENSITIVE_SCOPES))
    if sensitive and not device.get("managed"):
        return Decision("deny", "managed_device_required", risk)
    if sensitive and not device.get("compliant"):
        return Decision("deny", "compliant_device_required", risk)
    if sensitive and not device.get("attested"):
        return Decision("deny", "device_attestation_required", risk)

    if scopes & PRIVILEGED_SCOPES:
        roles = set(active_roles(user["username"]))
        if "deploy.prod" in scopes or "gpu.quota.update" in scopes:
            if "Production-Admin" not in roles:
                return Decision("step_up", "pim_activation_required", risk, requires_step_up=True)
        if "policy.admin" in scopes or "agent.rotate_cert" in scopes:
            if "Policy-Admin" not in roles:
                return Decision("step_up", "pim_activation_required", risk, requires_step_up=True)

    if risk == "medium" and scopes & PRIVILEGED_SCOPES:
        return Decision("step_up", "medium_risk_requires_reauthentication", risk, requires_step_up=True)

    return Decision("allow", "conditional_access_allow", risk)
