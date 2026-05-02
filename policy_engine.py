from pathlib import Path
from typing import Any, Dict

try:
    import yaml
except Exception:
    yaml = None

ROOT = Path(__file__).resolve().parent
POLICY_PATH = ROOT / "policies.yaml"


def load_policies() -> Dict[str, Any]:
    if not POLICY_PATH.exists():
        return {}
    text = POLICY_PATH.read_text()
    if yaml:
        return yaml.safe_load(text) or {}
    # lightweight fallback for test envs without PyYAML
    return {
        "policies": {
            "gpu.quota.update": {"allowed_actor_types": ["user"], "require_step_up_mfa": True, "require_pim": True, "require_approval_id": True, "require_device_managed": True, "require_cert_bound_token": True},
            "gpu.job.submit": {"allowed_actor_types": ["user", "agent"], "require_cert_bound_token": True, "require_device_managed": True, "max_gpu_count": 8},
            "deploy.prod": {"allowed_actor_types": ["user"], "require_step_up_mfa": True, "require_pim": True, "require_approval_id": True, "require_device_managed": True, "require_cert_bound_token": True},
            "agent.token": {"allowed_actor_types": ["agent"], "require_agent_id": True, "require_initiating_user": True, "require_cert_bound_token": True},
        }
    }


def evaluate_policy(policy_name: str, context: Dict[str, Any]) -> tuple[bool, str]:
    p = load_policies().get("policies", {}).get(policy_name, {})
    if not p: return True, "allowed"
    if p.get("allowed_actor_types") and context.get("actor_type") not in p["allowed_actor_types"]: return False, "actor_type_not_allowed"
    for k in ["require_agent_id", "require_initiating_user", "require_step_up_mfa", "require_pim", "require_approval_id", "require_ticket_id"]:
        if p.get(k) and not context.get(k.replace("require_", "")): return False, f"{k}_missing"
    if p.get("require_device_managed") and not context.get("device_managed"): return False, "device_not_managed"
    if p.get("require_cert_bound_token") and not context.get("cert_bound"): return False, "certificate_binding_failed"
    if p.get("max_gpu_count") and int(context.get("gpu_count", 0)) > int(p["max_gpu_count"]): return False, "gpu_count_exceeds_policy"
    return True, "allowed"
