import yaml
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parent
POLICY_PATH = ROOT / "policies.yaml"


def load_policies() -> Dict[str, Any]:
    if not POLICY_PATH.exists():
        return {}
    return yaml.safe_load(POLICY_PATH.read_text()) or {}


def evaluate_policy(policy_name: str, context: Dict[str, Any]) -> tuple[bool, str]:
    policies = load_policies().get("policies", {})
    p = policies.get(policy_name, {})
    if not p:
        return True, "allowed"

    actor_type = context.get("actor_type")
    if p.get("allowed_actor_types") and actor_type not in p["allowed_actor_types"]:
        return False, "actor_type_not_allowed"
    for k in ["require_agent_id", "require_initiating_user", "require_step_up_mfa", "require_pim", "require_approval_id", "require_ticket_id"]:
        if p.get(k) and not context.get(k.replace("require_", "")):
            return False, f"{k}_missing"
    if p.get("require_device_managed") and not context.get("device_managed"):
        return False, "device_not_managed"
    if p.get("require_cert_bound_token") and not context.get("cert_bound"):
        return False, "certificate_binding_failed"
    if p.get("max_token_ttl_seconds") and int(context.get("token_ttl_seconds", 0)) > int(p["max_token_ttl_seconds"]):
        return False, "ttl_exceeds_policy"
    if p.get("max_gpu_count") and int(context.get("gpu_count", 0)) > int(p["max_gpu_count"]):
        return False, "gpu_count_exceeds_policy"
    return True, "allowed"
