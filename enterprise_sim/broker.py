import uuid
from typing import Iterable

from .crypto import verify_jwt
from .directory import get_user, get_device, effective_entitlements
from .conditional_access import evaluate
from .pim import active_roles
from .settings import (
    IDP_ISSUER, IDP_JWKS_URL, BROKER_AUDIENCE, PRIVILEGED_SCOPES, DEFAULT_DEVICE
)
from .storage import audit

def _pim_scope_entitlements(roles):
    scopes = set()
    roles = set(roles)
    if "Production-Admin" in roles:
        scopes.update({"deploy.prod", "gpu.quota.update"})
    if "Policy-Admin" in roles:
        scopes.update({"policy.admin", "agent.rotate_cert"})
    return scopes

def exchange_enterprise_token(
    external_access_token: str,
    requested_scopes: Iterable[str],
    *,
    audience=None,
    action_claims=None,
):
    # Imports the existing TokenSystem primitives so this layer remains an
    # extension of the current project instead of a replacement.
    from token_utils import (
        INTERNAL_API_AUD, TOKEN_SERVICE_AUD, DEVICE_CERT_PATH,
        cert_thumbprint_sha256_pem, cert_to_pem_string, issue_jwt, write_audit_event
    )

    requested = set(requested_scopes)
    claims = verify_jwt(
        external_access_token,
        issuer=IDP_ISSUER,
        audience=BROKER_AUDIENCE,
        jwks_url=IDP_JWKS_URL,
    )
    username = claims["sub"]
    user = get_user(username)
    device = get_device(claims.get("device_id"))
    if not user or user.get("status") != "active":
        raise PermissionError("user_not_active")

    ent = effective_entitlements(username)
    pim_roles = active_roles(username)
    base_allowed = set(ent["scopes"])
    active_pim_allowed = _pim_scope_entitlements(pim_roles)
    potential_pim_allowed = _pim_scope_entitlements(user.get("eligible_roles", []))

    # Distinguish an outright entitlement violation from an eligible role that
    # merely has not been activated yet. The latter should surface as a PIM
    # step-up decision rather than a generic scope denial.
    entitlement_ceiling = base_allowed | potential_pim_allowed
    if not requested.issubset(entitlement_ceiling):
        audit("broker_scope_denied", user=username, requested=sorted(requested), allowed=sorted(entitlement_ceiling), reason="scope_not_entitled")
        raise PermissionError("scope_not_entitled")

    decision = evaluate(
        user=user,
        device=device,
        requested_scopes=requested,
        mfa="mfa" in claims.get("amr", []),
        risk_level=claims.get("risk_level"),
    )
    if decision.decision != "allow":
        audit("broker_policy_denied", user=username, requested=sorted(requested), **decision.to_dict())
        raise PermissionError(decision.reason)

    allowed = base_allowed | active_pim_allowed
    if not requested.issubset(allowed):
        # Defensive consistency check: CA should already have required PIM.
        raise PermissionError("pim_activation_required")

    # The current TokenSystem PKI provides sender-constrained proof for the
    # managed lab workstation. Sensitive flows from unmanaged devices are
    # denied by Conditional Access before this point.
    cnf_x5t = None
    if claims.get("device_id") == DEFAULT_DEVICE and DEVICE_CERT_PATH.exists():
        cnf_x5t = cert_thumbprint_sha256_pem(cert_to_pem_string(DEVICE_CERT_PATH))
    if not cnf_x5t:
        raise PermissionError("sender_constrained_device_certificate_required")

    target_aud = audience or INTERNAL_API_AUD
    privileged = bool(requested & PRIVILEGED_SCOPES)
    extra = {
        "federated": True,
        "external_issuer": claims.get("iss"),
        "external_jti": claims.get("jti"),
        "tenant_id": claims.get("tid"),
        "preferred_username": claims.get("preferred_username"),
        "groups": claims.get("groups", []),
        "roles": sorted(set(ent["roles"]) | set(pim_roles)),
        "device_id": claims.get("device_id"),
        "device_trust_level": "trusted",
        "auth_strength": "step_up_mfa" if privileged else claims.get("auth_strength", "mfa"),
        "risk_level": claims.get("risk_level", "low"),
        "pim": privileged and bool(pim_roles),
        "pim_roles": pim_roles,
        "policy_id": decision.policy_id,
        "policy_version": "2026.08",
        "decision_id": f"dec-{uuid.uuid4()}",
        "decision": decision.decision,
        "reason": decision.reason,
    }
    if action_claims:
        extra.update(action_claims)

    token = issue_jwt(
        subject=username,
        audience=target_aud,
        client_id="enterprise-token-broker",
        scopes=requested,
        actor_type="user",
        cnf_x5t=cnf_x5t,
        extra_claims=extra,
    )
    audit("federated_internal_token_issued", user=username, audience=target_aud, scopes=sorted(requested), pim_roles=pim_roles)
    write_audit_event("federated_internal_token_issued", {
        "user": username,
        "audience": target_aud,
        "scopes": sorted(requested),
        "decision": "allow",
        "risk_level": claims.get("risk_level", "low"),
        "policy_id": decision.policy_id,
        "reason": decision.reason,
    })
    return token
