import os
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import token_utils
from internal_api import posture_allowed_for_action
from device_registry import bootstrap_device_registry, check_device_posture
from policy_engine import evaluate_policy


def _write_cert_key(cert_path, key_path, name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()-datetime.timedelta(days=1)).not_valid_after(datetime.datetime.utcnow()+datetime.timedelta(days=30)).sign(key, hashes.SHA256())
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def setup_module():
    pki = Path("pki"); pki.mkdir(exist_ok=True)
    _write_cert_key(pki / "token-signing.cert.pem", pki / "token-signing.key.pem", "token")
    _write_cert_key(pki / "linux-laptop-001.cert.pem", pki / "linux-laptop-001.key.pem", "device")
    _write_cert_key(pki / "agent-gpu-planner-dev.cert.pem", pki / "agent-gpu-planner-dev.key.pem", "agent")


def test_jwks_validation_succeeds():
    token = token_utils.issue_jwt(subject="developer01", audience=token_utils.INTERNAL_API_AUD, client_id="c1", scopes=["build.read"], cnf_x5t="abc")
    claims = token_utils.decode_and_validate_jwt(token, token_utils.INTERNAL_API_AUD)
    assert claims["sub"] == "developer01"


def test_jwks_missing_kid_fails_without_fallback(monkeypatch):
    token = token_utils.issue_jwt(subject="developer01", audience=token_utils.INTERNAL_API_AUD, client_id="c1", scopes=["build.read"], cnf_x5t="abc")
    monkeypatch.setattr(token_utils, "ALLOW_LOCAL_SIGNING_CERT_FALLBACK", False)
    monkeypatch.setattr(token_utils, "get_cached_jwks", lambda uri: {"keys": []})
    try:
        token_utils.decode_and_validate_jwt(token, token_utils.INTERNAL_API_AUD)
        assert False
    except Exception as e:
        assert "jwks_validation_failed" in str(e)


def test_stolen_jwt_wrong_cert_fails():
    cert = token_utils.cert_to_pem_string(token_utils.DEVICE_CERT_PATH)
    thumb = token_utils.cert_thumbprint_sha256_pem(cert)
    token = token_utils.issue_jwt(subject="developer01", audience=token_utils.INTERNAL_API_AUD, client_id="c1", scopes=["gpu.job.submit"], cnf_x5t=thumb)
    try:
        token_utils.validate_sender_constrained_proof({"cnf": {"x5t#S256": thumb}}, "", None, token, "POST", "/gpu/jobs/submit", dev_header_thumbprint="bad")
        assert False
    except Exception as e:
        assert "certificate_binding_failed" in str(e)


def test_device_posture_checks():
    info = bootstrap_device_registry()
    assert check_device_posture("linux-laptop-001", info["cert_thumbprint"]) == (True, "allowed")
    assert check_device_posture("linux-laptop-001", "wrong")[1] == "certificate_binding_failed"


def test_gpu_quota_update_policy_requires_stepup_pim_approval():
    ok, _ = evaluate_policy("gpu.quota.update", {"actor_type": "user", "step_up_mfa": True, "pim": True, "approval_id": "APR-1", "device_managed": True, "cert_bound": True})
    assert ok
    ok2, _ = evaluate_policy("gpu.quota.update", {"actor_type": "user", "step_up_mfa": False, "pim": True, "approval_id": "APR-1", "device_managed": True, "cert_bound": True})
    assert not ok2


def test_deploy_prod_policy_fails_if_device_not_managed():
    ok, reason = evaluate_policy("deploy.prod", {"actor_type": "user", "step_up_mfa": True, "pim": True, "approval_id": "APR-1", "device_managed": False, "cert_bound": True})
    assert not ok and reason == "device_not_managed"


def test_agent_token_claims_include_actor_fields():
    token = token_utils.issue_jwt(subject="agent:agent-gpu-planner-dev", audience=token_utils.INTERNAL_API_AUD, client_id="agent-runtime", scopes=["pr.comment"], actor_type="agent", cnf_x5t="thumb", extra_claims={"agent_id": "agent-gpu-planner-dev", "initiating_user": "developer01"})
    claims = token_utils.decode_and_validate_jwt(token, token_utils.INTERNAL_API_AUD)
    assert claims["agent_id"] == "agent-gpu-planner-dev" and claims["initiating_user"] == "developer01"


def test_agent_no_device_context_allowed_for_comment_and_gpu_submit():
    claims = {
        "actor_type": "agent",
        "agent_id": "agent-gpu-planner-dev",
        "initiating_user": "developer01",
        "security_context": {"device_posture_reason": "no_device_context", "cert_bound": True},
    }
    assert posture_allowed_for_action(claims, "agent.comment")[0]
    assert posture_allowed_for_action(claims, "gpu.job.submit")[0]


def test_user_without_valid_posture_denied_sensitive_actions():
    claims = {"actor_type": "user", "security_context": {"device_posture_reason": "device_not_managed", "cert_bound": True}}
    assert not posture_allowed_for_action(claims, "gpu.job.submit")[0]
    assert not posture_allowed_for_action(claims, "gpu.quota.update")[0]
    assert not posture_allowed_for_action(claims, "deploy.prod")[0]


def test_deploy_prod_requires_allowed_posture():
    claims = {"actor_type": "user", "security_context": {"device_posture_reason": "allowed", "cert_bound": True}}
    assert posture_allowed_for_action(claims, "deploy.prod")[0]




def test_bootstrap_device_registry_repairs_stale_thumbprint_for_gpu_submit_scope():
    from device_registry import DEVICE_REGISTRY_PATH

    # Seed stale registry state that should fail posture checks.
    stale = {
        "devices": [{
            "device_id": "linux-laptop-001",
            "owner": "developer01",
            "os": "linux",
            "managed": True,
            "edr_healthy": True,
            "disk_encrypted": True,
            "cert_thumbprint": "stale-thumbprint",
            "risk": "low",
            "status": "active",
        }]
    }
    token_utils.json_save(DEVICE_REGISTRY_PATH, stale)

    current_thumb = token_utils.cert_thumbprint_sha256_pem(token_utils.cert_to_pem_string(token_utils.DEVICE_CERT_PATH))
    assert check_device_posture("linux-laptop-001", current_thumb)[0] is False

    bootstrap_device_registry()
    assert check_device_posture("linux-laptop-001", current_thumb) == (True, "allowed")
def test_route_wiring_uses_correct_action_names():
    text = Path("internal_api.py").read_text()
    assert 'posture_allowed_for_action(c, "gpu.job.submit")' in text
    assert 'posture_allowed_for_action(c, "gpu.quota.update")' in text
    assert 'posture_allowed_for_action(c, "agent.comment")' in text


def test_refresh_rotation_allows_chain_and_reuse_revokes_family(monkeypatch, tmp_path):
    import token_service

    refresh_db = tmp_path / "refresh_tokens.json"
    audit_db = tmp_path / "audit.json"
    monkeypatch.setattr(token_service, "REFRESH_DB", refresh_db)
    monkeypatch.setattr(token_service, "AUDIT_DB", audit_db)
    monkeypatch.setattr(token_utils, "verify_proof", lambda *args, **kwargs: True)

    cert_pem = token_utils.cert_to_pem_string(token_utils.DEVICE_CERT_PATH)
    thumb = token_utils.cert_thumbprint_sha256_pem(cert_pem)

    rt1 = token_service.new_refresh_record("developer01", "linux-devctl", ["build.read"], thumb)

    handler = token_service.Handler.__new__(token_service.Handler)
    captured = {}
    handler.send_json = lambda data, status=200: captured.update({"data": data, "status": status}) or captured

    resp1 = token_service.Handler.token_refresh(handler, {
        "refresh_token": rt1,
        "device_cert_pem": cert_pem,
        "proof_signature": "sig"
    })
    assert resp1["status"] == 200
    rt2 = resp1["data"]["refresh_token"]

    resp2 = token_service.Handler.token_refresh(handler, {
        "refresh_token": rt2,
        "device_cert_pem": cert_pem,
        "proof_signature": "sig"
    })
    assert resp2["status"] == 200

    reuse = token_service.Handler.token_refresh(handler, {
        "refresh_token": rt1,
        "device_cert_pem": cert_pem,
        "proof_signature": "sig"
    })
    assert reuse["status"] == 401
    assert "reuse detected" in reuse["data"]["error"]

    records = token_service.db(refresh_db, {})
    assert records[rt1]["used"] is True
    family_id = records[rt1]["family_id"]
    assert records[rt1]["revoked"] is True
    assert records[rt2]["family_id"] == family_id
    assert records[rt2]["revoked"] is True

def test_token_service_agent_routes_and_rotate(tmp_path, monkeypatch):
    import token_service
    monkeypatch.setattr(token_service, "AGENT_DB", tmp_path / "agents.json")
    monkeypatch.setattr(token_service, "AUDIT_DB", tmp_path / "audit.json")
    token_service.save(token_service.AGENT_DB, {"agent-gpu-planner-dev": {"agent_id":"agent-gpu-planner-dev", "cert_thumbprint":"x", "status":"active"}})
    h = token_service.Handler.__new__(token_service.Handler)
    captured = {}
    h.send_json = lambda data, status=200: captured.update({"data":data, "status":status}) or captured
    token_service.Handler.agent_rotate_cert(h, {"agent_id":"agent-gpu-planner-dev"})
    assert captured["status"] == 200


def test_cli_register_agent_supports_agent_id_flag():
    text = Path("devctl.py").read_text()
    assert 'register-agent' in text and '--agent-id' in text


def test_cli_commands_present():
    text = Path("devctl.py").read_text()
    for cmd in ["users", "register-user", "devices", "register-device", "disable-device", "enable-device", "agents", "agent-status", "rotate-agent-cert", "demo-full", "demo-enterprise"]:
        assert f'add_parser("{cmd}")' in text

def test_cli_deploy_and_quota_commands_present():
    text = Path("devctl.py").read_text()
    assert 'add_parser("deploy-prod")' in text
    assert 'add_parser("gpu-quota-update")' in text


def test_demo_functions_execute_real_steps_not_noop():
    text = Path("devctl.py").read_text()
    assert 'def demo_full(args):' in text and 'login(argparse.Namespace(auto=True))' in text and '_audit("demo_full_completed")' in text
    assert 'def demo_enterprise(args):' in text and 'register_device_cmd' in text and '_audit("demo_enterprise_completed")' in text
