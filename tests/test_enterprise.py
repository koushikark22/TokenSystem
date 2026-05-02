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
