import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

import token_utils
from device_registry import bootstrap_device_registry, check_device_posture


def _write_cert_key(cert_path, key_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "demo")])
    cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()-datetime.timedelta(days=1)).not_valid_after(datetime.datetime.utcnow()+datetime.timedelta(days=30)).sign(key, hashes.SHA256())
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def setup_module():
    pki = Path("pki"); pki.mkdir(exist_ok=True)
    _write_cert_key(pki / "token-signing.cert.pem", pki / "token-signing.key.pem")
    _write_cert_key(pki / "linux-laptop-001.cert.pem", pki / "linux-laptop-001.key.pem")
    _write_cert_key(pki / "agent-gpu-planner-dev.cert.pem", pki / "agent-gpu-planner-dev.key.pem")


def test_jwks_validation():
    token = token_utils.issue_jwt(subject="developer01", audience=token_utils.INTERNAL_API_AUD, client_id="c1", scopes=["build.read"], cnf_x5t="abc")
    claims = token_utils.decode_and_validate_jwt(token, token_utils.INTERNAL_API_AUD)
    assert claims["sub"] == "developer01"


def test_device_posture_checks():
    info = bootstrap_device_registry()
    ok, reason = check_device_posture("linux-laptop-001", info["cert_thumbprint"])
    assert ok and reason == "allowed"
    ok2, reason2 = check_device_posture("linux-laptop-001", "wrong")
    assert (not ok2) and reason2 == "certificate_binding_failed"
