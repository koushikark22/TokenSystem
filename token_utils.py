import base64, hashlib, json, os, time, uuid
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.serialization import load_pem_private_key

ROOT = Path(__file__).resolve().parent
PKI_DIR = ROOT / "pki"
STATE_DIR = ROOT / ".state"
STATE_DIR.mkdir(exist_ok=True)

ISSUER = os.getenv("TOKEN_ISSUER", "http://localhost:8000")
TOKEN_SERVICE_AUD = os.getenv("TOKEN_SERVICE_AUD", "token-service")
INTERNAL_API_AUD = os.getenv("INTERNAL_API_AUD", "internal-api")
ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "600"))
STEP_UP_TOKEN_TTL_SECONDS = int(os.getenv("STEP_UP_TOKEN_TTL_SECONDS", "180"))
AGENT_TOKEN_TTL_SECONDS = int(os.getenv("AGENT_TOKEN_TTL_SECONDS", "300"))
REFRESH_TOKEN_TTL_SECONDS = int(os.getenv("REFRESH_TOKEN_TTL_SECONDS", str(8 * 60 * 60)))

SIGNING_KEY_PATH = PKI_DIR / "token-signing.key.pem"
SIGNING_CERT_PATH = PKI_DIR / "token-signing.cert.pem"
CA_CERT_PATH = PKI_DIR / "ca.cert.pem"
DEVICE_CERT_PATH = PKI_DIR / "linux-laptop-001.cert.pem"
DEVICE_KEY_PATH = PKI_DIR / "linux-laptop-001.key.pem"
AGENT_CERT_PATH = PKI_DIR / "agent-gpu-planner-dev.cert.pem"
AGENT_KEY_PATH = PKI_DIR / "agent-gpu-planner-dev.key.pem"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def now() -> int:
    return int(time.time())


def load_private_key(path: Path):
    return load_pem_private_key(path.read_bytes(), password=None)


def load_public_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def cert_thumbprint_sha256_pem(cert_pem: str | bytes) -> str:
    if isinstance(cert_pem, str):
        cert_pem = cert_pem.encode()
    cert = x509.load_pem_x509_certificate(cert_pem)
    return b64url(cert.fingerprint(hashes.SHA256()))


def cert_to_pem_string(path: Path) -> str:
    return path.read_text()


def rsa_public_jwk_from_cert(cert_path: Path, kid: str = "token-signing-rsa-1") -> Dict[str, str]:
    cert = load_public_cert(cert_path)
    pub = cert.public_key()
    if not isinstance(pub, rsa.RSAPublicKey):
        raise ValueError("Expected RSA public key")
    nums = pub.public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": kid,
        "alg": "RS256",
        "n": b64url(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
        "e": b64url(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")),
    }


def jwks() -> Dict[str, Any]:
    return {"keys": [rsa_public_jwk_from_cert(SIGNING_CERT_PATH)]}


def sign_jwt(claims: Dict[str, Any]) -> str:
    key = load_private_key(SIGNING_KEY_PATH)
    header = {"alg": "RS256", "typ": "JWT", "kid": "token-signing-rsa-1"}
    header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
    claims_b64 = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{claims_b64}"
    signature = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{b64url(signature)}"

def issue_jwt(
    *,
    subject: str,
    audience: str,
    client_id: str,
    scopes: Iterable[str],
    actor_type: str = "user",
    ttl_seconds: int = ACCESS_TOKEN_TTL_SECONDS,
    extra_claims: Optional[Dict[str, Any]] = None,
    cnf_x5t: Optional[str] = None,
) -> str:
    claims: Dict[str, Any] = {
        "iss": ISSUER,
        "sub": subject,
        "aud": audience,
        "iat": now(),
        "nbf": now() - 2,
        "exp": now() + ttl_seconds,
        "jti": str(uuid.uuid4()),
        "client_id": client_id,
        "scope": " ".join(sorted(set(scopes))),
        "actor_type": actor_type,
    }
    if cnf_x5t:
        claims["cnf"] = {"x5t#S256": cnf_x5t}
    if extra_claims:
        claims.update(extra_claims)
    return sign_jwt(claims)


def decode_and_validate_jwt(token: str, audience: str) -> Dict[str, Any]:
    if not token or token.count(".") != 2:
        raise ValueError("Invalid JWT format")
    header_b64, payload_b64, sig_b64 = token.split(".")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = base64.urlsafe_b64decode((sig_b64 + "=" * (-len(sig_b64) % 4)).encode())
    cert = load_public_cert(SIGNING_CERT_PATH)
    cert.public_key().verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    payload_bytes = base64.urlsafe_b64decode((payload_b64 + "=" * (-len(payload_b64) % 4)).encode())
    claims = json.loads(payload_bytes.decode())
    current = now()
    if claims.get("iss") != ISSUER:
        raise ValueError("Invalid issuer")
    aud = claims.get("aud")
    ok = audience in aud if isinstance(aud, list) else aud == audience
    if not ok:
        raise ValueError("Invalid audience")
    if int(claims.get("exp", 0)) < current:
        raise ValueError("Token expired")
    if int(claims.get("nbf", 0)) > current:
        raise ValueError("Token not yet valid")
    return claims

def scopes_from_claims(claims: Dict[str, Any]) -> set[str]:
    scope = claims.get("scope", "")
    if isinstance(scope, str):
        return set(s for s in scope.split() if s)
    if isinstance(scope, list):
        return set(scope)
    return set()


def has_scopes(claims: Dict[str, Any], required: Iterable[str]) -> bool:
    have = scopes_from_claims(claims)
    return set(required).issubset(have)


def sign_proof(private_key_path: Path, access_token: str, method: str, path: str) -> str:
    key = load_private_key(private_key_path)
    message = f"{method.upper()}\n{path}\n{hashlib.sha256(access_token.encode()).hexdigest()}".encode()
    signature = key.sign(message, padding.PKCS1v15(), hashes.SHA256())
    return b64url(signature)


def verify_proof(cert_pem: str, signature_b64: str, access_token: str, method: str, path: str) -> bool:
    cert = x509.load_pem_x509_certificate(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)
    message = f"{method.upper()}\n{path}\n{hashlib.sha256(access_token.encode()).hexdigest()}".encode()
    padded = signature_b64 + "=" * (-len(signature_b64) % 4)
    signature = base64.urlsafe_b64decode(padded.encode())
    try:
        cert.public_key().verify(signature, message, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def validate_sender_constrained_proof(claims: Dict[str, Any], cert_pem: str, signature_b64: str, access_token: str, method: str, path: str) -> None:
    expected = (claims.get("cnf") or {}).get("x5t#S256")
    if not expected:
        raise ValueError("Token is missing cnf.x5t#S256 sender constraint")
    actual = cert_thumbprint_sha256_pem(cert_pem)
    if actual != expected:
        raise ValueError("Certificate thumbprint does not match token cnf")
    if not verify_proof(cert_pem, signature_b64, access_token, method, path):
        raise ValueError("Invalid private-key proof signature")


def json_load(path: Path, default: Any):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def json_save(path: Path, data: Any):
    path.write_text(json.dumps(data, indent=2, sort_keys=True))
