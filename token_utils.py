import base64
import hashlib
import json
import os
import time
import uuid
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key

ROOT = Path(__file__).resolve().parent
PKI_DIR = ROOT / "pki"
STATE_DIR = ROOT / ".state"
STATE_DIR.mkdir(exist_ok=True)

REGION = os.getenv("REGION", "local")
ISSUER_ID = os.getenv("ISSUER_ID", "issuer-local-01")
ISSUER_URL = os.getenv("ISSUER_URL", "http://localhost:8000")
JWKS_CACHE_TTL_SECONDS = int(os.getenv("JWKS_CACHE_TTL_SECONDS", "300"))
# Demo/testing only. Must never be enabled in production.
UNSAFE_DEV_MODE_CERT_HEADER = os.getenv("UNSAFE_DEV_MODE_CERT_HEADER", os.getenv("DEV_MODE_CERT_HEADER", "0")) == "1"
# Demo/testing only. Must never be enabled in production.
UNSAFE_ALLOW_LOCAL_SIGNING_CERT_FALLBACK = os.getenv("UNSAFE_ALLOW_LOCAL_SIGNING_CERT_FALLBACK", os.getenv("ALLOW_LOCAL_SIGNING_CERT_FALLBACK", "0")) == "1"
ALLOW_LOCAL_SIGNING_CERT_FALLBACK = UNSAFE_ALLOW_LOCAL_SIGNING_CERT_FALLBACK
ISSUER = ISSUER_URL
TOKEN_SERVICE_AUD = os.getenv("TOKEN_SERVICE_AUD", "token-service")
INTERNAL_API_AUD = os.getenv("INTERNAL_API_AUD", "internal-api")
ACCESS_TOKEN_TTL_SECONDS = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "600"))
STEP_UP_TOKEN_TTL_SECONDS = int(os.getenv("STEP_UP_TOKEN_TTL_SECONDS", "180"))
AGENT_TOKEN_TTL_SECONDS = int(os.getenv("AGENT_TOKEN_TTL_SECONDS", "300"))
REFRESH_TOKEN_TTL_SECONDS = int(os.getenv("REFRESH_TOKEN_TTL_SECONDS", str(8 * 60 * 60)))

SIGNING_KEY_PATH = PKI_DIR / "token-signing.key.pem"
SIGNING_CERT_PATH = PKI_DIR / "token-signing.cert.pem"
DEVICE_CERT_PATH = PKI_DIR / "linux-laptop-001.cert.pem"
DEVICE_KEY_PATH = PKI_DIR / "linux-laptop-001.key.pem"
AGENT_CERT_PATH = PKI_DIR / "agent-gpu-planner-dev.cert.pem"
AGENT_KEY_PATH = PKI_DIR / "agent-gpu-planner-dev.key.pem"

_JWKS_CACHE = {"expires_at": 0, "jwks": None}

def b64url(data: bytes) -> str: return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
def now() -> int: return int(time.time())
def load_private_key(path: Path): return load_pem_private_key(path.read_bytes(), password=None)
def cert_to_pem_string(path: Path) -> str: return path.read_text()
def encode_cert_header(cert_pem: str) -> str: return b64url(cert_pem.encode())
def decode_cert_header(header_value: str) -> str: return base64.urlsafe_b64decode((header_value + "=" * (-len(header_value) % 4)).encode()).decode()

def cert_thumbprint_sha256_pem(cert_pem: str | bytes) -> str:
    if isinstance(cert_pem, str): cert_pem = cert_pem.encode()
    cert = x509.load_pem_x509_certificate(cert_pem)
    return b64url(cert.fingerprint(hashes.SHA256()))

def jwks() -> Dict[str, Any]:
    cert = x509.load_pem_x509_certificate(SIGNING_CERT_PATH.read_bytes())
    nums = cert.public_key().public_numbers()
    return {"keys": [{"kty": "RSA", "use": "sig", "kid": "token-signing-rsa-1", "alg": "RS256", "n": b64url(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")), "e": b64url(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big"))}]}

def get_cached_jwks(jwks_uri: Optional[str]) -> Dict[str, Any]:
    if _JWKS_CACHE["jwks"] and _JWKS_CACHE["expires_at"] > now():
        return _JWKS_CACHE["jwks"]
    data = requests.get(jwks_uri, timeout=3).json() if jwks_uri else jwks()
    _JWKS_CACHE["jwks"] = data
    _JWKS_CACHE["expires_at"] = now() + JWKS_CACHE_TTL_SECONDS
    return data

def _verify_with_jwk(signing_input: bytes, signature: bytes, jwk: Dict[str, Any]):
    from cryptography.hazmat.primitives.asymmetric import rsa
    n = int.from_bytes(base64.urlsafe_b64decode(jwk["n"] + "=" * (-len(jwk["n"]) % 4)), "big")
    e = int.from_bytes(base64.urlsafe_b64decode(jwk["e"] + "=" * (-len(jwk["e"]) % 4)), "big")
    key = rsa.RSAPublicNumbers(e, n).public_key()
    key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())

def sign_jwt(claims: Dict[str, Any]) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": "token-signing-rsa-1"}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig = load_private_key(SIGNING_KEY_PATH).sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64url(sig)}"

def issue_jwt(*, subject: str, audience: str, client_id: str, scopes: Iterable[str], actor_type="user", ttl_seconds=ACCESS_TOKEN_TTL_SECONDS, extra_claims=None, cnf_x5t=None) -> str:
    claims = {"iss": ISSUER_URL, "sub": subject, "aud": audience, "iat": now(), "nbf": now() - 2, "exp": now() + ttl_seconds, "jti": str(uuid.uuid4()), "client_id": client_id, "scope": " ".join(sorted(set(scopes))), "actor_type": actor_type}
    if cnf_x5t: claims["cnf"] = {"x5t#S256": cnf_x5t}
    if extra_claims: claims.update(extra_claims)
    return sign_jwt(claims)

def decode_and_validate_jwt(token: str, audience: str, *, jwks_uri: Optional[str] = None) -> Dict[str, Any]:
    h_b64, p_b64, s_b64 = token.split(".")
    header = json.loads(base64.urlsafe_b64decode(h_b64 + "=" * (-len(h_b64) % 4)).decode())
    claims = json.loads(base64.urlsafe_b64decode(p_b64 + "=" * (-len(p_b64) % 4)).decode())
    signature = base64.urlsafe_b64decode(s_b64 + "=" * (-len(s_b64) % 4))
    signing_input = f"{h_b64}.{p_b64}".encode()

    kid = header.get("kid")
    try:
        keys = get_cached_jwks(jwks_uri).get("keys", [])
        key = next((k for k in keys if k.get("kid") == kid), None)
        if not key:
            raise ValueError("kid_not_found")
        _verify_with_jwk(signing_input, signature, key)
    except Exception as jwks_error:
        if not UNSAFE_ALLOW_LOCAL_SIGNING_CERT_FALLBACK:
            raise ValueError(f"jwks_validation_failed:{jwks_error}")
        cert = x509.load_pem_x509_certificate(SIGNING_CERT_PATH.read_bytes())
        cert.public_key().verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())

    if claims.get("iss") != ISSUER_URL: raise ValueError("Invalid issuer")
    aud = claims.get("aud")
    if not (audience in aud if isinstance(aud, list) else aud == audience): raise ValueError("Invalid audience")
    current_time = now()
    if int(claims.get("exp", 0)) < current_time: raise ValueError("Token expired")
    clock_skew_seconds = 60
    nbf = claims.get("nbf")
    if nbf is not None and current_time + clock_skew_seconds < int(nbf):
        raise ValueError("token not yet valid")
    return claims

def scopes_from_claims(claims: Dict[str, Any]) -> set[str]: return set(str(claims.get("scope", "")).split())


def _normalize_proof_path(path: str) -> str:
    p = (path or "/").split("?", 1)[0].strip()
    if not p.startswith("/"):
        p = f"/{p}"
    if len(p) > 1 and p.endswith("/"):
        p = p.rstrip("/")
    return p


def _proof_message(access_token: str, method: str, path: str) -> bytes:
    normalized_method = (method or "").upper().strip()
    normalized_path = _normalize_proof_path(path)
    return f"{normalized_method}\n{normalized_path}\n{hashlib.sha256(access_token.encode()).hexdigest()}".encode()
def has_scopes(claims: Dict[str, Any], required: Iterable[str]) -> bool: return set(required).issubset(scopes_from_claims(claims))

def sign_proof(private_key_path: Path, access_token: str, method: str, path: str) -> str:
    msg = _proof_message(access_token, method, path)
    sig = load_private_key(private_key_path).sign(msg, padding.PKCS1v15(), hashes.SHA256())
    return b64url(sig)

def verify_proof(cert_pem: str, signature_b64: str, access_token: str, method: str, path: str) -> bool:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    msg = _proof_message(access_token, method, path)
    sig = base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4))
    try: cert.public_key().verify(sig, msg, padding.PKCS1v15(), hashes.SHA256()); return True
    except Exception: return False

def validate_sender_constrained_proof(claims, cert_pem, signature_b64, access_token, method, path, dev_header_thumbprint=None):
    expected = (claims.get("cnf") or {}).get("x5t#S256")
    if not expected: raise ValueError("certificate_binding_failed")
    if cert_pem:
        actual = cert_thumbprint_sha256_pem(cert_pem)
    elif UNSAFE_DEV_MODE_CERT_HEADER and dev_header_thumbprint:
        actual = dev_header_thumbprint
    else:
        raise ValueError("certificate_binding_failed")
    if actual != expected: raise ValueError("certificate_binding_failed")
    if cert_pem and signature_b64 and not verify_proof(cert_pem, signature_b64, access_token, method, path):
        raise ValueError("certificate_binding_failed")

def json_load(path: Path, default: Any):
    if not path.exists(): return default
    try: return json.loads(path.read_text())
    except Exception: return default

def json_save(path: Path, data: Any): path.write_text(json.dumps(data, indent=2, sort_keys=True))
