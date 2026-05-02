import base64, hashlib, json, os, time, uuid
from pathlib import Path
from typing import Any, Dict, Iterable, Optional

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

ROOT = Path(__file__).resolve().parent
PKI_DIR = ROOT / "pki"
STATE_DIR = ROOT / ".state"
STATE_DIR.mkdir(exist_ok=True)

REGION = os.getenv("REGION", "local")
ISSUER_ID = os.getenv("ISSUER_ID", "issuer-local-01")
ISSUER_URL = os.getenv("ISSUER_URL", "http://localhost:8000")
JWKS_CACHE_TTL_SECONDS = int(os.getenv("JWKS_CACHE_TTL_SECONDS", "300"))
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
_jwks_cache = {"expires": 0, "jwks": None}

def b64url(data: bytes) -> str: return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")
def now() -> int: return int(time.time())
def load_private_key(path: Path): return load_pem_private_key(path.read_bytes(), password=None)
def load_public_cert(path: Path) -> x509.Certificate: return x509.load_pem_x509_certificate(path.read_bytes())

def cert_thumbprint_sha256_pem(cert_pem: str | bytes) -> str:
    if isinstance(cert_pem, str): cert_pem = cert_pem.encode()
    return b64url(x509.load_pem_x509_certificate(cert_pem).fingerprint(hashes.SHA256()))

def cert_to_pem_string(path: Path) -> str: return path.read_text()
def encode_cert_header(cert_pem: str) -> str: return b64url(cert_pem.encode("utf-8"))
def decode_cert_header(header_value: str) -> str: return base64.urlsafe_b64decode((header_value + "=" * (-len(header_value) % 4)).encode("ascii")).decode("utf-8")

def rsa_public_jwk_from_cert(cert_path: Path, kid: str = "token-signing-rsa-1") -> Dict[str, str]:
    pub = load_public_cert(cert_path).public_key()
    nums = pub.public_numbers()
    return {"kty":"RSA","use":"sig","kid":kid,"alg":"RS256","n":b64url(nums.n.to_bytes((nums.n.bit_length()+7)//8,"big")),"e":b64url(nums.e.to_bytes((nums.e.bit_length()+7)//8,"big"))}

def jwks() -> Dict[str, Any]: return {"keys": [rsa_public_jwk_from_cert(SIGNING_CERT_PATH)]}

def get_cached_jwks(jwks_uri: str | None = None) -> Dict[str, Any]:
    if _jwks_cache["jwks"] and _jwks_cache["expires"] > now():
        return _jwks_cache["jwks"]
    if jwks_uri:
        data = requests.get(jwks_uri, timeout=3).json()
    else:
        data = jwks()
    _jwks_cache["jwks"] = data
    _jwks_cache["expires"] = now() + JWKS_CACHE_TTL_SECONDS
    return data

def sign_jwt(claims: Dict[str, Any]) -> str:
    key = load_private_key(SIGNING_KEY_PATH)
    h = b64url(json.dumps({"alg":"RS256","typ":"JWT","kid":"token-signing-rsa-1"}, separators=(",",":")).encode())
    p = b64url(json.dumps(claims, separators=(",",":")).encode())
    si = f"{h}.{p}"
    sig = key.sign(si.encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{si}.{b64url(sig)}"

def issue_jwt(*, subject: str, audience: str, client_id: str, scopes: Iterable[str], actor_type: str = "user", ttl_seconds: int = ACCESS_TOKEN_TTL_SECONDS, extra_claims: Optional[Dict[str, Any]] = None, cnf_x5t: Optional[str] = None) -> str:
    claims = {"iss":ISSUER_URL,"sub":subject,"aud":audience,"iat":now(),"nbf":now()-2,"exp":now()+ttl_seconds,"jti":str(uuid.uuid4()),"client_id":client_id,"scope":" ".join(sorted(set(scopes))),"actor_type":actor_type}
    if cnf_x5t: claims["cnf"] = {"x5t#S256": cnf_x5t}
    if extra_claims: claims.update(extra_claims)
    return sign_jwt(claims)

def decode_and_validate_jwt(token: str, audience: str, *, jwks_uri: str | None = None) -> Dict[str, Any]:
    h,p,s = token.split(".")
    claims = json.loads(base64.urlsafe_b64decode((p + "=" * (-len(p)%4)).encode()).decode())
    sig = base64.urlsafe_b64decode((s + "=" * (-len(s)%4)).encode())
    # demo: use local signing cert; jwks cache call proves local validation path and cacheability
    get_cached_jwks(jwks_uri)
    load_public_cert(SIGNING_CERT_PATH).public_key().verify(sig, f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    if claims.get("iss") != ISSUER_URL: raise ValueError("Invalid issuer")
    aud = claims.get("aud"); ok = audience in aud if isinstance(aud, list) else aud == audience
    if not ok: raise ValueError("Invalid audience")
    if int(claims.get("exp",0)) < now(): raise ValueError("Token expired")
    return claims

def scopes_from_claims(claims):
    scope = claims.get("scope", "")
    return set(scope.split()) if isinstance(scope, str) else set(scope or [])
def has_scopes(claims, required): return set(required).issubset(scopes_from_claims(claims))

def sign_proof(private_key_path: Path, access_token: str, method: str, path: str) -> str:
    msg = f"{method.upper()}\n{path}\n{hashlib.sha256(access_token.encode()).hexdigest()}".encode()
    return b64url(load_private_key(private_key_path).sign(msg, padding.PKCS1v15(), hashes.SHA256()))

def verify_proof(cert_pem: str, signature_b64: str, access_token: str, method: str, path: str) -> bool:
    cert = x509.load_pem_x509_certificate(cert_pem.encode() if isinstance(cert_pem, str) else cert_pem)
    msg = f"{method.upper()}\n{path}\n{hashlib.sha256(access_token.encode()).hexdigest()}".encode()
    try: cert.public_key().verify(base64.urlsafe_b64decode((signature_b64 + "=" * (-len(signature_b64)%4)).encode()), msg, padding.PKCS1v15(), hashes.SHA256()); return True
    except Exception: return False

def validate_sender_constrained_proof(claims, cert_pem, signature_b64, access_token, method, path, presented_thumbprint: str | None = None):
    expected = (claims.get("cnf") or {}).get("x5t#S256")
    if not expected: raise ValueError("certificate_binding_failed")
    actual = presented_thumbprint or cert_thumbprint_sha256_pem(cert_pem)
    if actual != expected: raise ValueError("certificate_binding_failed")
    if cert_pem and signature_b64 and not verify_proof(cert_pem, signature_b64, access_token, method, path): raise ValueError("Invalid private-key proof signature")

def json_load(path: Path, default: Any):
    if not path.exists(): return default
    try: return json.loads(path.read_text())
    except Exception: return default

def json_save(path: Path, data: Any): path.write_text(json.dumps(data, indent=2, sort_keys=True))
