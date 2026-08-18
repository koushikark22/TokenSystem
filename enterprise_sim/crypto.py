import base64
import json
from typing import Dict, Any

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .settings import IDP_PRIVATE_KEY_FILE, IDP_KID
from .storage import now

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

def ensure_idp_key():
    if IDP_PRIVATE_KEY_FILE.exists():
        return
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    IDP_PRIVATE_KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    IDP_PRIVATE_KEY_FILE.write_bytes(pem)

def _load_private_key():
    ensure_idp_key()
    return serialization.load_pem_private_key(IDP_PRIVATE_KEY_FILE.read_bytes(), password=None)

def jwks() -> Dict[str, Any]:
    key = _load_private_key()
    nums = key.public_key().public_numbers()
    return {
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "kid": IDP_KID,
            "alg": "RS256",
            "n": b64url(nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")),
            "e": b64url(nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")),
        }]
    }

def sign_jwt(claims: dict) -> str:
    header = {"alg": "RS256", "typ": "JWT", "kid": IDP_KID}
    h = b64url(json.dumps(header, separators=(",", ":")).encode())
    p = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{h}.{p}".encode()
    sig = _load_private_key().sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{b64url(sig)}"

def decode_unverified(token: str) -> dict:
    _, p, _ = token.split(".")
    return json.loads(b64decode(p).decode())

def _rsa_public_key(jwk: dict):
    n = int.from_bytes(b64decode(jwk["n"]), "big")
    e = int.from_bytes(b64decode(jwk["e"]), "big")
    return rsa.RSAPublicNumbers(e, n).public_key()

def verify_jwt(token: str, *, issuer: str, audience: str, jwks_url: str) -> dict:
    h_b64, p_b64, s_b64 = token.split(".")
    header = json.loads(b64decode(h_b64).decode())
    if header.get("alg") != "RS256":
        raise ValueError("unsupported_algorithm")
    data = requests.get(jwks_url, timeout=3).json()
    jwk = next((k for k in data.get("keys", []) if k.get("kid") == header.get("kid")), None)
    if not jwk:
        raise ValueError("kid_not_found")
    _rsa_public_key(jwk).verify(
        b64decode(s_b64),
        f"{h_b64}.{p_b64}".encode(),
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    claims = json.loads(b64decode(p_b64).decode())
    current = now()
    if claims.get("iss") != issuer:
        raise ValueError("invalid_issuer")
    aud = claims.get("aud")
    if not (audience in aud if isinstance(aud, list) else aud == audience):
        raise ValueError("invalid_audience")
    if int(claims.get("exp", 0)) < current:
        raise ValueError("token_expired")
    if int(claims.get("nbf", 0)) > current + 60:
        raise ValueError("token_not_yet_valid")
    return claims
