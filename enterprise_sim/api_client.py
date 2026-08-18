import requests

def call_internal_api(token: str, method: str, path: str, *, json_body=None):
    from token_utils import DEVICE_CERT_PATH, DEVICE_KEY_PATH, cert_to_pem_string, encode_cert_header, sign_proof

    cert_pem = cert_to_pem_string(DEVICE_CERT_PATH)
    headers = {
        "Authorization": f"Bearer {token}",
        "X-Client-Cert": encode_cert_header(cert_pem),
        "X-Proof-Signature": sign_proof(DEVICE_KEY_PATH, token, method.upper(), path),
        "Content-Type": "application/json",
    }
    response = requests.request(
        method.upper(),
        f"http://127.0.0.1:8001{path}",
        headers=headers,
        json=json_body,
        timeout=5,
    )
    try:
        payload = response.json()
    except Exception:
        payload = {"text": response.text}
    return response.status_code, payload
