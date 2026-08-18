import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATE_ROOT = Path(os.getenv("ENTERPRISE_STATE_ROOT", str(ROOT / ".state" / "enterprise_sim")))
STATE_ROOT.mkdir(parents=True, exist_ok=True)

IDP_HOST = "127.0.0.1"
IDP_PORT = 8100
IDP_ISSUER = f"http://{IDP_HOST}:{IDP_PORT}"
IDP_JWKS_URL = f"{IDP_ISSUER}/jwks.json"
BROKER_AUDIENCE = "enterprise-token-broker"

PORTAL_HOST = "127.0.0.1"
PORTAL_PORT = 8200
PORTAL_BASE = f"http://{PORTAL_HOST}:{PORTAL_PORT}"
PORTAL_REDIRECT_URI = f"{PORTAL_BASE}/callback"
PORTAL_CLIENT_ID = "enterprise-browser-client"
CLI_CLIENT_ID = "enterprise-cli-client"

DIRECTORY_FILE = STATE_ROOT / "directory.json"
PIM_FILE = STATE_ROOT / "pim.json"
SCIM_FILE = STATE_ROOT / "scim_targets.json"
AUTH_CODES_FILE = STATE_ROOT / "auth_codes.json"
DEVICE_CODES_FILE = STATE_ROOT / "device_codes.json"
PORTAL_SESSION_FILE = STATE_ROOT / "portal_sessions.json"
CLI_TOKEN_FILE = STATE_ROOT / "cli_tokens.json"
ENTERPRISE_AUDIT_FILE = STATE_ROOT / "enterprise_audit.jsonl"
ALERTS_FILE = STATE_ROOT / "alerts.json"

IDP_PRIVATE_KEY_FILE = STATE_ROOT / "idp-signing-key.pem"
IDP_KID = "sim-entra-rsa-1"
TENANT_ID = "simulated-nvidia-enterprise-tenant"

AUTH_CODE_TTL = 120
DEVICE_CODE_TTL = 600
ACCESS_TOKEN_TTL = 600

PRIVILEGED_SCOPES = {
    "deploy.prod",
    "gpu.quota.update",
    "policy.admin",
    "agent.rotate_cert",
}
GPU_SENSITIVE_SCOPES = {"gpu.job.submit"}

DEFAULT_USER = "developer01"
DEFAULT_PASSWORD = "LabPassword!1"
DEFAULT_OTP = "654321"
DEFAULT_DEVICE = "linux-laptop-001"
