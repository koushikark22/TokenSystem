import sys
from pathlib import Path
sys.path.append(str(Path(__file__).resolve().parents[1]))

from token_utils import issue_jwt, decode_and_validate_jwt, INTERNAL_API_AUD


def test_user_token_issuance():
    t = issue_jwt(subject="developer01", audience=INTERNAL_API_AUD, client_id="x", scopes=["build.read"], cnf_x5t="tp")
    c = decode_and_validate_jwt(t, INTERNAL_API_AUD)
    assert c["sub"] == "developer01"


def test_stepup_scope_required():
    t = issue_jwt(subject="developer01", audience=INTERNAL_API_AUD, client_id="x", scopes=["gpu.quota.update"], extra_claims={"auth_strength":"step_up_mfa","pim":True,"approval_id":"APR-1"}, cnf_x5t="tp")
    c = decode_and_validate_jwt(t, INTERNAL_API_AUD)
    assert "gpu.quota.update" in c["scope"]


def test_agent_token_claims():
    t = issue_jwt(subject="agent:a", audience=INTERNAL_API_AUD, client_id="x", scopes=["gpu.job.submit"], actor_type="agent", extra_claims={"agent_id":"a","initiating_user":"developer01"}, cnf_x5t="tp")
    c = decode_and_validate_jwt(t, INTERNAL_API_AUD)
    assert c["agent_id"] == "a" and c["initiating_user"] == "developer01"
