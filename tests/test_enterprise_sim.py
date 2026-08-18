import shutil
from pathlib import Path

import pytest

from enterprise_sim import directory
from enterprise_sim.conditional_access import evaluate
from enterprise_sim.pim import activate, active_roles, revoke
from enterprise_sim.scim import provision, deprovision
from enterprise_sim.settings import STATE_ROOT

@pytest.fixture(autouse=True)
def clean_state():
    if STATE_ROOT.exists():
        shutil.rmtree(STATE_ROOT)
    STATE_ROOT.mkdir(parents=True, exist_ok=True)
    directory.bootstrap_directory(force=True)
    yield

def test_standard_access_allowed():
    user = directory.get_user("developer01")
    device = directory.get_device("linux-laptop-001")
    d = evaluate(user=user, device=device, requested_scopes=["build.read"], mfa=True, risk_level="low")
    assert d.decision == "allow"

def test_sensitive_access_denied_on_unmanaged_device():
    user = directory.get_user("developer01")
    device = directory.get_device("personal-laptop-001")
    d = evaluate(user=user, device=device, requested_scopes=["gpu.job.submit"], mfa=True, risk_level="low")
    assert d.decision == "deny"
    assert d.reason == "managed_device_required"

def test_high_risk_denied():
    user = directory.get_user("developer01")
    device = directory.get_device("linux-laptop-001")
    d = evaluate(user=user, device=device, requested_scopes=["build.read"], mfa=True, risk_level="high")
    assert d.decision == "deny"

def test_prod_requires_pim_then_allows():
    user = directory.get_user("developer01")
    device = directory.get_device("linux-laptop-001")
    before = evaluate(user=user, device=device, requested_scopes=["deploy.prod"], mfa=True, risk_level="low")
    assert before.decision == "step_up"
    activate("developer01", "Production-Admin", mfa=True, device_id="linux-laptop-001", justification="pytest")
    assert "Production-Admin" in active_roles("developer01")
    after = evaluate(user=user, device=device, requested_scopes=["deploy.prod"], mfa=True, risk_level="low")
    assert after.decision == "allow"
    revoke("developer01", "Production-Admin")

def test_scim_joiner_leaver():
    rec = provision("developer01")
    assert rec["active"] is True
    out = deprovision("developer01")
    assert out["active"] is False

def test_hybrid_sync_propagates_status():
    directory.disable_user("developer01")
    assert directory.get_user("developer01")["status"] == "disabled"
    directory.enable_user("developer01")
    assert directory.get_user("developer01")["status"] == "active"
