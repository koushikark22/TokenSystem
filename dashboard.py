import base64
import html
import json
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

TOKEN_SERVICE_URL = "http://127.0.0.1:8000"
INTERNAL_API_URL = "http://127.0.0.1:9000"
STATE_DIR = Path(".state")

DEVICE_ID = "linux-laptop-001"
USER_ID = "developer01"
AGENT_ID = "agent-gpu-planner-dev"


def load_json(path: Path, default):
    try:
        if path.exists():
            return json.loads(path.read_text())
    except Exception:
        pass
    return default


def health(url: str):
    try:
        r = requests.get(f"{url}/health", timeout=2)
        return r.ok, r.json() if r.headers.get("content-type", "").startswith("application/json") else {}
    except Exception as e:
        return False, {"error": str(e)}


def decode_jwt_payload(token: str):
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        padding = "=" * ((4 - len(payload) % 4) % 4)
        decoded = base64.urlsafe_b64decode(payload + padding)
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def display_value(value):
    if value is None:
        return ""
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def badge(value: str):
    raw_text = str(value or "unknown")
    safe_text = html.escape(raw_text)
    low = raw_text.lower()
    if any(k in low for k in ["ok", "active", "allow", "allowed", "healthy", "green"]):
        color = "#2e7d32"
    elif any(k in low for k in ["step_up", "step-up", "pending", "mfa"]):
        color = "#f9a825"
    else:
        color = "#c62828"
    return f"<span style='background:{color};color:white;padding:4px 9px;border-radius:12px;font-size:0.8rem'>{safe_text}</span>"


st.set_page_config(page_title="Centralized Token Service Demo", layout="wide")

st.title("Centralized Token Service Demo")
st.caption("Zero Trust | Entra ID | Linux CLI | NHI Agent Identity | GPU Governance")

# Local state
cli_tokens = load_json(STATE_DIR / "devctl_tokens.json", {})
audit_state = load_json(STATE_DIR / "audit.json", [])
agents_state = load_json(STATE_DIR / "agents.json", {})
device_registry = load_json(Path("device_registry.json"), {})

# Live health
ts_ok, ts_health = health(TOKEN_SERVICE_URL)
api_ok, api_health = health(INTERNAL_API_URL)

gpu_status = "unknown"
if agents_state.get(AGENT_ID):
    gpu_status = f"agent_quota={agents_state[AGENT_ID].get('gpu_quota_max_jobs', 'n/a')}"

c1, c2, c3, c4, c5, c6 = st.columns(6)
c1.metric("Token Service", "Healthy" if ts_ok else "Error")
c1.markdown(badge("healthy" if ts_ok else "error"), unsafe_allow_html=True)
c2.metric("Internal API", "Healthy" if api_ok else "Error")
c2.markdown(badge("healthy" if api_ok else "error"), unsafe_allow_html=True)
c3.metric("Device ID", DEVICE_ID)
c3.markdown(badge("active"), unsafe_allow_html=True)
c4.metric("User", USER_ID)
c4.markdown(badge("active"), unsafe_allow_html=True)
c5.metric("Agent", AGENT_ID)
c5.markdown(badge(agents_state.get(AGENT_ID, {}).get("status", "unknown")), unsafe_allow_html=True)
c6.metric("GPU quota/status", gpu_status)
c6.markdown(badge("allowed" if "quota" in gpu_status else "unknown"), unsafe_allow_html=True)

st.markdown("---")
st.subheader("Architecture Flow")
st.markdown(
    "Linux CLI → Entra ID → Central Token Service → Device Registry / PKI / Policy Engine → Internal API / GPU Platform → Audit / SIEM"
)

with st.sidebar:
    st.header("Actions")
    st.caption("Demo placeholders only — run the CLI commands from the Demo Script section to execute actions.")
    st.button("Bootstrap Device Registry")
    st.button("Login")
    st.button("GPU Quota Update")
    st.button("Register Agent")
    st.button("Agent Comment")
    st.button("Agent GPU Submit")
    if st.button("Refresh Audit"):
        audit_state = load_json(STATE_DIR / "audit.json", [])
        st.success("Audit state refreshed")


overview_tab, trust_tab, claims_tab, agent_tab, gpu_tab, audit_tab = st.tabs(
    ["Overview", "Device Trust", "Token Claims", "Agent Identity / NHI", "GPU Jobs", "Audit Timeline"]
)

with overview_tab:
    st.write("Service health responses:")
    st.json({"token_service": ts_health, "internal_api": api_health})
    st.subheader("Demo Script")
    st.code("""python token_service.py
python internal_api.py
streamlit run dashboard.py""")

with trust_tab:
    st.write("Device Registry Snapshot")
    st.json(device_registry)

with claims_tab:
    token = cli_tokens.get("access_token", "")
    if token:
        claims = decode_jwt_payload(token)
        selected = {
            "sub": claims.get("sub"),
            "actor_type": claims.get("actor_type"),
            "device_id": claims.get("device_id"),
            "agent_id": claims.get("agent_id"),
            "initiating_user": claims.get("initiating_user"),
            "scope": claims.get("scope"),
            "aud": claims.get("aud"),
            "cnf": claims.get("cnf"),
            "auth_strength": claims.get("auth_strength"),
            "pim": claims.get("pim"),
            "approval_id": claims.get("approval_id"),
        }
        st.json(selected)
        st.markdown(badge(claims.get("auth_strength", "unknown")), unsafe_allow_html=True)
    else:
        st.info("No .state/devctl_tokens.json access_token found yet.")

with agent_tab:
    st.write("Agent Registry")
    if agents_state:
        rows = []
        for _, item in agents_state.items():
            rows.append(
                {
                    "agent_id": item.get("agent_id"),
                    "status": item.get("status"),
                    "agent_owner": item.get("agent_owner"),
                    "environment": item.get("environment"),
                    "allowed_scopes": ", ".join(item.get("allowed_scopes", [])),
                    "gpu_quota_max_jobs": item.get("gpu_quota_max_jobs"),
                }
            )
        st.dataframe(pd.DataFrame(rows), use_container_width=True)
    else:
        st.info("No .state/agents.json data found.")

with gpu_tab:
    st.write("GPU Governance Overview")
    st.markdown("- User and agent quotas are enforced by Internal API quota manager.")
    st.markdown(badge("allowed"), unsafe_allow_html=True)

with audit_tab:
    if not audit_state:
        st.info("No .state/audit.json data found.")
    else:
        rows = []
        for e in audit_state:
            rows.append(
                {
                    "timestamp": display_value(e.get("timestamp") or e.get("ts")),
                    "event_type": display_value(e.get("event_type") or e.get("event")),
                    "actor_type": display_value(e.get("actor_type")),
                    "user": display_value(e.get("user") or e.get("sub")),
                    "agent_id": display_value(e.get("agent_id")),
                    "scope/scopes": display_value(e.get("scope") or e.get("scopes")),
                    "decision": display_value(e.get("decision")),
                    "reason": display_value(e.get("reason")),
                    "correlation_id": display_value(e.get("correlation_id")),
                }
            )
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True)
