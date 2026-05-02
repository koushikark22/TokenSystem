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
        color = "#15803d"
        bg = "#dcfce7"
    elif any(k in low for k in ["step_up", "step-up", "pending", "mfa"]):
        color = "#92400e"
        bg = "#fef3c7"
    else:
        color = "#991b1b"
        bg = "#fee2e2"
    return f"<span style='background:{bg}; color:{color}; padding:4px 10px; border-radius:999px; font-weight:700; font-size:0.78rem'>{safe_text}</span>"


def render_claim_summary(claims: dict):
    rows = [
        {"Claim": "sub", "What to explain": "Subject / human identity", "Value": display_value(claims.get("sub"))},
        {"Claim": "actor_type", "What to explain": "Whether caller is user or agent", "Value": display_value(claims.get("actor_type"))},
        {"Claim": "device_id", "What to explain": "Linux endpoint/device context", "Value": display_value(claims.get("device_id"))},
        {"Claim": "agent_id", "What to explain": "Non-human identity", "Value": display_value(claims.get("agent_id"))},
        {"Claim": "scope", "What to explain": "Least-privilege permission", "Value": display_value(claims.get("scope"))},
        {"Claim": "aud", "What to explain": "Target API/resource", "Value": display_value(claims.get("aud"))},
        {"Claim": "cnf", "What to explain": "Certificate-bound proof", "Value": display_value(claims.get("cnf"))},
        {"Claim": "auth_strength", "What to explain": "MFA / stronger auth context", "Value": display_value(claims.get("auth_strength"))},
        {"Claim": "pim", "What to explain": "Privileged activation", "Value": display_value(claims.get("pim"))},
        {"Claim": "approval_id", "What to explain": "Step-up approval evidence", "Value": display_value(claims.get("approval_id"))},
    ]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


st.set_page_config(page_title="Centralized Token Service Demo", page_icon="🔐", layout="wide")

st.markdown(
    """
    <style>
        .block-container {padding-top: 1.4rem; max-width: 1380px;}
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        .top-box {
            border: 1px solid #e5e7eb;
            border-radius: 14px;
            padding: 18px 22px;
            background: #ffffff;
            box-shadow: 0 4px 14px rgba(15, 23, 42, 0.05);
            margin-bottom: 16px;
        }
        .eyebrow {color:#16a34a; font-weight:700; font-size:0.82rem; letter-spacing:0.06em; text-transform:uppercase; margin-bottom:4px;}
        .main-title {font-size:2rem; font-weight:760; color:#111827; margin-bottom:4px;}
        .subtitle {font-size:0.98rem; color:#4b5563; line-height:1.45; max-width:1050px;}
        .mini-card {
            border:1px solid #e5e7eb;
            border-radius:12px;
            padding:14px 14px 12px 14px;
            background:#ffffff;
            min-height:118px;
        }
        .mini-label {font-size:0.78rem; color:#6b7280; font-weight:700; text-transform:uppercase; letter-spacing:0.04em;}
        .mini-value {font-size:1.25rem; font-weight:740; color:#111827; margin:6px 0 8px 0; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
        .flow-row {
            border:1px solid #e5e7eb;
            border-radius:12px;
            padding:14px 16px;
            background:#f9fafb;
            font-size:0.96rem;
            line-height:1.6;
        }
        .explain-box {
            border-left:4px solid #16a34a;
            padding:10px 14px;
            background:#f0fdf4;
            border-radius:10px;
            color:#14532d;
            margin-bottom:14px;
        }
        div[data-testid="stButton"] > button {width:100%; border-radius:10px;}
    </style>
    """,
    unsafe_allow_html=True,
)

# Local state
cli_tokens = load_json(STATE_DIR / "devctl_tokens.json", {})
audit_state = load_json(STATE_DIR / "audit.json", [])
agents_state = load_json(STATE_DIR / "agents.json", {})
device_registry = load_json(Path("device_registry.json"), {})

# Live health
ts_ok, ts_health = health(TOKEN_SERVICE_URL)
api_ok, api_health = health(INTERNAL_API_URL)

agent_record = agents_state.get(AGENT_ID, {})
gpu_status = "unknown"
if agent_record:
    gpu_status = f"quota={agent_record.get('gpu_quota_max_jobs', 'n/a')}"

st.markdown(
    """
    <div class='top-box'>
        <div class='eyebrow'>Enterprise IAM + GPU Governance Prototype</div>
        <div class='main-title'>Centralized Token Service Demo</div>
        <div class='subtitle'>A Linux developer and agentic-AI access-control demo showing short-lived JWTs, OBO delegation, sender-constrained proof, step-up, non-human identity, GPU authorization, and auditability.</div>
    </div>
    """,
    unsafe_allow_html=True,
)

cols = st.columns(6)
status_items = [
    ("Token Service", "Healthy" if ts_ok else "Error", "healthy" if ts_ok else "error"),
    ("Internal API", "Healthy" if api_ok else "Error", "healthy" if api_ok else "error"),
    ("Device", DEVICE_ID, "active"),
    ("User", USER_ID, "active"),
    ("Agent", AGENT_ID, agent_record.get("status", "unknown")),
    ("GPU", gpu_status, "allowed" if "quota" in gpu_status else "unknown"),
]
for col, (label, value, status) in zip(cols, status_items):
    with col:
        st.markdown(
            f"""
            <div class='mini-card'>
                <div class='mini-label'>{html.escape(label)}</div>
                <div class='mini-value' title='{html.escape(str(value))}'>{html.escape(str(value))}</div>
                {badge(status)}
            </div>
            """,
            unsafe_allow_html=True,
        )

st.markdown("### Architecture Flow")
st.markdown(
    """
    <div class='flow-row'>
    <b>Linux CLI</b> → <b>Entra ID / IdP</b> → <b>Central Token Service</b> → <b>Device Registry + PKI Proof + Policy</b> → <b>Internal API / GPU Platform</b> → <b>Audit / SIEM</b>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.header("Demo Guide")
    st.caption("Run commands in the terminal. The dashboard is for visualization and interview explanation.")
    st.divider()
    st.button("Bootstrap Device Registry", disabled=True)
    st.button("Login", disabled=True)
    st.button("GPU Quota Update", disabled=True)
    st.button("Register Agent", disabled=True)
    st.button("Agent Comment", disabled=True)
    st.button("Agent GPU Submit", disabled=True)
    if st.button("Refresh Audit"):
        audit_state = load_json(STATE_DIR / "audit.json", [])
        st.success("Audit refreshed")
    st.divider()
    st.markdown("**Best panel flow:**")
    st.caption("Overview → Token Claims → Agent Identity / NHI → Audit Timeline")


overview_tab, trust_tab, claims_tab, agent_tab, gpu_tab, audit_tab = st.tabs(
    ["Overview", "Device Trust", "Token Claims", "Agent Identity / NHI", "GPU Jobs", "Audit Timeline"]
)

with overview_tab:
    st.markdown(
        """
        <div class='explain-box'>
        <b>Panel explanation:</b> The dashboard is the visualization layer. The security controls are enforced by the token service, CLI, internal API, certificate proof, scopes, and audit flow.
        </div>
        """,
        unsafe_allow_html=True,
    )
    left, right = st.columns([1.05, 1])
    with left:
        st.subheader("What this demo proves")
        st.markdown(
            """
            - Centralized token issuance for Linux developer tooling.
            - OBO token exchange for downstream internal APIs.
            - Explicit agent / non-human identity instead of anonymous automation.
            - GPU access controlled by scopes and quota context.
            - Audit trail for token, step-up, agent, and GPU activity.
            """
        )
        with st.expander("Service health JSON"):
            st.json({"token_service": ts_health, "internal_api": api_health})
    with right:
        st.subheader("Demo commands")
        st.code(
            """python token_service.py
python internal_api.py
python devctl.py login --auto
python devctl.py obo-build
python devctl.py gpu-submit
python devctl.py register-agent
python devctl.py agent-gpu-submit
python devctl.py audit
streamlit run dashboard.py""",
            language="bash",
        )

with trust_tab:
    st.subheader("Device Trust Snapshot")
    st.caption("Local demo device registry. In production this maps to enterprise device identity, managed certificates, or workload identity.")
    st.json(device_registry)

with claims_tab:
    st.subheader("Decoded Token Claims")
    token = cli_tokens.get("access_token", "")
    if token:
        claims = decode_jwt_payload(token)
        render_claim_summary(claims)
        with st.expander("Raw selected claims"):
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
    else:
        st.info("No access token found. Run `python devctl.py login --auto` first.")

with agent_tab:
    st.subheader("Agent / Non-Human Identity Registry")
    st.caption("Shows how the demo avoids anonymous automation by giving each agent an ID, owner, environment, scopes, and GPU quota.")
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
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No agent registry data found. Run `python devctl.py register-agent` first.")

with gpu_tab:
    st.subheader("GPU Governance Overview")
    st.markdown(
        """
        - GPU job submission requires scoped authorization.
        - Privileged quota updates require step-up authorization.
        - Agent GPU access is bounded by agent identity and quota.
        - Production design should connect this control layer to Kubernetes, Run:ai, NVIDIA GPU Operator, admission control, and GPU-hours reconciliation.
        """
    )
    st.markdown(badge("allowed"), unsafe_allow_html=True)

with audit_tab:
    st.subheader("Audit Timeline")
    st.caption("Trace login, token issuance, OBO, refresh, step-up, agent registration, and GPU actions.")
    if not audit_state:
        st.info("No audit data found. Run `python devctl.py audit` after demo commands.")
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
        st.dataframe(df, use_container_width=True, hide_index=True)
