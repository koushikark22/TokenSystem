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


def short_text(value: str, max_len: int = 22) -> str:
    text = str(value or "unknown")
    if len(text) <= max_len:
        return text
    return f"{text[: max_len - 3]}..."


def badge(value: str):
    raw_text = str(value or "unknown")
    safe_text = html.escape(raw_text)
    low = raw_text.lower()
    if any(k in low for k in ["ok", "active", "allow", "allowed", "healthy", "green"]):
        css_class = "badge badge-green"
    elif any(k in low for k in ["step_up", "step-up", "pending", "mfa"]):
        css_class = "badge badge-yellow"
    else:
        css_class = "badge badge-red"
    return f"<span class='{css_class}'>{safe_text}</span>"


def status_card(title: str, value: str, status: str, detail: str = ""):
    return f"""
    <div class='status-card'>
        <div class='status-title'>{html.escape(title)}</div>
        <div class='status-value' title='{html.escape(str(value))}'>{html.escape(short_text(value, 18))}</div>
        <div>{badge(status)}</div>
        <div class='status-detail'>{html.escape(detail)}</div>
    </div>
    """


def flow_step(label: str, detail: str):
    return f"""
    <div class='flow-step'>
        <div class='flow-label'>{html.escape(label)}</div>
        <div class='flow-detail'>{html.escape(detail)}</div>
    </div>
    """


def render_claim_summary(claims: dict):
    rows = [
        {"Claim": "sub", "Meaning": "Human or subject identity", "Value": display_value(claims.get("sub"))},
        {"Claim": "actor_type", "Meaning": "Human vs agent actor", "Value": display_value(claims.get("actor_type"))},
        {"Claim": "device_id", "Meaning": "Linux endpoint/device context", "Value": display_value(claims.get("device_id"))},
        {"Claim": "agent_id", "Meaning": "Non-human identity", "Value": display_value(claims.get("agent_id"))},
        {"Claim": "scope", "Meaning": "Least-privilege permission", "Value": display_value(claims.get("scope"))},
        {"Claim": "aud", "Meaning": "Target API/resource", "Value": display_value(claims.get("aud"))},
        {"Claim": "cnf", "Meaning": "Certificate-bound proof", "Value": display_value(claims.get("cnf"))},
        {"Claim": "auth_strength", "Meaning": "MFA/step-up strength", "Value": display_value(claims.get("auth_strength"))},
        {"Claim": "pim", "Meaning": "Privileged activation", "Value": display_value(claims.get("pim"))},
        {"Claim": "approval_id", "Meaning": "Step-up approval evidence", "Value": display_value(claims.get("approval_id"))},
    ]
    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


st.set_page_config(page_title="Centralized Token Service Demo", page_icon="🔐", layout="wide")

st.markdown(
    """
    <style>
        .block-container {padding-top: 1.5rem; padding-bottom: 2rem; max-width: 1500px;}
        #MainMenu {visibility: hidden;}
        footer {visibility: hidden;}
        .hero {
            padding: 1.35rem 1.5rem;
            border-radius: 18px;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 54%, #14532d 100%);
            color: white;
            margin-bottom: 1.15rem;
            box-shadow: 0 14px 32px rgba(15, 23, 42, 0.18);
        }
        .hero-title {font-size: 2rem; font-weight: 760; letter-spacing: -0.02em; margin-bottom: 0.25rem;}
        .hero-subtitle {font-size: 1rem; opacity: 0.92; max-width: 1080px;}
        .hero-pills {margin-top: 0.85rem; display: flex; gap: 0.45rem; flex-wrap: wrap;}
        .hero-pill {
            border: 1px solid rgba(255,255,255,0.22);
            border-radius: 999px;
            padding: 0.25rem 0.7rem;
            background: rgba(255,255,255,0.10);
            font-size: 0.82rem;
        }
        .status-grid {display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 0.8rem; margin: 0.9rem 0 1.15rem 0;}
        .status-card {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 16px;
            padding: 0.95rem 0.95rem 0.8rem 0.95rem;
            min-height: 132px;
            box-shadow: 0 7px 18px rgba(15, 23, 42, 0.06);
        }
        .status-title {font-size: 0.78rem; text-transform: uppercase; color: #64748b; letter-spacing: 0.055em; font-weight: 700;}
        .status-value {font-size: 1.42rem; font-weight: 760; margin: 0.28rem 0 0.52rem 0; color: #0f172a; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;}
        .status-detail {font-size: 0.76rem; color: #64748b; margin-top: 0.45rem; min-height: 1rem;}
        .badge {padding: 0.22rem 0.62rem; border-radius: 999px; font-size: 0.78rem; font-weight: 700; display: inline-block;}
        .badge-green {background: #dcfce7; color: #166534; border: 1px solid #bbf7d0;}
        .badge-yellow {background: #fef3c7; color: #92400e; border: 1px solid #fde68a;}
        .badge-red {background: #fee2e2; color: #991b1b; border: 1px solid #fecaca;}
        .section-card {
            border: 1px solid #e5e7eb;
            border-radius: 16px;
            padding: 1rem 1.15rem;
            background: #ffffff;
            box-shadow: 0 7px 18px rgba(15, 23, 42, 0.045);
            margin-bottom: 1rem;
        }
        .section-title {font-size: 1.2rem; font-weight: 760; color: #0f172a; margin-bottom: 0.3rem;}
        .section-caption {color: #64748b; font-size: 0.92rem; margin-bottom: 0.8rem;}
        .flow-grid {display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 0.55rem; align-items: stretch;}
        .flow-step {border: 1px solid #dbeafe; background: #f8fafc; border-radius: 14px; padding: 0.8rem; min-height: 95px;}
        .flow-label {font-weight: 750; color: #0f172a; font-size: 0.92rem; margin-bottom: 0.25rem;}
        .flow-detail {color: #64748b; font-size: 0.78rem; line-height: 1.25;}
        .callout {border-left: 5px solid #22c55e; background: #f0fdf4; border-radius: 12px; padding: 0.8rem 1rem; color: #14532d; margin: 0.8rem 0;}
        .sidebar-note {font-size: 0.86rem; color: #475569; line-height: 1.35;}
        div[data-testid="stButton"] > button {border-radius: 10px; width: 100%; border: 1px solid #d1d5db;}
        div[data-testid="stMetricValue"] {font-size: 1.4rem;}
        @media (max-width: 1200px) {
            .status-grid {grid-template-columns: repeat(3, minmax(0, 1fr));}
            .flow-grid {grid-template-columns: repeat(2, minmax(0, 1fr));}
        }
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

gpu_status = "unknown"
agent_record = agents_state.get(AGENT_ID, {})
if agent_record:
    gpu_status = f"agent_quota={agent_record.get('gpu_quota_max_jobs', 'n/a')}"

st.markdown(
    """
    <div class='hero'>
        <div class='hero-title'>Centralized Token Service Demo</div>
        <div class='hero-subtitle'>Enterprise IAM control-plane prototype for Linux developers, Entra-style identity, non-human agents, sender-constrained tokens, GPU governance, and auditability.</div>
        <div class='hero-pills'>
            <span class='hero-pill'>Zero Trust</span>
            <span class='hero-pill'>Linux CLI</span>
            <span class='hero-pill'>OBO / Delegation</span>
            <span class='hero-pill'>Agent / NHI Identity</span>
            <span class='hero-pill'>GPU Governance</span>
            <span class='hero-pill'>Audit Trail</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

st.markdown(
    "<div class='status-grid'>"
    + status_card("Token Service", "Healthy" if ts_ok else "Error", "healthy" if ts_ok else "error", TOKEN_SERVICE_URL)
    + status_card("Internal API", "Healthy" if api_ok else "Error", "healthy" if api_ok else "error", INTERNAL_API_URL)
    + status_card("Device ID", DEVICE_ID, "active", "Linux endpoint")
    + status_card("User", USER_ID, "active", "Developer principal")
    + status_card("Agent", AGENT_ID, agent_record.get("status", "unknown"), "Non-human identity")
    + status_card("GPU Quota", gpu_status, "allowed" if "quota" in gpu_status else "unknown", "Governed workload access")
    + "</div>",
    unsafe_allow_html=True,
)

st.markdown(
    """
    <div class='section-card'>
        <div class='section-title'>Architecture Flow</div>
        <div class='section-caption'>How the demo explains enterprise token governance end to end.</div>
        <div class='flow-grid'>
    """
    + flow_step("1. Linux CLI", "Developer or automation starts from devctl.py on a Linux-style endpoint.")
    + flow_step("2. Entra / IdP", "Production source of user identity, MFA, Conditional Access, and OBO trust.")
    + flow_step("3. Token Service", "Issues short-lived scoped JWTs, refreshes tokens, step-up tokens, and agent tokens.")
    + flow_step("4. Device / PKI", "Binds tokens to device or agent certificate proof using cnf.x5t#S256.")
    + flow_step("5. Internal / GPU API", "Validates signature, audience, scope, sender proof, and GPU quota rules.")
    + flow_step("6. Audit / SIEM", "Records token issuance, OBO, step-up, agent, and GPU access events.")
    + """
        </div>
    </div>
    """,
    unsafe_allow_html=True,
)

with st.sidebar:
    st.title("Demo Controls")
    st.markdown(
        "<div class='sidebar-note'>Run the real demo actions from the terminal. These buttons are visual placeholders so the browser does not execute shell commands.</div>",
        unsafe_allow_html=True,
    )
    st.divider()
    st.button("Bootstrap Device Registry")
    st.button("Login")
    st.button("GPU Quota Update")
    st.button("Register Agent")
    st.button("Agent Comment")
    st.button("Agent GPU Submit")
    if st.button("Refresh Audit"):
        audit_state = load_json(STATE_DIR / "audit.json", [])
        st.success("Audit state refreshed")
    st.divider()
    st.caption("Interview tip: show Overview → Token Claims → Agent Identity / NHI → Audit Timeline.")


overview_tab, trust_tab, claims_tab, agent_tab, gpu_tab, audit_tab = st.tabs(
    ["Overview", "Device Trust", "Token Claims", "Agent Identity / NHI", "GPU Jobs", "Audit Timeline"]
)

with overview_tab:
    st.markdown(
        """
        <div class='callout'>
        <b>Panel explanation:</b> This dashboard is the visualization layer. The actual controls are enforced by the token service, CLI, internal API, certificate proof, scopes, and audit flow.
        </div>
        """,
        unsafe_allow_html=True,
    )
    left, right = st.columns([1.15, 1])
    with left:
        st.subheader("Service Health")
        st.json({"token_service": ts_health, "internal_api": api_health})
    with right:
        st.subheader("Demo Script")
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
    st.subheader("Linux Developer Fleet")
    st.caption("Each Linux laptop is treated as a device identity. Token issuance can be conditioned on managed status, EDR health, encryption, risk, and certificate binding.")

    fleet = device_registry.get("devices", []) if isinstance(device_registry, dict) else []
    total_devices = len(fleet)
    active_devices = sum(1 for d in fleet if str(d.get("status", "")).lower() == "active")
    blocked_or_high_risk = sum(
        1
        for d in fleet
        if str(d.get("status", "")).lower() == "blocked" or str(d.get("risk", "")).lower() == "high"
    )
    managed_count = sum(1 for d in fleet if d.get("managed") is True)
    managed_percentage = (managed_count / total_devices * 100) if total_devices else 0.0

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total devices", total_devices)
    m2.metric("Active devices", active_devices)
    m3.metric("Blocked/high-risk devices", blocked_or_high_risk)
    m4.metric("Managed percentage", f"{managed_percentage:.0f}%")

    display_rows = []
    for d in fleet:
        display_rows.append(
            {
                "device_id": d.get("device_id", ""),
                "owner": d.get("owner", ""),
                "os": d.get("os", ""),
                "managed": badge("healthy" if d.get("managed") else "blocked"),
                "edr_healthy": badge("healthy" if d.get("edr_healthy") else "blocked"),
                "disk_encrypted": badge("healthy" if d.get("disk_encrypted") else "blocked"),
                "risk": badge("healthy" if str(d.get("risk", "")).lower() == "low" else str(d.get("risk", "unknown"))),
                "status": badge("active" if str(d.get("status", "")).lower() == "active" else str(d.get("status", "unknown"))),
            }
        )

    fleet_df = pd.DataFrame(
        display_rows,
        columns=["device_id", "owner", "os", "managed", "edr_healthy", "disk_encrypted", "risk", "status"],
    )
    st.markdown(fleet_df.to_html(index=False, escape=False), unsafe_allow_html=True)

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
        st.info("No .state/devctl_tokens.json access_token found yet. Run `python devctl.py login --auto` first.")

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
        st.info("No .state/agents.json data found. Run `python devctl.py register-agent` first.")

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
        st.info("No .state/audit.json data found. Run `python devctl.py audit` after demo commands.")
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
