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
        is_json = r.headers.get("content-type", "").startswith("application/json")
        return r.ok, r.json() if is_json else {}
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
    if value is None or value == "":
        return "—"
    if isinstance(value, list):
        return ", ".join(str(v) for v in value)
    if isinstance(value, dict):
        return json.dumps(value, sort_keys=True)
    return str(value)


def short_text(value, max_len=36):
    text = display_value(value)
    return text if len(text) <= max_len else f"{text[: max_len - 1]}…"


def badge(value: str):
    raw = str(value or "unknown")
    low = raw.lower()
    safe = html.escape(raw)
    if any(k in low for k in ["ok", "active", "allow", "allowed", "healthy", "low", "online", "green"]):
        cls = "badge-green"
        dot = "●"
    elif any(k in low for k in ["step", "pending", "mfa", "warning", "medium"]):
        cls = "badge-yellow"
        dot = "●"
    elif any(k in low for k in ["error", "fail", "blocked", "high", "deny", "revoked", "offline"]):
        cls = "badge-red"
        dot = "●"
    else:
        cls = "badge-slate"
        dot = "○"
    return f"<span class='badge {cls}'>{dot} {safe}</span>"


def event_name(e: dict) -> str:
    return str(e.get("event_type") or e.get("event") or "unknown")


def audit_bar_color(name: str) -> str:
    e = name.lower()
    if any(k in e for k in ["fail", "revok", "deny", "reject", "detect"]):
        return "#ef4444"
    if any(k in e for k in ["stepup", "step_up", "pim"]):
        return "#f59e0b"
    if "agent" in e:
        return "#8b5cf6"
    if "gpu" in e:
        return "#06b6d4"
    if "refresh" in e:
        return "#3b82f6"
    if "token" in e:
        return "#22c55e"
    return "#94a3b8"


def empty_state(icon: str, title: str, command: str):
    return f"""
    <div class='empty-state'>
        <div class='empty-icon'>{icon}</div>
        <div class='empty-title'>{html.escape(title)}</div>
        <div class='empty-cmd'>{html.escape(command)}</div>
    </div>
    """


def status_card(icon: str, label: str, value: str, status: str, detail: str = ""):
    return f"""
    <div class='status-card'>
        <div class='status-icon'>{icon}</div>
        <div class='status-label'>{html.escape(label)}</div>
        <div class='status-value' title='{html.escape(str(value))}'>{html.escape(short_text(value, 18))}</div>
        <div>{badge(status)}</div>
        <div class='status-detail'>{html.escape(detail)}</div>
    </div>
    """


def flow_node(number: int, icon: str, label: str, detail: str):
    return f"""
    <div class='flow-node'>
        <div class='flow-step'>Step {number}</div>
        <div class='flow-icon'>{icon}</div>
        <div class='flow-label'>{html.escape(label)}</div>
        <div class='flow-detail'>{html.escape(detail)}</div>
    </div>
    """


st.set_page_config(
    page_title="Token Service — Security Demo",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">',
    unsafe_allow_html=True,
)

st.markdown(
    """
<style>
html, body, [class*="css"] {font-family:'DM Sans', sans-serif !important;}
code, pre, .mono {font-family:'DM Mono', monospace !important;}
.block-container {padding-top:1.15rem; padding-bottom:2rem; max-width:1440px;}
#MainMenu, footer {visibility:hidden;}
.hero {background:linear-gradient(130deg,#0d1117 0%,#102a43 55%,#0f3d25 100%); border-radius:20px; padding:1.55rem 2rem 1.35rem; margin-bottom:1.2rem; box-shadow:0 20px 48px rgba(15,23,42,.22); position:relative; overflow:hidden;}
.hero:after {content:""; position:absolute; inset:0; background:radial-gradient(ellipse 55% 80% at 85% 35%,rgba(59,130,246,.18),transparent 70%); pointer-events:none;}
.hero-eyebrow {font-size:.75rem; letter-spacing:.16em; text-transform:uppercase; color:#93c5fd; font-weight:700; margin-bottom:.42rem;}
.hero-title {font-size:2.05rem; font-weight:760; color:#f8fafc; letter-spacing:-.03em; line-height:1.15; margin-bottom:.45rem;}
.hero-title span {color:#60a5fa;}
.hero-sub {font-size:.94rem; color:#cbd5e1; max-width:980px; line-height:1.55;}
.hero-pills {margin-top:1rem; display:flex; gap:.42rem; flex-wrap:wrap;}
.hero-pill {background:rgba(96,165,250,.13); border:1px solid rgba(96,165,250,.30); color:#bfdbfe; border-radius:999px; padding:.23rem .72rem; font-size:.78rem; font-weight:600;}
.status-grid {display:grid; grid-template-columns:repeat(6,minmax(0,1fr)); gap:.75rem; margin-bottom:1.1rem;}
.status-card {background:#fff; border:1px solid #e2e8f0; border-radius:18px; padding:1rem .95rem .9rem; box-shadow:0 4px 16px rgba(15,23,42,.06); min-height:132px;}
.status-card:hover {box-shadow:0 10px 26px rgba(15,23,42,.10);}
.status-icon {font-size:1.45rem; margin-bottom:.35rem;}
.status-label {font-size:.72rem; text-transform:uppercase; letter-spacing:.06em; color:#94a3b8; font-weight:700;}
.status-value {font-size:1.08rem; font-weight:760; color:#0f172a; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; margin:.18rem 0 .48rem;}
.status-detail {font-size:.73rem; color:#94a3b8; margin-top:.35rem;}
.badge {padding:.20rem .60rem; border-radius:999px; font-size:.75rem; font-weight:700; display:inline-flex; align-items:center; gap:.3rem; white-space:nowrap;}
.badge-green {background:#dcfce7; color:#15803d; border:1px solid #bbf7d0;}
.badge-blue {background:#dbeafe; color:#1d4ed8; border:1px solid #bfdbfe;}
.badge-yellow {background:#fef3c7; color:#b45309; border:1px solid #fde68a;}
.badge-red {background:#fee2e2; color:#b91c1c; border:1px solid #fecaca;}
.badge-slate {background:#f1f5f9; color:#475569; border:1px solid #e2e8f0;}
.section-card {background:#fff; border:1px solid #e2e8f0; border-radius:18px; padding:1.15rem 1.3rem; box-shadow:0 4px 14px rgba(15,23,42,.045); margin-bottom:1rem;}
.section-title {font-size:1.1rem; font-weight:760; color:#0f172a; margin-bottom:.2rem;}
.section-caption {font-size:.86rem; color:#64748b; margin-bottom:.9rem;}
.flow-wrap {display:flex; align-items:stretch; gap:0; overflow-x:auto; padding-bottom:.25rem;}
.flow-node {flex:1; min-width:145px; background:#f8fafc; border:1.5px solid #e2e8f0; border-radius:14px; padding:.85rem; position:relative;}
.flow-node + .flow-node {margin-left:2rem;}
.flow-node + .flow-node:before {content:"→"; position:absolute; left:-1.55rem; top:50%; transform:translateY(-50%); font-size:1.1rem; color:#94a3b8; font-weight:800;}
.flow-step {font-size:.68rem; font-weight:800; letter-spacing:.08em; text-transform:uppercase; color:#94a3b8; margin-bottom:.35rem;}
.flow-icon {font-size:1.35rem; margin-bottom:.25rem;}
.flow-label {font-size:.88rem; font-weight:800; color:#0f172a; margin-bottom:.24rem;}
.flow-detail {font-size:.75rem; color:#64748b; line-height:1.35;}
.callout-blue {border-left:4px solid #3b82f6; background:#eff6ff; border-radius:10px; padding:.78rem 1rem; color:#1e40af; font-size:.88rem; margin:.75rem 0;}
.callout-green {border-left:4px solid #22c55e; background:#f0fdf4; border-radius:10px; padding:.78rem 1rem; color:#15803d; font-size:.88rem; margin:.75rem 0;}
.claim-grid {display:grid; grid-template-columns:165px 1fr; gap:.55rem .8rem;}
.claim-key {font-family:'DM Mono',monospace; font-size:.76rem; text-transform:uppercase; letter-spacing:.05em; color:#64748b; font-weight:700; padding-top:.15rem;}
.claim-val {font-family:'DM Mono',monospace; font-size:.82rem; background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:.28rem .6rem; color:#0f172a; word-break:break-all;}
.claim-meaning {font-size:.76rem; color:#64748b; padding-top:.05rem;}
.agent-card {background:#fff; border:1px solid #e2e8f0; border-radius:16px; padding:1rem 1.1rem; margin-bottom:.75rem; box-shadow:0 4px 14px rgba(15,23,42,.045);}
.agent-head {display:flex; justify-content:space-between; align-items:flex-start; gap:1rem;}
.agent-title {font-size:1rem; font-weight:800; color:#0f172a; margin-bottom:.18rem;}
.agent-meta {font-size:.82rem; color:#64748b;}
.agent-scopes {margin-top:.65rem; font-family:'DM Mono',monospace; color:#334155; font-size:.81rem;}
.gpu-card {background:#f8fafc; border:1.5px solid #e2e8f0; border-radius:14px; padding:1rem 1.1rem;}
.gpu-label {font-size:.75rem; text-transform:uppercase; letter-spacing:.06em; color:#64748b; font-weight:700;}
.gpu-val {font-size:1.85rem; font-weight:780; color:#0f172a; margin:.25rem 0; line-height:1;}
.gpu-sub {font-size:.78rem; color:#64748b;}
.audit-row {display:grid; grid-template-columns:6px 140px 190px 110px 135px 1fr 90px; align-items:center; gap:.5rem; padding:.55rem .75rem; border-radius:10px; margin-bottom:.32rem; background:#fff; border:1px solid #f1f5f9;}
.audit-row:hover {background:#f8fafc;}
.audit-bar {border-radius:3px; height:36px; width:6px;}
.audit-ts {font-family:'DM Mono',monospace; font-size:.72rem; color:#64748b;}
.audit-event {font-size:.8rem; font-weight:700; color:#0f172a;}
.audit-cell {font-size:.78rem; color:#475569; white-space:nowrap; overflow:hidden; text-overflow:ellipsis;}
.audit-hdr {display:grid; grid-template-columns:6px 140px 190px 110px 135px 1fr 90px; gap:.5rem; padding:.4rem .75rem; font-size:.7rem; text-transform:uppercase; letter-spacing:.07em; color:#94a3b8; font-weight:800; border-bottom:1px solid #e2e8f0; margin-bottom:.4rem;}
.empty-state {text-align:center; padding:2.5rem 1rem; color:#94a3b8;}
.empty-icon {font-size:2.3rem; margin-bottom:.55rem;}
.empty-title {font-size:.95rem; font-weight:700; color:#64748b; margin-bottom:.3rem;}
.empty-cmd {font-family:'DM Mono',monospace; font-size:.82rem; background:#f1f5f9; border-radius:8px; padding:.35rem .85rem; display:inline-block; margin-top:.5rem; color:#334155;}
section[data-testid="stSidebar"] {background:#0d1117 !important;}
section[data-testid="stSidebar"] * {color:#e2e8f0 !important;}
.sidebar-group {font-size:.7rem; text-transform:uppercase; letter-spacing:.1em; color:#64748b !important; font-weight:800; margin:.85rem 0 .35rem;}
div[data-testid="stButton"] > button {width:100%; border-radius:10px;}
section[data-testid="stSidebar"] .stButton > button {background:rgba(255,255,255,.06) !important; border:1px solid rgba(255,255,255,.12) !important; color:#e2e8f0 !important;}
section[data-testid="stSidebar"] .stButton > button:hover {background:rgba(96,165,250,.18) !important; border-color:rgba(96,165,250,.35) !important;}
@media (max-width:1200px) {.status-grid{grid-template-columns:repeat(3,minmax(0,1fr));}.audit-row,.audit-hdr{grid-template-columns:6px 120px 1fr 90px 90px;}.audit-row>*:nth-child(4),.audit-row>*:nth-child(5),.audit-hdr>*:nth-child(4),.audit-hdr>*:nth-child(5){display:none;}}
</style>
""",
    unsafe_allow_html=True,
)

# State
cli_tokens = load_json(STATE_DIR / "devctl_tokens.json", {})
audit_state = load_json(STATE_DIR / "audit.json", [])
agents_state = load_json(STATE_DIR / "agents.json", {})
device_registry = load_json(Path("device_registry.json"), {})
ts_ok, ts_health = health(TOKEN_SERVICE_URL)
api_ok, api_health = health(INTERNAL_API_URL)
agent_record = agents_state.get(AGENT_ID, {})
gpu_quota = agent_record.get("gpu_quota_max_jobs", "—")

# Header
st.markdown(
    """
<div class='hero'>
  <div class='hero-eyebrow'>Enterprise IAM · Proof-of-Concept</div>
  <div class='hero-title'>Centralized <span>Token Service</span> Demo</div>
  <div class='hero-sub'>Short-lived JWTs · Refresh rotation · OBO delegation · Sender-constrained tokens · Agent identity · GPU governance · Full audit trail</div>
  <div class='hero-pills'>
    <span class='hero-pill'>🛡 Zero Trust</span>
    <span class='hero-pill'>🖥 Linux CLI</span>
    <span class='hero-pill'>🔄 OBO / Delegation</span>
    <span class='hero-pill'>🤖 Agent / NHI Identity</span>
    <span class='hero-pill'>⚡ GPU Governance</span>
    <span class='hero-pill'>📋 Audit Trail</span>
    <span class='hero-pill'>🔑 PKI / cnf Binding</span>
  </div>
</div>
""",
    unsafe_allow_html=True,
)

st.markdown(
    "<div class='status-grid'>"
    + status_card("🔐", "Token Service", "Healthy" if ts_ok else "Error", "healthy" if ts_ok else "error", TOKEN_SERVICE_URL)
    + status_card("🛡", "Internal API", "Healthy" if api_ok else "Error", "healthy" if api_ok else "error", INTERNAL_API_URL)
    + status_card("💻", "Device", DEVICE_ID, "active", "Linux endpoint")
    + status_card("👤", "User", USER_ID, "active", "Developer principal")
    + status_card("🤖", "Agent", AGENT_ID, agent_record.get("status", "unknown"), "Non-human identity")
    + status_card("⚡", "GPU Quota", f"{gpu_quota} job(s)", "allowed" if gpu_quota != "—" else "unknown", "Per-agent cap")
    + "</div>",
    unsafe_allow_html=True,
)

st.markdown(
    f"""
<div class='section-card'>
  <div class='section-title'>Architecture Flow</div>
  <div class='section-caption'>How the demo explains enterprise token governance end to end.</div>
  <div class='flow-wrap'>
    {flow_node(1, '🖥', 'Linux CLI', 'devctl.py starts login, OBO, GPU, step-up, and agent flows')}
    {flow_node(2, '🏛', 'Entra / IdP', 'Production source of user identity, MFA, Conditional Access, and OBO trust')}
    {flow_node(3, '🔐', 'Token Service', 'Issues short-lived JWTs, refresh tokens, step-up tokens, and agent tokens')}
    {flow_node(4, '🔑', 'PKI / cnf', 'Binds tokens to certificate thumbprint using cnf.x5t#S256')}
    {flow_node(5, '🛡', 'Internal / GPU API', 'Validates signature, audience, scope, sender proof, and GPU quota')}
    {flow_node(6, '📋', 'Audit / SIEM', 'Records auth, token, OBO, agent, and GPU access events')}
  </div>
</div>
""",
    unsafe_allow_html=True,
)

with st.sidebar:
    st.markdown("## 🔐 Demo Guide")
    st.caption("Run actual flows from PowerShell. The dashboard is read-only visualization for the interview.")
    st.divider()
    st.markdown("<div class='sidebar-group'>Identity / Auth</div>", unsafe_allow_html=True)
    st.code("python devctl.py login --auto\npython devctl.py obo-build\npython devctl.py refresh", language="bash")
    st.markdown("<div class='sidebar-group'>Agent / NHI</div>", unsafe_allow_html=True)
    st.code("python devctl.py register-agent\npython devctl.py agent-comment\npython devctl.py agent-gpu-submit", language="bash")
    st.markdown("<div class='sidebar-group'>Privileged Ops</div>", unsafe_allow_html=True)
    st.code("python devctl.py deploy-prod\npython devctl.py gpu-quota-update --subject developer01 --quota 3", language="bash")
    st.markdown("<div class='sidebar-group'>Dashboard</div>", unsafe_allow_html=True)
    if st.button("🔃 Refresh Audit Log", use_container_width=True):
        audit_state = load_json(STATE_DIR / "audit.json", [])
        st.success("Audit refreshed")
    st.divider()
    st.caption("Best panel flow: Overview → Token Claims → Agent / NHI → Audit Timeline")


t_overview, t_fleet, t_claims, t_agent, t_gpu, t_audit = st.tabs(
    ["🏠 Overview", "💻 Linux Developer Fleet", "🔎 Token Claims", "🤖 Agent / NHI", "⚡ GPU Jobs", "📋 Audit Timeline"]
)

with t_overview:
    st.markdown(
        """
<div class='callout-blue'>
<b>Panel explanation:</b> This dashboard is the visualization layer only. Security controls are enforced by the token service, CLI, internal API, certificate proof, scopes, and audit flow.
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
        with st.expander("Raw health JSON"):
            st.json({"token_service": ts_health, "internal_api": api_health})
    with right:
        st.subheader("Quick-start")
        st.code(
            """# Terminal 1
python token_service.py

# Terminal 2
python internal_api.py

# Terminal 3
python devctl.py login --auto
python devctl.py obo-build
python devctl.py gpu-submit
python devctl.py register-agent
python devctl.py agent-gpu-submit
python devctl.py audit

# Terminal 4
streamlit run dashboard.py""",
            language="bash",
        )

with t_fleet:
    st.subheader("Linux Developer Fleet")
    st.caption("Each Linux laptop is treated as a device identity. Token issuance can be conditioned on managed status, EDR health, encryption, risk, and certificate binding.")
    fleet = device_registry.get("devices", []) if isinstance(device_registry, dict) else []
    total = len(fleet)
    active = sum(1 for d in fleet if str(d.get("status", "")).lower() == "active")
    blocked_high = sum(1 for d in fleet if str(d.get("status", "")).lower() == "blocked" or str(d.get("risk", "")).lower() == "high")
    managed = sum(1 for d in fleet if d.get("managed") is True)
    pct = (managed / total * 100) if total else 0
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total devices", total)
    m2.metric("Active devices", active)
    m3.metric("Blocked/high-risk", blocked_high)
    m4.metric("Managed", f"{pct:.0f}%")
    if not fleet:
        st.markdown(empty_state("💻", "No device registry found", "python devctl.py bootstrap-device-registry"), unsafe_allow_html=True)
    else:
        rows = []
        for d in fleet:
            rows.append(
                {
                    "device_id": d.get("device_id", ""),
                    "owner": d.get("owner", ""),
                    "os": d.get("os", ""),
                    "managed": badge("healthy" if d.get("managed") else "blocked"),
                    "edr_healthy": badge("healthy" if d.get("edr_healthy") else "blocked"),
                    "disk_encrypted": badge("healthy" if d.get("disk_encrypted") else "blocked"),
                    "risk": badge(d.get("risk", "unknown")),
                    "status": badge(d.get("status", "unknown")),
                }
            )
        st.markdown(pd.DataFrame(rows).to_html(index=False, escape=False), unsafe_allow_html=True)
        with st.expander("Raw device_registry.json"):
            st.json(device_registry)

with t_claims:
    st.subheader("Decoded Token Claims")
    token = cli_tokens.get("access_token", "")
    if not token:
        st.markdown(empty_state("🔑", "No access token found yet", "python devctl.py login --auto"), unsafe_allow_html=True)
    else:
        claims = decode_jwt_payload(token)
        claim_defs = [
            ("sub", "Subject identity", claims.get("sub")),
            ("actor_type", "Human vs agent", claims.get("actor_type")),
            ("device_id", "Endpoint / device context", claims.get("device_id")),
            ("agent_id", "Non-human identity", claims.get("agent_id")),
            ("scope", "Least-privilege permission", claims.get("scope")),
            ("aud", "Target API / resource", claims.get("aud")),
            ("cnf", "Certificate-bound proof", claims.get("cnf")),
            ("auth_strength", "MFA / step-up strength", claims.get("auth_strength")),
            ("pim", "Privileged activation", claims.get("pim")),
            ("approval_id", "Step-up approval evidence", claims.get("approval_id")),
            ("exp", "Token expiry epoch", claims.get("exp")),
            ("jti", "Unique token ID", claims.get("jti")),
        ]
        rows = ""
        for key, meaning, value in claim_defs:
            val = display_value(value)
            val_html = html.escape(val) if value is not None else "<span style='color:#94a3b8'>not present</span>"
            rows += f"""
<div style='display:contents'>
  <div class='claim-key'>{html.escape(key)}</div>
  <div><div class='claim-val'>{val_html}</div><div class='claim-meaning'>{html.escape(meaning)}</div></div>
</div>
"""
        st.markdown(f"<div class='claim-grid'>{rows}</div>", unsafe_allow_html=True)
        with st.expander("Full raw claims JSON"):
            st.json(claims)

with t_agent:
    st.subheader("Agent / Non-Human Identity Registry")
    st.caption("Each agent has an explicit ID, owner, environment, scopes, and GPU quota — never anonymous automation.")
    if not agents_state:
        st.markdown(empty_state("🤖", "No agents registered yet", "python devctl.py register-agent"), unsafe_allow_html=True)
    else:
        for aid, item in agents_state.items():
            st.markdown(
                f"""
<div class='agent-card'>
  <div class='agent-head'>
    <div>
      <div class='agent-title'>🤖 {html.escape(aid)}</div>
      <div class='agent-meta'>Owner: <b>{html.escape(item.get('agent_owner','?'))}</b> · Env: <b>{html.escape(item.get('environment','?'))}</b> · GPU quota: <b>{item.get('gpu_quota_max_jobs','?')}</b> job(s)</div>
    </div>
    <div>{badge(item.get('status','unknown'))}</div>
  </div>
  <div class='agent-scopes'>{html.escape(', '.join(item.get('allowed_scopes', [])))}</div>
</div>
""",
                unsafe_allow_html=True,
            )
        with st.expander("Raw agents JSON"):
            st.json(agents_state)

with t_gpu:
    st.subheader("GPU Governance Overview")
    gpu_events = [e for e in audit_state if "gpu" in event_name(e).lower()]
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"<div class='gpu-card'><div class='gpu-label'>Agent GPU Quota</div><div class='gpu-val'>{gpu_quota}</div><div class='gpu-sub'>max concurrent jobs</div></div>", unsafe_allow_html=True)
    with col2:
        st.markdown("<div class='gpu-card'><div class='gpu-label'>Developer Quota</div><div class='gpu-val'>2</div><div class='gpu-sub'>demo max concurrent jobs</div></div>", unsafe_allow_html=True)
    with col3:
        st.markdown(f"<div class='gpu-card'><div class='gpu-label'>GPU Events</div><div class='gpu-val'>{len(gpu_events)}</div><div class='gpu-sub'>audit-recorded actions</div></div>", unsafe_allow_html=True)
    st.markdown("""
<div class='callout-green'>
<b>Governance controls active:</b> GPU job submission requires <code>gpu.job.submit</code> scope via OBO exchange · quota updates require step-up token with <code>pim=true</code> and <code>approval_id</code> · agent GPU access is bounded by registered quota.
</div>
""", unsafe_allow_html=True)
    st.markdown("**Production roadmap**")
    st.markdown(
        """
- **Kubernetes admission webhook** — validate GPU token claims before pod scheduling.
- **Run:ai / NVIDIA GPU Operator** — enforce quota at workload runtime layer.
- **GPU-hours reconciliation** — compare audit trail with actual GPU consumption.
- **Per-actor rate limiting** — throttle by user, device, agent, and scope.
"""
    )

with t_audit:
    st.subheader("Audit Timeline")
    st.caption("Every auth, token issuance, OBO, refresh, step-up, agent, and GPU event — newest first.")
    if not audit_state:
        st.markdown(empty_state("📋", "No audit events yet", "python devctl.py audit"), unsafe_allow_html=True)
    else:
        counts = {}
        for e in audit_state:
            name = event_name(e)
            counts[name] = counts.get(name, 0) + 1
        metric_cols = st.columns(min(max(len(counts), 1), 5))
        for i, (name, count) in enumerate(list(counts.items())[:5]):
            with metric_cols[i % len(metric_cols)]:
                st.metric(name.replace("_", " ").title(), count)
        st.markdown("""
<div class='audit-hdr'><div></div><div>Timestamp</div><div>Event Type</div><div>Actor</div><div>User / Agent</div><div>Scope / Detail</div><div>Decision</div></div>
""", unsafe_allow_html=True)
        for e in reversed(audit_state[-120:]):
            name = event_name(e)
            ts_raw = e.get("timestamp") or e.get("ts") or ""
            ts_disp = str(ts_raw)[:16].replace("T", " ") if ts_raw else "—"
            actor = display_value(e.get("actor_type"))
            user = display_value(e.get("user") or e.get("sub"))
            agent = display_value(e.get("agent_id"))
            identity = agent if agent != "—" else user
            scope = display_value(e.get("scope") or e.get("scopes") or e.get("reason"))
            decision = display_value(e.get("decision") or "allow")
            bar = audit_bar_color(name)
            st.markdown(
                f"""
<div class='audit-row'>
  <div class='audit-bar' style='background:{bar};'></div>
  <div class='audit-ts'>{html.escape(ts_disp)}</div>
  <div class='audit-event'>{html.escape(name.replace('_',' '))}</div>
  <div class='audit-cell'>{badge(actor)}</div>
  <div class='audit-cell' title='{html.escape(identity)}'>{html.escape(short_text(identity,18))}</div>
  <div class='audit-cell' title='{html.escape(scope)}'>{html.escape(short_text(scope,46))}</div>
  <div>{badge(decision)}</div>
</div>
""",
                unsafe_allow_html=True,
            )
        with st.expander(f"Export — all {len(audit_state)} events as JSON"):
            st.json(audit_state)
