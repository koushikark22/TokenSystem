import base64
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


def status_icon(value: str) -> str:
    low = str(value or "").lower()
    if any(k in low for k in ["healthy", "active", "allow", "allowed", "low", "online", "ok"]):
        return "🟢"
    if any(k in low for k in ["step", "pending", "medium", "warning"]):
        return "🟡"
    if any(k in low for k in ["error", "blocked", "high", "fail", "deny", "offline"]):
        return "🔴"
    return "⚪"


def event_name(event: dict) -> str:
    return str(event.get("event_type") or event.get("event") or "unknown")


def claim_rows(claims: dict) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {"claim": "sub", "meaning": "Subject identity", "value": display_value(claims.get("sub"))},
            {"claim": "actor_type", "meaning": "Human vs agent", "value": display_value(claims.get("actor_type"))},
            {"claim": "device_id", "meaning": "Endpoint/device context", "value": display_value(claims.get("device_id"))},
            {"claim": "agent_id", "meaning": "Non-human identity", "value": display_value(claims.get("agent_id"))},
            {"claim": "scope", "meaning": "Least-privilege permission", "value": display_value(claims.get("scope"))},
            {"claim": "aud", "meaning": "Target API/resource", "value": display_value(claims.get("aud"))},
            {"claim": "cnf", "meaning": "Certificate-bound proof", "value": display_value(claims.get("cnf"))},
            {"claim": "auth_strength", "meaning": "MFA/step-up strength", "value": display_value(claims.get("auth_strength"))},
            {"claim": "pim", "meaning": "Privileged activation", "value": display_value(claims.get("pim"))},
            {"claim": "approval_id", "meaning": "Step-up approval evidence", "value": display_value(claims.get("approval_id"))},
            {"claim": "exp", "meaning": "Token expiry epoch", "value": display_value(claims.get("exp"))},
            {"claim": "jti", "meaning": "Unique token ID", "value": display_value(claims.get("jti"))},
        ]
    )


st.set_page_config(
    page_title="Token Service — Security Demo",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
<style>
.block-container {padding-top: 1.2rem; padding-bottom: 2rem; max-width: 1400px;}
#MainMenu, footer {visibility: hidden;}
.hero-box {background: linear-gradient(130deg, #0d1117 0%, #102a43 55%, #0f3d25 100%); border-radius: 18px; padding: 1.45rem 1.7rem; margin-bottom: 1rem; color: white;}
.hero-eyebrow {font-size: .75rem; letter-spacing: .14em; text-transform: uppercase; color: #93c5fd; font-weight: 700;}
.hero-title {font-size: 2rem; font-weight: 800; margin: .25rem 0 .35rem 0; letter-spacing: -.02em;}
.hero-sub {color: #cbd5e1; font-size: .96rem; line-height: 1.45;}
.pill {display:inline-block; background:rgba(96,165,250,.14); border:1px solid rgba(96,165,250,.30); color:#bfdbfe; border-radius:999px; padding:.2rem .65rem; margin:.7rem .25rem 0 0; font-size:.78rem; font-weight:600;}
section[data-testid="stSidebar"] {background:#0d1117;}
section[data-testid="stSidebar"] * {color:#e2e8f0 !important;}
</style>
""",
    unsafe_allow_html=True,
)

cli_tokens = load_json(STATE_DIR / "devctl_tokens.json", {})
audit_state = load_json(STATE_DIR / "audit.json", [])
agents_state = load_json(STATE_DIR / "agents.json", {})
device_registry = load_json(Path("device_registry.json"), {})
ts_ok, ts_health = health(TOKEN_SERVICE_URL)
api_ok, api_health = health(INTERNAL_API_URL)
agent_record = agents_state.get(AGENT_ID, {})
gpu_quota = agent_record.get("gpu_quota_max_jobs", "—")

st.markdown(
    """
<div class="hero-box">
  <div class="hero-eyebrow">Enterprise IAM · Proof-of-Concept</div>
  <div class="hero-title">Centralized Token Service Demo</div>
  <div class="hero-sub">Short-lived JWTs · Refresh rotation · OBO delegation · Sender-constrained tokens · Agent identity · GPU governance · Full audit trail</div>
  <span class="pill">🛡 Zero Trust</span>
  <span class="pill">🖥 Linux CLI</span>
  <span class="pill">🔄 OBO / Delegation</span>
  <span class="pill">🤖 Agent / NHI Identity</span>
  <span class="pill">⚡ GPU Governance</span>
  <span class="pill">📋 Audit Trail</span>
  <span class="pill">🔑 PKI / cnf Binding</span>
</div>
""",
    unsafe_allow_html=True,
)

status_items = [
    ("🔐 Token Service", "Healthy" if ts_ok else "Error", TOKEN_SERVICE_URL, "healthy" if ts_ok else "error"),
    ("🛡 Internal API", "Healthy" if api_ok else "Error", INTERNAL_API_URL, "healthy" if api_ok else "error"),
    ("💻 Device", DEVICE_ID, "Linux endpoint", "active"),
    ("👤 User", USER_ID, "Developer principal", "active"),
    ("🤖 Agent", AGENT_ID, "Non-human identity", agent_record.get("status", "unknown")),
    ("⚡ GPU Quota", f"{gpu_quota} job(s)", "Per-agent cap", "allowed" if gpu_quota != "—" else "unknown"),
]
cols = st.columns(6)
for col, (label, value, detail, status) in zip(cols, status_items):
    with col:
        with st.container(border=True):
            st.caption(label)
            st.markdown(f"**{value}**")
            st.caption(f"{status_icon(status)} {status}")
            st.caption(detail)

st.subheader("Architecture Flow")
flow_cols = st.columns(6)
flow_steps = [
    ("1", "🖥", "Linux CLI", "devctl.py starts login, OBO, GPU, step-up, and agent flows"),
    ("2", "🏛", "Entra / IdP", "Production source of user identity, MFA, Conditional Access, and OBO trust"),
    ("3", "🔐", "Token Service", "Issues short-lived JWTs, refresh tokens, step-up tokens, and agent tokens"),
    ("4", "🔑", "PKI / cnf", "Binds tokens to certificate thumbprint using cnf.x5t#S256"),
    ("5", "🛡", "Internal / GPU API", "Validates signature, audience, scope, sender proof, and GPU quota"),
    ("6", "📋", "Audit / SIEM", "Records auth, token, OBO, agent, and GPU access events"),
]
for col, (num, icon, title, detail) in zip(flow_cols, flow_steps):
    with col:
        with st.container(border=True):
            st.caption(f"STEP {num}")
            st.markdown(f"### {icon}")
            st.markdown(f"**{title}**")
            st.caption(detail)

with st.sidebar:
    st.markdown("## 🔐 Demo Guide")
    st.caption("Run actual flows from the CLI. The dashboard is a read-only visualization layer for the demo.")
    st.divider()
    st.markdown("**Identity / Auth**")
    st.code("python devctl.py login --auto\npython devctl.py obo-build\npython devctl.py refresh", language="bash")
    st.markdown("**Agent / NHI**")
    st.code("python devctl.py register-agent\npython devctl.py agent-comment\npython devctl.py agent-gpu-submit", language="bash")
    st.markdown("**Privileged Ops**")
    st.code("python devctl.py deploy-prod\npython devctl.py gpu-quota-update --subject developer01 --quota 3", language="bash")
    st.markdown("**Dashboard**")
    if st.button("🔃 Refresh Audit Log", use_container_width=True):
        audit_state = load_json(STATE_DIR / "audit.json", [])
        st.success("Audit refreshed")
    st.divider()
    st.caption("Recommended demo flow: Overview → Token Claims → Agent / NHI → Audit Timeline")


t_overview, t_fleet, t_claims, t_agent, t_gpu, t_audit = st.tabs(
    ["🏠 Overview", "💻 Linux Developer Fleet", "🔎 Token Claims", "🤖 Agent / NHI", "⚡ GPU Jobs", "📋 Audit Timeline"]
)

with t_overview:
    st.info("Architecture note: This dashboard is the visualization layer only. Security controls are enforced by the token service, CLI, internal API, certificate proof, scopes, and audit flow.")
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
        st.warning("No device registry found. Run: python devctl.py bootstrap-device-registry")
    else:
        rows = []
        for d in fleet:
            risk = str(d.get("risk", "unknown"))
            status = str(d.get("status", "unknown"))
            rows.append(
                {
                    "device_id": d.get("device_id", ""),
                    "owner": d.get("owner", ""),
                    "os": d.get("os", ""),
                    "managed": "✅" if d.get("managed") else "❌",
                    "edr_healthy": "✅" if d.get("edr_healthy") else "❌",
                    "disk_encrypted": "✅" if d.get("disk_encrypted") else "❌",
                    "risk": f"{status_icon(risk)} {risk}",
                    "status": f"{status_icon(status)} {status}",
                }
            )
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        with st.expander("Raw device_registry.json"):
            st.json(device_registry)

with t_claims:
    st.subheader("Decoded Token Claims")
    token = cli_tokens.get("access_token", "")
    if not token:
        st.warning("No access token found yet. Run: python devctl.py login --auto")
    else:
        claims = decode_jwt_payload(token)
        st.dataframe(claim_rows(claims), use_container_width=True, hide_index=True)
        with st.expander("Full raw claims JSON"):
            st.json(claims)

with t_agent:
    st.subheader("Agent / Non-Human Identity Registry")
    st.caption("Each agent has an explicit ID, owner, environment, scopes, and GPU quota — never anonymous automation.")
    if not agents_state:
        st.warning("No agents registered yet. Run: python devctl.py register-agent")
    else:
        for aid, item in agents_state.items():
            with st.container(border=True):
                top_left, top_right = st.columns([3, 1])
                with top_left:
                    st.markdown(f"### 🤖 {aid}")
                    st.write(
                        f"Owner: **{item.get('agent_owner', '?')}** · "
                        f"Env: **{item.get('environment', '?')}** · "
                        f"GPU quota: **{item.get('gpu_quota_max_jobs', '?')} job(s)**"
                    )
                with top_right:
                    st.metric("Status", f"{status_icon(item.get('status'))} {item.get('status', 'unknown')}")
                st.caption("Allowed scopes")
                st.code(", ".join(item.get("allowed_scopes", [])) or "—", language="text")
        with st.expander("Raw agents JSON"):
            st.json(agents_state)

with t_gpu:
    st.subheader("GPU Governance Overview")
    gpu_events = [e for e in audit_state if "gpu" in event_name(e).lower()]
    col1, col2, col3 = st.columns(3)
    col1.metric("Agent GPU quota", gpu_quota, "max concurrent jobs")
    col2.metric("Developer quota", "2", "demo max concurrent jobs")
    col3.metric("GPU events", len(gpu_events), "audit-recorded actions")
    st.success("Governance controls active: GPU job submission requires gpu.job.submit scope via OBO exchange; quota updates require step-up token with pim=true and approval_id; agent GPU access is bounded by registered quota.")
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
        st.warning("No audit events yet. Run: python devctl.py audit")
    else:
        counts = {}
        for e in audit_state:
            name = event_name(e)
            counts[name] = counts.get(name, 0) + 1
        metric_cols = st.columns(min(max(len(counts), 1), 5))
        for i, (name, count) in enumerate(list(counts.items())[:5]):
            with metric_cols[i % len(metric_cols)]:
                st.metric(name.replace("_", " ").title(), count)
        rows = []
        for e in reversed(audit_state[-120:]):
            name = event_name(e)
            ts_raw = e.get("timestamp") or e.get("ts") or ""
            actor = display_value(e.get("actor_type"))
            user = display_value(e.get("user") or e.get("sub"))
            agent = display_value(e.get("agent_id"))
            identity = agent if agent != "—" else user
            rows.append(
                {
                    "timestamp": display_value(ts_raw),
                    "event_type": name,
                    "actor": actor,
                    "user_or_agent": identity,
                    "scope_or_detail": display_value(e.get("scope") or e.get("scopes") or e.get("reason")),
                    "decision": display_value(e.get("decision") or "allow"),
                    "correlation_id": display_value(e.get("correlation_id")),
                }
            )
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
        with st.expander(f"Export — all {len(audit_state)} events as JSON"):
            st.json(audit_state)
