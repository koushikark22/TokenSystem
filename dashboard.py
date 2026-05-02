import base64
import html
import json
from pathlib import Path

import pandas as pd
import requests
import streamlit as st

TOKEN_SERVICE_URL = "http://127.0.0.1:8000"
INTERNAL_API_URL  = "http://127.0.0.1:9000"
STATE_DIR         = Path(".state")
DEVICE_ID         = "linux-laptop-001"
USER_ID           = "developer01"
AGENT_ID          = "agent-gpu-planner-dev"

# ── helpers ────────────────────────────────────────────────────────────────
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
        return r.ok, r.json() if r.headers.get("content-type","").startswith("application/json") else {}
    except Exception as e:
        return False, {"error": str(e)}

def decode_jwt_payload(token: str):
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return {}
        payload = parts[1]
        padding = "=" * ((4 - len(payload) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(payload + padding).decode("utf-8"))
    except Exception:
        return {}

def display_value(value):
    if value is None: return "—"
    if isinstance(value, list): return ", ".join(str(v) for v in value)
    if isinstance(value, dict): return json.dumps(value, sort_keys=True)
    return str(value)

def short_text(value: str, max_len: int = 22) -> str:
    text = str(value or "—")
    return text if len(text) <= max_len else f"{text[:max_len-3]}…"

# ── page config ────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="Token Service — Security Demo",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── inject fonts + master CSS ──────────────────────────────────────────────
st.markdown(
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&'
    'family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">',
    unsafe_allow_html=True,
)

st.markdown("""
<style>
/* ── Base ─────────────────────────────────────────────── */
html, body, [class*="css"] {
    font-family: 'DM Sans', sans-serif !important;
}
code, pre, .mono { font-family: 'DM Mono', monospace !important; }

.block-container { padding-top: 1.2rem; padding-bottom: 2rem; max-width: 1440px; }
#MainMenu { visibility: hidden; }
footer    { visibility: hidden; }

/* ── Hero ─────────────────────────────────────────────── */
.hero {
    background: linear-gradient(130deg, #0d1117 0%, #0f2744 55%, #0d2e1a 100%);
    border-radius: 20px;
    padding: 1.6rem 2rem 1.4rem;
    margin-bottom: 1.25rem;
    box-shadow: 0 20px 48px rgba(0,0,0,.22);
    position: relative;
    overflow: hidden;
}
.hero::after {
    content: "";
    position: absolute;
    inset: 0;
    background: radial-gradient(ellipse 60% 80% at 85% 40%, rgba(37,99,235,.13) 0%, transparent 70%);
    pointer-events: none;
}
.hero-eyebrow { font-size:.75rem; letter-spacing:.16em; text-transform:uppercase;
    color: #60a5fa; font-weight:600; margin-bottom:.45rem; }
.hero-title { font-size:2rem; font-weight:760; color:#f8fafc; letter-spacing:-.03em;
    line-height:1.15; margin-bottom:.5rem; }
.hero-title span { color:#60a5fa; }
.hero-sub { font-size:.93rem; color:#94a3b8; max-width:860px; line-height:1.55; }
.hero-pills { margin-top:1rem; display:flex; gap:.4rem; flex-wrap:wrap; }
.hero-pill {
    background: rgba(96,165,250,.12);
    border: 1px solid rgba(96,165,250,.28);
    color: #93c5fd;
    border-radius:999px; padding:.22rem .72rem; font-size:.78rem; font-weight:500;
}

/* ── Status cards ─────────────────────────────────────── */
.sc-grid {
    display: grid;
    grid-template-columns: repeat(6, minmax(0,1fr));
    gap: .75rem; margin-bottom: 1.25rem;
}
.sc {
    background:#fff; border:1px solid #e2e8f0; border-radius:18px;
    padding:1rem 1rem .9rem; box-shadow:0 4px 16px rgba(15,23,42,.06);
    transition: box-shadow .2s;
}
.sc:hover { box-shadow:0 8px 28px rgba(15,23,42,.11); }
.sc-icon { font-size:1.5rem; margin-bottom:.4rem; }
.sc-label { font-size:.72rem; text-transform:uppercase; letter-spacing:.06em;
    color:#94a3b8; font-weight:600; }
.sc-value { font-size:1.1rem; font-weight:700; color:#0f172a;
    white-space:nowrap; overflow:hidden; text-overflow:ellipsis;
    margin:.18rem 0 .45rem; }
.sc-detail { font-size:.73rem; color:#94a3b8; margin-top:.3rem; }

/* ── Badges ───────────────────────────────────────────── */
.badge { padding:.2rem .62rem; border-radius:999px; font-size:.76rem;
    font-weight:600; display:inline-flex; align-items:center; gap:.3rem; }
.badge-green  { background:#dcfce7; color:#15803d; border:1px solid #bbf7d0; }
.badge-blue   { background:#dbeafe; color:#1d4ed8; border:1px solid #bfdbfe; }
.badge-yellow { background:#fef3c7; color:#b45309; border:1px solid #fde68a; }
.badge-red    { background:#fee2e2; color:#b91c1c; border:1px solid #fecaca; }
.badge-slate  { background:#f1f5f9; color:#475569; border:1px solid #e2e8f0; }

/* ── Section card ─────────────────────────────────────── */
.scard { background:#fff; border:1px solid #e2e8f0; border-radius:18px;
    padding:1.15rem 1.3rem; box-shadow:0 4px 14px rgba(15,23,42,.045); margin-bottom:1rem; }
.scard-title { font-size:1.1rem; font-weight:700; color:#0f172a; margin-bottom:.2rem; }
.scard-cap { font-size:.85rem; color:#64748b; margin-bottom:.9rem; }

/* ── Flow diagram ─────────────────────────────────────── */
.flow-wrap { display:flex; align-items:stretch; gap:0; overflow-x:auto; padding-bottom:.25rem; }
.flow-node {
    flex: 1; min-width: 130px;
    background: #f8fafc; border: 1.5px solid #e2e8f0;
    border-radius: 14px; padding: .85rem .85rem .75rem;
    position: relative;
}
.flow-node + .flow-node { margin-left: 2rem; }
.flow-node + .flow-node::before {
    content: "→";
    position: absolute; left: -1.6rem; top: 50%; transform: translateY(-50%);
    font-size: 1.15rem; color: #94a3b8; font-weight: 700;
}
.fn-num { font-size:.7rem; font-weight:700; letter-spacing:.08em; text-transform:uppercase;
    color:#94a3b8; margin-bottom:.35rem; }
.fn-icon { font-size:1.4rem; margin-bottom:.3rem; }
.fn-label { font-size:.88rem; font-weight:700; color:#0f172a; margin-bottom:.25rem; }
.fn-detail { font-size:.75rem; color:#64748b; line-height:1.35; }

/* ── Claim row ────────────────────────────────────────── */
.claim-grid { display:grid; grid-template-columns:160px 1fr; gap:.5rem .75rem; }
.claim-key { font-size:.78rem; text-transform:uppercase; letter-spacing:.05em;
    color:#94a3b8; font-weight:600; padding-top:.15rem; }
.claim-val { font-family:'DM Mono',monospace; font-size:.82rem;
    background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px;
    padding:.25rem .6rem; color:#0f172a; word-break:break-all; }
.claim-meaning { font-size:.76rem; color:#64748b; padding-top:.05rem; }

/* ── Audit event row ──────────────────────────────────── */
.audit-row {
    display:grid;
    grid-template-columns: 6px 140px 200px 100px 120px 1fr 80px;
    align-items:center; gap:.5rem;
    padding:.55rem .75rem; border-radius:10px; margin-bottom:.3rem;
    background:#fff; border:1px solid #f1f5f9;
}
.audit-row:hover { background:#f8fafc; }
.audit-bar { border-radius:3px; height:36px; width:6px; }
.audit-ts { font-family:'DM Mono',monospace; font-size:.72rem; color:#64748b; }
.audit-event { font-size:.8rem; font-weight:600; color:#0f172a; }
.audit-cell { font-size:.78rem; color:#475569; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
.audit-hdr {
    display:grid;
    grid-template-columns: 6px 140px 200px 100px 120px 1fr 80px;
    gap:.5rem; padding:.4rem .75rem;
    font-size:.7rem; text-transform:uppercase; letter-spacing:.07em;
    color:#94a3b8; font-weight:700; border-bottom:1px solid #e2e8f0; margin-bottom:.4rem;
}

/* ── GPU metrics ──────────────────────────────────────── */
.gpu-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:.75rem; margin:.85rem 0; }
.gpu-card { background:#f8fafc; border:1.5px solid #e2e8f0; border-radius:14px; padding:1rem 1.1rem; }
.gpu-label { font-size:.75rem; text-transform:uppercase; letter-spacing:.06em; color:#64748b; font-weight:600; }
.gpu-val { font-size:1.8rem; font-weight:780; color:#0f172a; margin:.25rem 0; line-height:1; }
.gpu-sub { font-size:.78rem; color:#64748b; }

/* ── Empty state ──────────────────────────────────────── */
.empty-state { text-align:center; padding:2.5rem 1rem; color:#94a3b8; }
.empty-icon { font-size:2.2rem; margin-bottom:.6rem; }
.empty-title { font-size:.95rem; font-weight:600; color:#64748b; margin-bottom:.3rem; }
.empty-cmd { font-family:'DM Mono',monospace; font-size:.82rem;
    background:#f1f5f9; border-radius:8px; padding:.35rem .85rem;
    display:inline-block; margin-top:.5rem; color:#334155; }

/* ── Callout ──────────────────────────────────────────── */
.callout-blue { border-left:4px solid #3b82f6; background:#eff6ff;
    border-radius:10px; padding:.75rem 1rem; color:#1e40af; font-size:.88rem; margin:.75rem 0; }
.callout-green { border-left:4px solid #22c55e; background:#f0fdf4;
    border-radius:10px; padding:.75rem 1rem; color:#15803d; font-size:.88rem; margin:.75rem 0; }

/* ── Sidebar ──────────────────────────────────────────── */
section[data-testid="stSidebar"] { background:#0d1117 !important; }
section[data-testid="stSidebar"] * { color:#e2e8f0 !important; }
section[data-testid="stSidebar"] .stButton > button {
    background: rgba(255,255,255,.06) !important;
    border: 1px solid rgba(255,255,255,.12) !important;
    border-radius: 10px !important; color: #e2e8f0 !important;
    font-size:.85rem !important; width:100%;
    transition: background .15s;
}
section[data-testid="stSidebar"] .stButton > button:hover {
    background: rgba(96,165,250,.18) !important;
    border-color: rgba(96,165,250,.35) !important;
}
.sb-group { font-size:.7rem; text-transform:uppercase; letter-spacing:.1em;
    color:#475569 !important; font-weight:700; margin:.9rem 0 .4rem; padding-left:.1rem; }

/* ── Tabs ─────────────────────────────────────────────── */
div[data-testid="stTabs"] button[data-baseweb="tab"] {
    font-family:'DM Sans',sans-serif !important;
    font-weight:600 !important; font-size:.88rem !important;
}

/* ── Responsive ───────────────────────────────────────── */
@media (max-width:1200px) {
    .sc-grid { grid-template-columns:repeat(3,minmax(0,1fr)); }
    .audit-row, .audit-hdr { grid-template-columns:6px 120px 1fr 80px 80px; }
    .audit-row > *:nth-child(4), .audit-row > *:nth-child(5),
    .audit-hdr > *:nth-child(4), .audit-hdr > *:nth-child(5) { display:none; }
}
</style>
""", unsafe_allow_html=True)

# ── load state ─────────────────────────────────────────────────────────────
cli_tokens      = load_json(STATE_DIR / "devctl_tokens.json", {})
audit_state     = load_json(STATE_DIR / "audit.json", [])
agents_state    = load_json(STATE_DIR / "agents.json", {})
device_registry = load_json(Path("device_registry.json"), {})
ts_ok, ts_health  = health(TOKEN_SERVICE_URL)
api_ok, api_health = health(INTERNAL_API_URL)
agent_record    = agents_state.get(AGENT_ID, {})
gpu_quota       = agent_record.get("gpu_quota_max_jobs", "—")

# ── badge helper ───────────────────────────────────────────────────────────
def badge(value: str, size="normal"):
    raw = str(value or "—"); low = raw.lower(); s = html.escape(raw)
    if any(k in low for k in ["ok","active","allow","allowed","healthy","green"]):
        cls = "badge-green"; dot = "●"
    elif any(k in low for k in ["step_up","step-up","pending","mfa","blue"]):
        cls = "badge-blue";  dot = "●"
    elif any(k in low for k in ["warn","yellow","agent"]):
        cls = "badge-yellow"; dot = "●"
    elif any(k in low for k in ["err","fail","revok","deny","reject","red"]):
        cls = "badge-red"; dot = "●"
    else:
        cls = "badge-slate"; dot = "○"
    return f"<span class='badge {cls}'>{dot} {s}</span>"

def audit_bar_color(event: str) -> str:
    e = event.lower()
    if "fail" in e or "revok" in e or "detect" in e or "deny" in e: return "#ef4444"
    if "stepup" in e or "step_up" in e or "pim" in e: return "#f59e0b"
    if "agent" in e: return "#8b5cf6"
    if "gpu" in e: return "#06b6d4"
    if "refresh" in e: return "#3b82f6"
    if "token" in e: return "#22c55e"
    return "#94a3b8"

def empty_state(icon, title, cmd):
    return f"""
    <div class='empty-state'>
        <div class='empty-icon'>{icon}</div>
        <div class='empty-title'>{html.escape(title)}</div>
        <div class='empty-cmd'>{html.escape(cmd)}</div>
    </div>"""

# ══════════════════════════════════════════════════════════════════════════
# HERO
# ══════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class='hero'>
    <div class='hero-eyebrow'>Enterprise IAM · Proof-of-Concept</div>
    <div class='hero-title'>Centralized <span>Token Service</span> Demo</div>
    <div class='hero-sub'>
        Short-lived JWTs · Refresh rotation · OBO delegation · Sender-constrained tokens ·
        Agent identity · GPU governance · Full audit trail
    </div>
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
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════
# STATUS CARDS
# ══════════════════════════════════════════════════════════════════════════
ts_status  = "healthy" if ts_ok  else "error"
api_status = "healthy" if api_ok else "error"

def sc(icon, label, value, status, detail=""):
    s = html.escape(str(status)); v = html.escape(short_text(str(value),18))
    full_v = html.escape(str(value)); d = html.escape(detail)
    return f"""
    <div class='sc'>
        <div class='sc-icon'>{icon}</div>
        <div class='sc-label'>{html.escape(label)}</div>
        <div class='sc-value' title='{full_v}'>{v}</div>
        <div>{badge(s)}</div>
        <div class='sc-detail'>{d}</div>
    </div>"""

st.markdown(
    "<div class='sc-grid'>"
    + sc("🔐", "Token Service",  "Healthy" if ts_ok  else "Error", ts_status,  TOKEN_SERVICE_URL)
    + sc("🛡", "Internal API",   "Healthy" if api_ok else "Error", api_status, INTERNAL_API_URL)
    + sc("💻", "Device",         DEVICE_ID,  "active",    "Linux endpoint")
    + sc("👤", "User",           USER_ID,    "active",    "Developer principal")
    + sc("🤖", "Agent",          AGENT_ID,   agent_record.get("status","unknown"), "Non-human identity")
    + sc("⚡", "GPU Quota",      f"{gpu_quota} job(s)", "allowed" if gpu_quota != "—" else "unknown", "Per-agent cap")
    + "</div>",
    unsafe_allow_html=True,
)

# ══════════════════════════════════════════════════════════════════════════
# ARCHITECTURE FLOW
# ══════════════════════════════════════════════════════════════════════════
def flow_node(num, icon, label, detail):
    return f"""
    <div class='flow-node'>
        <div class='fn-num'>Step {num}</div>
        <div class='fn-icon'>{icon}</div>
        <div class='fn-label'>{html.escape(label)}</div>
        <div class='fn-detail'>{html.escape(detail)}</div>
    </div>"""

st.markdown(f"""
<div class='scard'>
    <div class='scard-title'>Architecture Flow</div>
    <div class='scard-cap'>How the demo explains enterprise token governance end to end.</div>
    <div class='flow-wrap'>
        {flow_node(1,"🖥","Linux CLI","devctl.py — device flow login, token exchange, GPU submit")}
        {flow_node(2,"🏛","Entra / IdP","Production source of user identity, MFA and Conditional Access")}
        {flow_node(3,"🔐","Token Service","Issues short-lived JWTs, handles refresh, OBO, step-up and agent tokens")}
        {flow_node(4,"🔑","PKI / cnf","Binds tokens to cert thumbprint (cnf.x5t#S256) — sender-constrained proof")}
        {flow_node(5,"🛡","Internal / GPU API","Validates sig, audience, scope, sender proof and GPU quota per-request")}
        {flow_node(6,"📋","Audit / SIEM","Immutable record of every auth, token, OBO, agent and GPU access event")}
    </div>
</div>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════
# SIDEBAR
# ══════════════════════════════════════════════════════════════════════════
with st.sidebar:
    st.markdown("## 🔐 Demo Controls")
    st.markdown(
        "<div style='font-size:.82rem;color:#64748b;line-height:1.45;margin-bottom:.5rem;'>"
        "Run actual flows from a terminal. These buttons are visual placeholders "
        "— the real enforcement is in the token service and API."
        "</div>", unsafe_allow_html=True
    )
    st.divider()

    st.markdown("<div class='sb-group'>Identity / Auth</div>", unsafe_allow_html=True)
    st.button("🔑  Bootstrap Device Registry", use_container_width=True)
    st.button("👤  Login (device flow)",        use_container_width=True)
    st.button("🔄  Refresh Token",              use_container_width=True)

    st.markdown("<div class='sb-group'>Agent / NHI</div>", unsafe_allow_html=True)
    st.button("🤖  Register Agent",    use_container_width=True)
    st.button("💬  Agent PR Comment",  use_container_width=True)
    st.button("⚡  Agent GPU Submit",  use_container_width=True)

    st.markdown("<div class='sb-group'>Privileged Ops</div>", unsafe_allow_html=True)
    st.button("🚀  Deploy Prod (step-up)",   use_container_width=True)
    st.button("📊  GPU Quota Update",         use_container_width=True)

    st.markdown("<div class='sb-group'>Dashboard</div>", unsafe_allow_html=True)
    if st.button("🔃  Refresh Audit Log", use_container_width=True):
        audit_state = load_json(STATE_DIR / "audit.json", [])
        st.success("Audit refreshed")

    st.divider()
    st.markdown(
        "<div style='font-size:.78rem;color:#475569;line-height:1.5;'>"
        "💡 <b>Interview tip:</b><br>"
        "Overview → Token Claims → Agent / NHI → Audit Timeline"
        "</div>", unsafe_allow_html=True
    )

# ══════════════════════════════════════════════════════════════════════════
# TABS
# ══════════════════════════════════════════════════════════════════════════
t_overview, t_trust, t_claims, t_agent, t_gpu, t_audit = st.tabs([
    "🏠 Overview", "💻 Device Trust", "🔎 Token Claims",
    "🤖 Agent / NHI", "⚡ GPU Jobs", "📋 Audit Timeline",
])

# ── OVERVIEW ───────────────────────────────────────────────────────────────
with t_overview:
    st.markdown("""
    <div class='callout-blue'>
    <b>Panel explanation:</b> This dashboard is the visualization layer only.
    All security controls are enforced by the token service, CLI, internal API,
    certificate proof, scopes, and audit flow — not by the dashboard.
    </div>""", unsafe_allow_html=True)

    left, right = st.columns([1.1, 1])
    with left:
        st.subheader("Live Service Health")
        ts_col, api_col = st.columns(2)
        with ts_col:
            st.metric("Token Service", "● Online" if ts_ok else "● Offline",
                      delta="port 8000", delta_color="off")
        with api_col:
            st.metric("Internal API",  "● Online" if api_ok else "● Offline",
                      delta="port 9000", delta_color="off")
        with st.expander("Raw health JSON"):
            st.json({"token_service": ts_health, "internal_api": api_health})

    with right:
        st.subheader("Quick-Start Script")
        st.code("""# Terminal 1
python token_service.py

# Terminal 2
python internal_api.py

# Terminal 3 — run flows
python devctl.py login --auto
python devctl.py obo-build
python devctl.py gpu-submit
python devctl.py register-agent
python devctl.py agent-gpu-submit
python devctl.py audit

# Terminal 4 — dashboard
streamlit run dashboard.py""", language="bash")

# ── DEVICE TRUST ───────────────────────────────────────────────────────────
with t_trust:
    st.subheader("Device Trust Snapshot")
    st.caption("Local demo device registry. In production: enterprise MDM, managed certs, or workload identity.")

    devices = device_registry.get("devices", [])
    if devices:
        for dev in devices:
            cols = st.columns([1.2, 1, 1, 1, 1, 1.4])
            checks = {
                "Managed":     dev.get("managed"),
                "EDR Healthy": dev.get("edr_healthy"),
                "Encrypted":   dev.get("disk_encrypted"),
            }
            labels   = [dev.get("device_id","?"), dev.get("owner","?"), dev.get("os","?"),
                        dev.get("risk","?"), dev.get("status","?"), ""]
            for i, (col, lbl) in enumerate(zip(cols, labels)):
                with col:
                    if i == 0: st.markdown(f"**{lbl}**")
                    elif i == 5:
                        for chk_label, chk_val in checks.items():
                            icon = "✅" if chk_val else "❌"
                            st.markdown(f"{icon} {chk_label}")
                    else: st.markdown(lbl)
        st.divider()
        with st.expander("Raw device_registry.json"):
            st.json(device_registry)
    else:
        st.markdown(empty_state("💻", "No device registry found",
            "python devctl.py bootstrap-device-registry"), unsafe_allow_html=True)

# ── TOKEN CLAIMS ───────────────────────────────────────────────────────────
with t_claims:
    st.subheader("Decoded Token Claims")
    token = cli_tokens.get("access_token","")
    if token:
        claims = decode_jwt_payload(token)
        claim_defs = [
            ("sub",          "Subject identity",          claims.get("sub")),
            ("actor_type",   "Human vs agent",            claims.get("actor_type")),
            ("device_id",    "Endpoint / device context", claims.get("device_id")),
            ("agent_id",     "Non-human identity",        claims.get("agent_id")),
            ("scope",        "Least-privilege permission",claims.get("scope")),
            ("aud",          "Target API / resource",     claims.get("aud")),
            ("cnf",          "Certificate-bound proof",   claims.get("cnf")),
            ("auth_strength","MFA / step-up strength",    claims.get("auth_strength")),
            ("pim",          "Privileged activation",     claims.get("pim")),
            ("approval_id",  "Step-up approval evidence", claims.get("approval_id")),
            ("exp",          "Token expiry (epoch)",      claims.get("exp")),
            ("jti",          "Unique token ID",           claims.get("jti")),
        ]

        rows_html = ""
        for key, meaning, val in claim_defs:
            v = display_value(val); present = val is not None
            val_class = "claim-val" if present else "claim-val" 
            v_display = html.escape(v) if present else "<span style='color:#94a3b8'>not present</span>"
            rows_html += f"""
            <div style='display:contents'>
                <div class='claim-key'>{html.escape(key)}</div>
                <div>
                    <div class='{val_class}'>{v_display}</div>
                    <div class='claim-meaning'>{html.escape(meaning)}</div>
                </div>
            </div>"""

        st.markdown(f"<div class='claim-grid'>{rows_html}</div>", unsafe_allow_html=True)

        with st.expander("Full raw claims JSON"):
            st.json(claims)
    else:
        st.markdown(empty_state("🔑", "No access token found yet",
            "python devctl.py login --auto"), unsafe_allow_html=True)

# ── AGENT / NHI ────────────────────────────────────────────────────────────
with t_agent:
    st.subheader("Agent / Non-Human Identity Registry")
    st.caption("Each agent has an explicit ID, owner, environment, scopes, and GPU quota — never anonymous automation.")

    if agents_state:
        for aid, item in agents_state.items():
            status = item.get("status","unknown")
            st.markdown(f"""
            <div class='scard' style='margin-bottom:.75rem;'>
                <div style='display:flex;justify-content:space-between;align-items:flex-start;'>
                    <div>
                        <div style='font-size:1rem;font-weight:700;color:#0f172a;margin-bottom:.2rem;'>
                            🤖 {html.escape(aid)}
                        </div>
                        <div style='font-size:.82rem;color:#64748b;'>
                            Owner: <b>{html.escape(item.get("agent_owner","?"))}</b> ·
                            Env: <b>{html.escape(item.get("environment","?"))}</b> ·
                            GPU quota: <b>{item.get("gpu_quota_max_jobs","?")}</b> job(s)
                        </div>
                    </div>
                    <div>{badge(status)}</div>
                </div>
                <div style='margin-top:.65rem;font-size:.8rem;'>
                    <span style='color:#94a3b8;font-weight:600;text-transform:uppercase;
                        font-size:.7rem;letter-spacing:.05em;'>Allowed Scopes</span><br>
                    <span style='font-family:"DM Mono",monospace;font-size:.81rem;color:#334155;'>
                        {html.escape(", ".join(item.get("allowed_scopes",[])))}
                    </span>
                </div>
            </div>""", unsafe_allow_html=True)
        with st.expander("Raw agents JSON"):
            st.json(agents_state)
    else:
        st.markdown(empty_state("🤖", "No agents registered yet",
            "python devctl.py register-agent"), unsafe_allow_html=True)

# ── GPU JOBS ───────────────────────────────────────────────────────────────
with t_gpu:
    st.subheader("GPU Governance Overview")

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown(f"""<div class='gpu-card'>
            <div class='gpu-label'>Agent GPU Quota</div>
            <div class='gpu-val'>{gpu_quota}</div>
            <div class='gpu-sub'>max concurrent jobs</div>
        </div>""", unsafe_allow_html=True)
    with col2:
        user_quota = 2
        st.markdown(f"""<div class='gpu-card'>
            <div class='gpu-label'>Developer Quota</div>
            <div class='gpu-val'>{user_quota}</div>
            <div class='gpu-sub'>max concurrent jobs</div>
        </div>""", unsafe_allow_html=True)
    with col3:
        gpu_events = [e for e in audit_state if "gpu" in str(e.get("event_type","")).lower()]
        st.markdown(f"""<div class='gpu-card'>
            <div class='gpu-label'>GPU Events (audit)</div>
            <div class='gpu-val'>{len(gpu_events)}</div>
            <div class='gpu-sub'>total recorded actions</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("""
    <div class='callout-green' style='margin-top:.85rem;'>
    <b>Governance controls active:</b>
    GPU job submission requires <code>gpu.job.submit</code> scope via OBO exchange ·
    Quota updates require <b>step-up token</b> with <code>pim=true</code> and <code>approval_id</code> ·
    Agent GPU access is bounded by registered <code>gpu_quota_max_jobs</code>
    </div>""", unsafe_allow_html=True)

    st.markdown("**GPU control-plane integration (production roadmap)**")
    roadmap = [
        ("Kubernetes admission webhook", "Validate GPU token claims before pod scheduling"),
        ("Run:ai / NVIDIA GPU Operator", "Enforce quota at workload runtime layer"),
        ("Step-up for quota changes",    "PIM-gated approval required per gpu.quota.update"),
        ("Per-actor rate limiting",       "Sliding window per user:, device:, agent:, scope:"),
        ("GPU-hours reconciliation",      "Audit log cross-referenced with actual GPU usage"),
    ]
    for title, desc in roadmap:
        st.markdown(f"- **{title}** — {desc}")

# ── AUDIT TIMELINE ─────────────────────────────────────────────────────────
with t_audit:
    st.subheader("Audit Timeline")
    st.caption("Every auth, token issuance, OBO, refresh, step-up, agent, and GPU event — in order.")

    if not audit_state:
        st.markdown(empty_state("📋", "No audit events yet",
            "python devctl.py audit"), unsafe_allow_html=True)
    else:
        # Summary counts
        event_types = {}
        for e in audit_state:
            et = e.get("event_type", "unknown")
            event_types[et] = event_types.get(et, 0) + 1

        count_cols = st.columns(min(len(event_types), 5))
        for i, (et, cnt) in enumerate(list(event_types.items())[:5]):
            with count_cols[i % len(count_cols)]:
                st.metric(et.replace("_"," ").title(), cnt)

        st.markdown("<div style='margin-top:.75rem;'></div>", unsafe_allow_html=True)

        # Column headers
        st.markdown("""
        <div class='audit-hdr'>
            <div></div>
            <div>Timestamp</div>
            <div>Event Type</div>
            <div>Actor Type</div>
            <div>User / Agent</div>
            <div>Scope / Detail</div>
            <div>Decision</div>
        </div>""", unsafe_allow_html=True)

        for e in reversed(audit_state[-120:]):
            et       = str(e.get("event_type",""))
            ts_raw   = e.get("timestamp","")
            ts_disp  = str(ts_raw)[:16].replace("T"," ") if ts_raw else "—"
            actor    = display_value(e.get("actor_type"))
            user     = display_value(e.get("user") or e.get("sub"))
            agent    = display_value(e.get("agent_id"))
            identity = agent if agent != "—" else user
            scope    = display_value(e.get("scope") or e.get("scopes") or e.get("reason",""))
            decision = display_value(e.get("decision","allow"))
            bar_col  = audit_bar_color(et)

            st.markdown(f"""
            <div class='audit-row'>
                <div class='audit-bar' style='background:{bar_col};'></div>
                <div class='audit-ts'>{html.escape(ts_disp)}</div>
                <div class='audit-event'>{html.escape(et.replace("_"," "))}</div>
                <div class='audit-cell'>{badge(actor)}</div>
                <div class='audit-cell' title='{html.escape(identity)}'>{html.escape(short_text(identity,18))}</div>
                <div class='audit-cell' title='{html.escape(scope)}'>{html.escape(short_text(scope,42))}</div>
                <div>{badge(decision)}</div>
            </div>""", unsafe_allow_html=True)

        with st.expander(f"Export — all {len(audit_state)} events as JSON"):
            st.json(audit_state)
