"""
streamlit_dashboard.py
=======================
Governance & Compliance Monitoring Dashboard for the Compliant FinTech Data API.

Reads directly from the same SQLite audit-log database the running API
writes to, so what you see here is the real, live audit trail -- not a
mock. Requires the API to be running (`uvicorn app.main:app`) for the
"Run Live Simulation" button and the API-status panel; the historical
views work off the database file alone even if the API is stopped.

Run with:
    streamlit run dashboard/streamlit_dashboard.py
"""
import os
import sys
import subprocess
import sqlite3
from datetime import datetime, timedelta

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)
DB_PATH = os.path.join(PROJECT_ROOT, "compliant_api.db")
API_BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8000")

st.set_page_config(page_title="API Governance Dashboard", page_icon="🛡️", layout="wide",
                    initial_sidebar_state="expanded")


# ---------------------------------------------------------------------------
def load_audit_log() -> pd.DataFrame:
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query("SELECT * FROM audit_log ORDER BY id ASC", conn)
    except Exception:
        return pd.DataFrame()
    finally:
        conn.close()
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def api_is_up() -> bool:
    try:
        r = requests.get(f"{API_BASE_URL}/health", timeout=1.5)
        return r.status_code == 200
    except requests.RequestException:
        return False


def admin_login():
    try:
        r = requests.post(f"{API_BASE_URL}/auth/login",
                           data={"username": "admin", "password": "AdminPass123!"}, timeout=3)
        if r.status_code == 200:
            return r.json()["access_token"]
    except requests.RequestException:
        pass
    return None


def verify_chain_via_api(token: str):
    try:
        r = requests.get(f"{API_BASE_URL}/api/v1/audit-logs/verify",
                          headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if r.status_code == 200:
            return r.json()
    except requests.RequestException:
        pass
    return None


def verify_chain_locally(df: pd.DataFrame):
    """Fallback integrity check computed directly from the DataFrame, using
    the identical hash-chain algorithm as app/middleware/audit_logging.py,
    so the dashboard can still show a verification result even if the API
    process isn't currently running."""
    from app.middleware.audit_logging import compute_entry_hash, canonical_timestamp
    from app.config import get_settings
    settings = get_settings()

    prev_hash = settings.audit_log_genesis_hash
    for _, row in df.iterrows():
        fields = {
            "request_id": row["request_id"], "timestamp": canonical_timestamp(row["timestamp"].to_pydatetime()),
            "username": row["username"], "role": row["role"], "method": row["method"],
            "path": row["path"], "status_code": int(row["status_code"]), "client_ip": row["client_ip"],
            "duration_ms": row["duration_ms"], "outcome": row["outcome"], "detail": row["detail"],
        }
        expected = compute_entry_hash(fields, prev_hash)
        if expected != row["entry_hash"] or row["prev_hash"] != prev_hash:
            return {"total_entries": len(df), "verified": False, "first_break_at_id": int(row["id"])}
        prev_hash = row["entry_hash"]
    return {"total_entries": len(df), "verified": True, "first_break_at_id": None}


OUTCOME_COLORS = {"SUCCESS": "#3B9B4A", "DENIED": "#D8453B", "RATE_LIMITED": "#E8A33D",
                   "ERROR": "#B00020", "CLIENT_ERROR": "#8B6DBF"}

# ---------------------------------------------------------------------------
st.sidebar.title("🛡️ Governance Dashboard")
st.sidebar.caption("Compliant FinTech Data API -- audit, access control & rate-limit monitoring")

api_up = api_is_up()
st.sidebar.markdown(f"**API status:** {'🟢 Online' if api_up else '🔴 Offline'} (`{API_BASE_URL}`)")

page = st.sidebar.radio("Navigate", ["Audit Trail Overview", "Access Control Monitor",
                                       "Rate Limiting Monitor", "Integrity Verification",
                                       "Run Live Simulation", "About This Project"])

st.sidebar.markdown("---")
if st.sidebar.button("🔄 Refresh data"):
    st.rerun()

df = load_audit_log()
if df.empty:
    st.warning("No audit log data found yet. Start the API (`uvicorn app.main:app`), seed it "
               "(`python -m scripts.seed_data`), and generate some traffic -- either normal use, "
               "`python -m scripts.simulate_traffic`, or the **Run Live Simulation** page here.")
    st.stop()

# ===========================================================================
if page == "Audit Trail Overview":
    st.title("Audit Trail Overview")
    st.caption(f"{len(df):,} logged requests, {df['timestamp'].min()} to {df['timestamp'].max()}")

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Requests", f"{len(df):,}")
    c2.metric("Success", f"{(df.outcome=='SUCCESS').sum():,}")
    c3.metric("Denied (401/403)", f"{(df.outcome=='DENIED').sum():,}")
    c4.metric("Rate Limited", f"{(df.outcome=='RATE_LIMITED').sum():,}")
    c5.metric("Unique Users", df["username"].nunique())

    st.markdown("---")
    col1, col2 = st.columns([2, 1])
    with col1:
        ts = df.set_index("timestamp").resample("10s").size().rename("requests").reset_index()
        fig = px.line(ts, x="timestamp", y="requests", title="Request Volume Over Time (10s buckets)")
        st.plotly_chart(fig, width="stretch")
    with col2:
        outcome_counts = df["outcome"].value_counts()
        fig2 = px.pie(values=outcome_counts.values, names=outcome_counts.index, title="Outcome Breakdown",
                      color=outcome_counts.index, color_discrete_map=OUTCOME_COLORS)
        st.plotly_chart(fig2, width="stretch")

    col3, col4 = st.columns(2)
    with col3:
        by_path = df["path"].value_counts().head(10).sort_values()
        fig3 = px.bar(x=by_path.values, y=by_path.index, orientation="h", title="Top 10 Endpoints by Traffic")
        fig3.update_layout(yaxis_title="", xaxis_title="Requests")
        st.plotly_chart(fig3, width="stretch")
    with col4:
        by_role = df["role"].fillna("anonymous").value_counts()
        fig4 = px.bar(x=by_role.index, y=by_role.values, title="Requests by Role", color=by_role.index)
        fig4.update_layout(showlegend=False, xaxis_title="", yaxis_title="Requests")
        st.plotly_chart(fig4, width="stretch")

    st.markdown("### Recent Log Entries")
    recent = df.sort_values("id", ascending=False).head(50)
    st.dataframe(
        recent[["timestamp", "username", "role", "method", "path", "status_code", "outcome",
                "duration_ms", "client_ip"]],
        width="stretch", height=420
    )

# ===========================================================================
elif page == "Access Control Monitor":
    st.title("Access Control (RBAC) Monitor")
    st.caption("Every DENIED outcome below is a 401 (no/invalid token) or 403 (authenticated but "
               "insufficiently privileged) response -- i.e. the access-control layer doing its job.")

    denied = df[df["outcome"] == "DENIED"]
    c1, c2, c3 = st.columns(3)
    c1.metric("Total Denials", len(denied))
    c2.metric("Distinct Users Denied", denied["username"].nunique())
    c3.metric("Denial Rate", f"{len(denied)/len(df)*100:.1f}% of all traffic")

    if len(denied) > 0:
        col1, col2 = st.columns(2)
        with col1:
            by_user = denied["username"].fillna("(no valid token)").value_counts()
            fig = px.bar(x=by_user.values, y=by_user.index, orientation="h",
                         title="Denials by User", color_discrete_sequence=["#D8453B"])
            fig.update_layout(yaxis_title="", xaxis_title="Denied requests")
            st.plotly_chart(fig, width="stretch")
        with col2:
            by_endpoint = denied["path"].value_counts()
            fig2 = px.bar(x=by_endpoint.values, y=by_endpoint.index, orientation="h",
                          title="Denials by Endpoint", color_discrete_sequence=["#D8453B"])
            fig2.update_layout(yaxis_title="", xaxis_title="Denied requests")
            st.plotly_chart(fig2, width="stretch")

        st.markdown("### Denial Log")
        st.dataframe(
            denied[["timestamp", "username", "role", "method", "path", "status_code", "client_ip"]]
            .sort_values("timestamp", ascending=False),
            width="stretch", height=350
        )
    else:
        st.info("No access-control denials recorded yet.")

# ===========================================================================
elif page == "Rate Limiting Monitor":
    st.title("Rate Limiting Monitor")
    st.caption("Role-tiered limits: VIEWER 30/min, ANALYST 60/min, AUDITOR 100/min, ADMIN 200/min "
               "(rolling 60-second sliding window), plus a 10/min IP-based limit on login attempts.")

    limited = df[df["outcome"] == "RATE_LIMITED"]
    c1, c2 = st.columns(2)
    c1.metric("Total Rate-Limit Rejections", len(limited))
    c2.metric("As % of All Traffic", f"{len(limited)/len(df)*100:.2f}%")

    if len(limited) > 0:
        col1, col2 = st.columns(2)
        with col1:
            by_role = limited["role"].fillna("(login attempt)").value_counts()
            fig = px.bar(x=by_role.index, y=by_role.values, title="Rate-Limit Rejections by Role",
                        color_discrete_sequence=["#E8A33D"])
            fig.update_layout(xaxis_title="", yaxis_title="Rejections")
            st.plotly_chart(fig, width="stretch")
        with col2:
            limited_ts = limited.set_index("timestamp").resample("10s").size().rename("rejections").reset_index()
            fig2 = px.bar(limited_ts, x="timestamp", y="rejections", title="Rate-Limit Rejections Over Time")
            st.plotly_chart(fig2, width="stretch")

        st.markdown("### Rejection Log")
        st.dataframe(
            limited[["timestamp", "username", "role", "path", "detail", "client_ip"]]
            .sort_values("timestamp", ascending=False),
            width="stretch", height=350
        )
    else:
        st.info("No rate-limit rejections recorded yet -- try the 'Run Live Simulation' page, "
                "which includes a deliberate burst scenario.")

# ===========================================================================
elif page == "Integrity Verification":
    st.title("Audit Log Integrity Verification")
    st.markdown("""
    Every audit log row is hash-chained: `entry_hash = SHA256(canonical_fields || previous_row's_hash)`.
    Altering *any* historical field in *any* row breaks the chain from that point forward.
    This check recomputes the entire chain from the genesis hash and confirms every row matches.
    """)

    if api_up:
        token = admin_login()
        result = verify_chain_via_api(token) if token else None
        source = "live API"
    else:
        result = None
        source = None

    if result is None:
        result = verify_chain_locally(df)
        source = "local recomputation (API offline)"

    st.caption(f"Verification source: {source}")

    if result["verified"]:
        st.success(f"✅ Chain verified intact across all {result['total_entries']:,} entries. "
                   "No tampering detected.")
    else:
        st.error(f"⚠️ Chain integrity FAILED at entry id={result['first_break_at_id']}. "
                 "This entry (or one before it) does not match its expected hash -- indicating "
                 "the stored data was altered after being written.")

    st.markdown("### Try it yourself: tamper with an entry and re-verify")
    st.caption("This directly edits the SQLite database to simulate an attacker or a rogue insider "
               "editing a historical log row, then re-runs verification to show detection.")
    tamper_id = st.number_input("Entry ID to tamper with", min_value=1,
                                  max_value=int(df["id"].max()), value=1, step=1)
    if st.button("💥 Tamper with this entry (set status_code to 999)"):
        conn = sqlite3.connect(DB_PATH)
        conn.execute("UPDATE audit_log SET status_code = 999 WHERE id = ?", (int(tamper_id),))
        conn.commit()
        conn.close()
        st.warning(f"Entry {tamper_id} has been altered directly in the database. Refresh or "
                   "revisit this page to see verification now fail.")
        st.rerun()

# ===========================================================================
elif page == "Run Live Simulation":
    st.title("Run a Live Traffic Simulation")
    st.caption("Fires real requests, from all four demo roles, at the running API -- including "
               "deliberate policy violations -- and records everything in the real audit log.")

    if not api_up:
        st.error(f"API is not reachable at {API_BASE_URL}. Start it with `uvicorn app.main:app` "
                 "in a separate terminal, then reload this page.")
    else:
        n_requests = st.slider("Number of normal-activity requests", 10, 100, 30)
        include_violations = st.checkbox("Include violation scenarios (RBAC denials, rate-limit burst, "
                                          "brute-force login attempt)", value=True)
        if st.button("▶️ Run Simulation", type="primary"):
            cmd = [sys.executable, "-m", "scripts.simulate_traffic",
                   "--base-url", API_BASE_URL, "--rounds-count", str(n_requests)]
            if not include_violations:
                cmd.append("--skip-violations")

            with st.spinner("Simulation running..."):
                result = subprocess.run(cmd, cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=120)

            st.code(result.stdout or result.stderr, language="text")
            st.success("Simulation complete. Visit 'Audit Trail Overview' to see the results.")

# ===========================================================================
elif page == "About This Project":
    st.title("About This Project")
    st.markdown("""
This dashboard is the monitoring component of a **compliant REST API demo** implementing the
governance patterns discussed in the 2022 paper on leadership practices in overseeing data
engineers within regulated FinTech environments: role-based access control, tamper-evident audit
logging, and role-tiered rate limiting, applied to a small accounts/transactions API.

**Three controls, each independently verifiable on this dashboard:**

1. **Role-Based Access Control** -- four roles (VIEWER, ANALYST, AUDITOR, ADMIN) with distinct,
   deliberately asymmetric permissions per endpoint (e.g. AUDITOR can read everything but write
   nothing, preserving independence). See *Access Control Monitor*.
2. **Tamper-evident audit logging** -- every request, successful or not, is recorded in a
   SHA-256 hash-chained log. See *Integrity Verification*, including a live tamper-and-detect demo.
3. **Role-tiered rate limiting** -- a sliding-window limiter with a different ceiling per role,
   plus a separate IP-based limiter on the login endpoint against brute-force attempts.
   See *Rate Limiting Monitor*.

**Repository structure:**
```
compliant_api_project/
├── app/                      # FastAPI application (routers, RBAC, rate limiting, audit middleware)
├── scripts/seed_data.py       # creates demo users + sample accounts
├── scripts/simulate_traffic.py  # realistic multi-role traffic generator
├── dashboard/streamlit_dashboard.py   # this dashboard
├── tests/                     # 30 pytest tests covering auth, RBAC, rate limits, audit integrity
├── Dockerfile / docker-compose.yml
└── README.md
```
""")
