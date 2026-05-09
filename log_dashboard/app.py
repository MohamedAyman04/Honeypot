"""
Level 2 ICS Honeypot — Unified Log Dashboard
=============================================
Streamlit dashboard reading from InfluxDB.  Mirrors the Level 3 :8501
dashboard but surfaces OT/SCADA data: pipeline metrics, ML alerts,
MITRE ATT&CK mapping, and the full correlated attack narrative.

Run:  streamlit run app.py --server.port 8502
"""

import os
from datetime import datetime, timezone

import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st

# ── Optional InfluxDB client ─────────────────────────────────────────────────
try:
    from influxdb_client import InfluxDBClient
    _HAS_INFLUX = True
except ImportError:
    _HAS_INFLUX = False

# ── Config ───────────────────────────────────────────────────────────────────
INFLUX_URL    = os.getenv("INFLUX_URL",    "http://localhost:8086")
INFLUX_TOKEN  = os.getenv("INFLUX_TOKEN",  "supersecrettoken")
INFLUX_ORG    = os.getenv("INFLUX_ORG",    "my_refinery")
INFLUX_BUCKET = os.getenv("INFLUX_BUCKET", "sensor_logs")
TIME_RANGE    = os.getenv("DASHBOARD_RANGE", "-6h")

st.set_page_config(
    page_title="Level 2 ICS Honeypot — Log Dashboard",
    page_icon="🏭",
    layout="wide",
)

# ── Helpers ──────────────────────────────────────────────────────────────────
@st.cache_resource
def get_client():
    if not _HAS_INFLUX:
        return None
    try:
        return InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
    except Exception:
        return None


def query(flux: str) -> pd.DataFrame:
    client = get_client()
    if client is None:
        return pd.DataFrame()
    try:
        return client.query_api().query_data_frame(flux)
    except Exception as exc:
        st.warning(f"InfluxDB query error: {exc}")
        return pd.DataFrame()


def _clean(df: pd.DataFrame) -> pd.DataFrame:
    if df.empty:
        return df
    drop = [c for c in df.columns if c.startswith("result") or c.startswith("table") or c == "_start" or c == "_stop"]
    return df.drop(columns=drop, errors="ignore")


# ── Sidebar ──────────────────────────────────────────────────────────────────
st.sidebar.title("⚙️ Controls")
time_range = st.sidebar.selectbox(
    "Time window",
    ["-15m", "-30m", "-1h", "-3h", "-6h", "-12h", "-24h", "-48h"],
    index=4,
)
if st.sidebar.button("🔄 Refresh"):
    st.cache_data.clear()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown(f"**InfluxDB:** `{INFLUX_URL}`")
st.sidebar.markdown(f"**Bucket:** `{INFLUX_BUCKET}`")
st.sidebar.markdown(f"**Org:** `{INFLUX_ORG}`")

# ── Header ───────────────────────────────────────────────────────────────────
st.markdown("""
<style>
.hero {
    background: linear-gradient(135deg,#0f2237 0%,#1a3a5c 50%,#0f7b6c 100%);
    padding:20px 28px; border-radius:14px; margin-bottom:18px;
}
.hero h1 {color:#f5fbff;margin:0 0 6px;}
.hero p  {color:rgba(245,251,255,0.82);margin:0;}
.stMetric {background:#1e2d3d;border-radius:10px;padding:10px;}
</style>
<div class="hero">
  <h1>🏭 Level 2 ICS Honeypot — Log Dashboard</h1>
  <p>Real-time OT/SCADA telemetry, ML alerts, MITRE ATT&amp;CK mapping &amp; correlated attack narrative</p>
</div>
""", unsafe_allow_html=True)

# ── KPI row ──────────────────────────────────────────────────────────────────
@st.cache_data(ttl=15)
def kpi_data(tr):
    alerts_df = query(f"""
        from(bucket:"{INFLUX_BUCKET}") |> range(start:{tr})
        |> filter(fn:(r) => r["_measurement"] == "security_alerts")
        |> filter(fn:(r) => r["_field"] == "value")
        |> count()
    """)
    n_alerts = int(alerts_df["_value"].sum()) if not alerts_df.empty and "_value" in alerts_df.columns else 0

    crit_df = query(f"""
        from(bucket:"{INFLUX_BUCKET}") |> range(start:{tr})
        |> filter(fn:(r) => r["_measurement"] == "security_alerts")
        |> filter(fn:(r) => r["_field"] == "value")
        |> filter(fn:(r) => r["severity"] == "CRITICAL")
        |> count()
    """)
    n_crit = int(crit_df["_value"].sum()) if not crit_df.empty and "_value" in crit_df.columns else 0

    mod_df = query(f"""
        from(bucket:"{INFLUX_BUCKET}") |> range(start:{tr})
        |> filter(fn:(r) => r["_measurement"] == "correlation_logs")
        |> filter(fn:(r) => r["_field"] == "func_code")
        |> count()
    """)
    n_mod = int(mod_df["_value"].sum()) if not mod_df.empty and "_value" in mod_df.columns else 0

    hp_df = query(f"""
        from(bucket:"{INFLUX_BUCKET}") |> range(start:{tr})
        |> filter(fn:(r) => r["_measurement"] == "honeypot_events")
        |> filter(fn:(r) => r["_field"] == "value")
        |> count()
    """)
    n_hp = int(hp_df["_value"].sum()) if not hp_df.empty and "_value" in hp_df.columns else 0

    return n_alerts, n_crit, n_mod, n_hp

n_alerts, n_crit, n_mod, n_hp = kpi_data(time_range)
k1, k2, k3, k4 = st.columns(4)
k1.metric("🚨 Total Alerts",        n_alerts)
k2.metric("🔴 Critical Alerts",     n_crit)
k3.metric("📡 Modbus Events",       n_mod)
k4.metric("🕵️ Honeypot Probes",    n_hp)

st.divider()

# ── Tabs ─────────────────────────────────────────────────────────────────────
tab_story, tab_pipeline, tab_alerts, tab_mitre, tab_raw = st.tabs([
    "📖 Attack Story", "📊 Pipeline Metrics", "🚨 Security Alerts",
    "🎯 MITRE ATT&CK", "📋 All Logs"
])

# ════════════════════════════════════════════════════════════════════════════
# TAB 1 — ATTACK STORY (correlated narrative)
# ════════════════════════════════════════════════════════════════════════════
with tab_story:
    st.subheader("📖 Correlated Attack Narrative — Kill Chain Story")
    st.caption("Events are grouped by session_id so you can follow the attacker's path from start to finish.")

    @st.cache_data(ttl=15)
    def story_data(tr):
        return _clean(query(f"""
            from(bucket:"{INFLUX_BUCKET}") |> range(start:{tr})
            |> filter(fn:(r) => r["_measurement"] == "security_alerts")
            |> filter(fn:(r) => r["_field"] == "narrative")
            |> keep(columns:["_time","_value","event_type","severity","layer",
                              "kill_chain_stage","mitre_tactic","protocol",
                              "session_id","correlation_id"])
            |> sort(columns:["_time"], desc:false)
        """))

    sdf = story_data(time_range)

    if sdf.empty:
        st.info("No narrative events yet. Run an attack scenario to generate correlated logs.")
    else:
        sdf["_time"] = pd.to_datetime(sdf["_time"], errors="coerce", utc=True)
        sdf = sdf.dropna(subset=["_time"])

        # Session selector
        sessions = sdf["session_id"].dropna().unique().tolist() if "session_id" in sdf.columns else []
        chosen = st.selectbox("Filter by Session ID (blank = show all)", ["— All Sessions —"] + sessions)

        show_df = sdf if chosen == "— All Sessions —" else sdf[sdf["session_id"] == chosen]

        # Timeline chart
        if not show_df.empty and "kill_chain_stage" in show_df.columns:
            tl = show_df.copy()
            tl["count"] = 1
            fig = px.scatter(
                tl, x="_time", y="kill_chain_stage",
                color="mitre_tactic" if "mitre_tactic" in tl.columns else "event_type",
                size="count", hover_data=["event_type","severity","protocol","_value"],
                title="Attack Kill-Chain Timeline",
                labels={"_time":"Time","kill_chain_stage":"Kill Chain Stage"},
                height=380,
            )
            fig.update_layout(paper_bgcolor="#0f1923", plot_bgcolor="#0f1923",
                              font_color="#c8d8e8")
            st.plotly_chart(fig, use_container_width=True)

        # Narrative feed
        st.subheader("📜 Narrative Feed")
        sev_colors = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","INFO":"🔵"}
        for _, row in show_df.sort_values("_time", ascending=False).head(40).iterrows():
            sev   = str(row.get("severity", "INFO"))
            icon  = sev_colors.get(sev, "⚪")
            ts    = row["_time"].strftime("%H:%M:%S")
            evt   = row.get("event_type","?")
            kc    = row.get("kill_chain_stage","")
            narr  = row.get("_value","")
            st.markdown(f"{icon} `{ts}` **{evt}** _{kc}_  \n> {narr}")

# ════════════════════════════════════════════════════════════════════════════
# TAB 2 — PIPELINE METRICS
# ════════════════════════════════════════════════════════════════════════════
with tab_pipeline:
    st.subheader("📊 Physical Process Telemetry")

    @st.cache_data(ttl=15)
    def pipeline_data(tr):
        return _clean(query(f"""
            from(bucket:"{INFLUX_BUCKET}") |> range(start:{tr})
            |> filter(fn:(r) => r["_measurement"] == "pipeline_metrics")
            |> aggregateWindow(every:30s, fn:mean, createEmpty:false)
            |> pivot(rowKey:["_time"], columnKey:["_field"], valueColumn:"_value")
        """))

    pdf = pipeline_data(time_range)

    if pdf.empty:
        st.info("No pipeline metrics available.")
    else:
        pdf["_time"] = pd.to_datetime(pdf["_time"], errors="coerce", utc=True)
        fields = [c for c in ["pressure","flow_rate","temperature","pump_rpm"] if c in pdf.columns]

        cols = st.columns(2)
        for i, field in enumerate(fields):
            with cols[i % 2]:
                fig = px.line(pdf, x="_time", y=field,
                              title=field.replace("_"," ").title(),
                              labels={"_time":"Time", field: field},
                              height=300)
                fig.update_layout(paper_bgcolor="#0f1923", plot_bgcolor="#0f1923",
                                  font_color="#c8d8e8")
                st.plotly_chart(fig, use_container_width=True)

# ════════════════════════════════════════════════════════════════════════════
# TAB 3 — SECURITY ALERTS
# ════════════════════════════════════════════════════════════════════════════
with tab_alerts:
    st.subheader("🚨 Security Alerts")

    @st.cache_data(ttl=15)
    def alerts_data(tr):
        return _clean(query(f"""
            from(bucket:"{INFLUX_BUCKET}") |> range(start:{tr})
            |> filter(fn:(r) => r["_measurement"] == "security_alerts")
            |> filter(fn:(r) => r["_field"] == "narrative")
            |> keep(columns:["_time","_value","event_type","severity","layer",
                              "kill_chain_stage","mitre_tactic","mitre_technique_id",
                              "protocol","session_id"])
            |> sort(columns:["_time"], desc:true)
            |> limit(n:200)
        """))

    adf = alerts_data(time_range)

    if adf.empty:
        st.info("No security alerts in this window.")
    else:
        adf["_time"] = pd.to_datetime(adf["_time"], errors="coerce", utc=True)

        left, right = st.columns(2)
        with left:
            if "event_type" in adf.columns:
                vc = adf["event_type"].value_counts().reset_index()
                vc.columns = ["event_type","count"]
                fig = px.bar(vc, x="event_type", y="count", title="Alert Types",
                             color="event_type", height=300)
                fig.update_layout(paper_bgcolor="#0f1923", plot_bgcolor="#0f1923",
                                  font_color="#c8d8e8", showlegend=False)
                st.plotly_chart(fig, use_container_width=True)
        with right:
            if "severity" in adf.columns:
                svc = adf["severity"].value_counts().reset_index()
                svc.columns = ["severity","count"]
                color_map = {"CRITICAL":"#e53935","HIGH":"#fb8c00",
                             "MEDIUM":"#fdd835","INFO":"#42a5f5"}
                fig = px.pie(svc, names="severity", values="count",
                             color="severity", color_discrete_map=color_map,
                             title="Severity Breakdown", height=300)
                fig.update_layout(paper_bgcolor="#0f1923", font_color="#c8d8e8")
                st.plotly_chart(fig, use_container_width=True)

        st.dataframe(
            adf.rename(columns={"_time":"Time","_value":"Narrative",
                                 "event_type":"Event","severity":"Severity",
                                 "layer":"Layer","kill_chain_stage":"Kill Chain",
                                 "mitre_tactic":"Tactic","mitre_technique_id":"Technique ID",
                                 "protocol":"Protocol","session_id":"Session"}),
            use_container_width=True, height=400,
        )

# ════════════════════════════════════════════════════════════════════════════
# TAB 4 — MITRE ATT&CK
# ════════════════════════════════════════════════════════════════════════════
with tab_mitre:
    st.subheader("🎯 MITRE ATT&CK for ICS Mapping")

    @st.cache_data(ttl=15)
    def mitre_data(tr):
        return _clean(query(f"""
            from(bucket:"{INFLUX_BUCKET}") |> range(start:{tr})
            |> filter(fn:(r) => r["_measurement"] == "security_alerts" or
                                 r["_measurement"] == "correlation_logs")
            |> filter(fn:(r) => r["_field"] == "value" or r["_field"] == "func_code")
            |> keep(columns:["_time","_value","mitre_tactic","mitre_technique_id",
                              "mitre_technique_name","kill_chain_stage","purdue_level","protocol"])
        """))

    mdf = mitre_data(time_range)

    if mdf.empty:
        st.info("No MITRE-tagged events in this time window.")
    else:
        mdf["_time"] = pd.to_datetime(mdf["_time"], errors="coerce", utc=True)
        cols = st.columns(3)

        with cols[0]:
            if "mitre_tactic" in mdf.columns:
                tdf = mdf[mdf["mitre_tactic"].notna() & (mdf["mitre_tactic"] != "Unknown")]
                if not tdf.empty:
                    vc = tdf["mitre_tactic"].value_counts().reset_index()
                    vc.columns = ["tactic","count"]
                    fig = px.bar(vc, x="count", y="tactic", orientation="h",
                                 title="Tactics", height=350)
                    fig.update_layout(paper_bgcolor="#0f1923", plot_bgcolor="#0f1923",
                                      font_color="#c8d8e8")
                    st.plotly_chart(fig, use_container_width=True)

        with cols[1]:
            if "protocol" in mdf.columns:
                pdf = mdf[mdf["protocol"].notna() & (mdf["protocol"] != "Unknown")]
                if not pdf.empty:
                    vc = pdf["protocol"].value_counts().reset_index()
                    vc.columns = ["protocol","count"]
                    fig = px.pie(vc, names="protocol", values="count",
                                 title="Protocol Distribution", height=350)
                    fig.update_layout(paper_bgcolor="#0f1923", font_color="#c8d8e8")
                    st.plotly_chart(fig, use_container_width=True)

        with cols[2]:
            if "purdue_level" in mdf.columns:
                pldf = mdf[mdf["purdue_level"].notna() & (mdf["purdue_level"] != "Unknown")]
                if not pldf.empty:
                    vc = pldf["purdue_level"].value_counts().reset_index()
                    vc.columns = ["level","count"]
                    fig = px.bar(vc, x="level", y="count", title="Purdue Level Activity",
                                 color="level", height=350)
                    fig.update_layout(paper_bgcolor="#0f1923", plot_bgcolor="#0f1923",
                                      font_color="#c8d8e8", showlegend=False)
                    st.plotly_chart(fig, use_container_width=True)

        # Technique table
        if "mitre_technique_id" in mdf.columns and "mitre_technique_name" in mdf.columns:
            st.subheader("Technique Summary")
            tbl = (mdf.groupby(["mitre_technique_id","mitre_technique_name","mitre_tactic","protocol"])
                      .size().reset_index(name="count")
                      .sort_values("count", ascending=False))
            st.dataframe(tbl, use_container_width=True, height=300)

# ════════════════════════════════════════════════════════════════════════════
# TAB 5 — ALL LOGS (raw browser)
# ════════════════════════════════════════════════════════════════════════════
with tab_raw:
    st.subheader("📋 All Measurements — Raw Log Browser")

    MEASUREMENTS = [
        "pipeline_metrics", "security_alerts", "security_metrics",
        "correlation_logs", "honeypot_events", "recon_scan_events",
        "modbus_events", "forced_writes", "attack_status",
        "grafana_events",
    ]
    selected_m = st.selectbox("Measurement", MEASUREMENTS)
    row_limit  = st.slider("Max rows", 50, 500, 100, 50)

    @st.cache_data(ttl=10)
    def raw_data(measurement, limit, tr):
        return _clean(query(f"""
            from(bucket:"{INFLUX_BUCKET}") |> range(start:{tr})
            |> filter(fn:(r) => r["_measurement"] == "{measurement}")
            |> sort(columns:["_time"], desc:true)
            |> limit(n:{limit})
        """))

    rdf = raw_data(selected_m, row_limit, time_range)
    if rdf.empty:
        st.info(f"No data in `{selected_m}` for the selected time window.")
    else:
        st.caption(f"{len(rdf)} rows from `{selected_m}`")
        st.dataframe(rdf, use_container_width=True, height=500)

        # Download
        csv = rdf.to_csv(index=False)
        st.download_button(
            f"⬇️ Download {selected_m}.csv",
            data=csv,
            file_name=f"{selected_m}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )

st.markdown("---")
st.caption(f"Level 2 ICS Honeypot Log Dashboard • {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
