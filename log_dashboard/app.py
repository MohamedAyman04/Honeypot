import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import plotly.express as px
import streamlit as st

# -- Page Configuration --
st.set_page_config(
    page_title="ICS Honeypot - Unified Dashboard",
    page_icon="🛡️",
    layout="wide",
)

# -- Custom CSS for Premium Look --
st.markdown("""
<style>
    .main {
        background-color: #0e1117;
    }
    .hero {
        background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 50%, #10b981 100%);
        padding: 30px;
        border-radius: 15px;
        margin-bottom: 25px;
        color: white;
        box-shadow: 0 4px 15px rgba(0,0,0,0.3);
    }
    .hero h1 {
        margin: 0;
        font-weight: 800;
        letter-spacing: -1px;
    }
    .hero p {
        opacity: 0.9;
        font-size: 1.1rem;
    }
    .stMetric {
        background: #1f2937;
        border: 1px solid #374151;
        padding: 20px;
        border-radius: 12px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.2);
    }
    [data-testid="stMetricLabel"] {
        color: #9ca3af !important;
        font-size: 0.9rem !important;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    [data-testid="stMetricValue"] {
        color: #f3f4f6 !important;
        font-size: 2.2rem !important;
        font-weight: 700 !important;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 10px;
    }
    .stTabs [data-baseweb="tab"] {
        background-color: #1f2937;
        border-radius: 8px 8px 0 0;
        padding: 10px 20px;
        color: #9ca3af;
    }
    .stTabs [aria-selected="true"] {
        background-color: #3b82f6 !important;
        color: white !important;
    }
</style>
""", unsafe_allow_html=True)

# -- Data Loading --
# Use environment variable if provided, otherwise try to find it
LOG_FILE_ENV = os.getenv("LOG_FILE_PATH")
LOG_FILENAME = "general logs.jsonl"

def find_log_file():
    if LOG_FILE_ENV and Path(LOG_FILE_ENV).exists():
        return Path(LOG_FILE_ENV)
    
    curr = Path(__file__).resolve().parent
    for _ in range(5):
        potential = curr / LOG_FILENAME
        if potential.exists():
            return potential
        curr = curr.parent
    return Path(LOG_FILENAME)

LOG_FILE = find_log_file()

@st.cache_data(ttl=5)
def load_data():
    if not LOG_FILE.exists():
        return pd.DataFrame()
    
    events = []
    with open(LOG_FILE, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    events.append(json.loads(line))
                except Exception:
                    continue
    
    if not events:
        return pd.DataFrame()
    
    df = pd.DataFrame(events)

    # Normalize columns: promote commonly-used fields from meta to top-level
    for col in ("level", "component", "severity", "message"):
        if col not in df.columns and "meta" in df.columns:
            df[col] = df["meta"].apply(
                lambda m: m.get(col) if isinstance(m, dict) else None
            )

    # MITRE ATT&CK promotion (they might be at root or in meta)
    for col in ("mitre_tactic", "mitre_technique_id", "mitre_technique_name", "kill_chain_stage", "purdue_level", "protocol"):
        if col not in df.columns and "meta" in df.columns:
            df[col] = df["meta"].apply(
                lambda m: m.get(col) if isinstance(m, dict) else None
            )

    # Map 'ts' (new schema) → 'timestamp' (dashboard expected name)
    if 'timestamp' not in df.columns and 'ts' in df.columns:
        df['timestamp'] = df['ts']

    if 'timestamp' in df.columns:
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce', utc=True)
    return df

# -- Dashboard Header --
st.markdown("""
<div class="hero">
    <h1>🛡️ ICS Honeypot Unified Dashboard</h1>
    <p>Cross-layer telemetry visualization for Level 2 & Level 3 industrial assets.</p>
</div>
""", unsafe_allow_html=True)

df = load_data()

if df.empty:
    st.warning(f"No logs found in {LOG_FILE.absolute()}. Please ensure the honeynet is generating events.")
    if st.button("🔄 Refresh Data"):
        st.rerun()
    st.stop()

# -- Sidebar Controls --
st.sidebar.title("🛠️ Configuration")
if st.sidebar.button("🔄 Force Refresh"):
    st.cache_data.clear()
    st.rerun()

st.sidebar.divider()
st.sidebar.subheader("Filters")

levels = ["All"]
if 'level' in df.columns:
    levels += sorted(df['level'].dropna().unique().tolist())
selected_level = st.sidebar.selectbox("Filter by Level", levels)

components = ["All"]
if 'component' in df.columns:
    components += sorted(df['component'].dropna().unique().tolist())
selected_comp = st.sidebar.selectbox("Filter by Component", components)

severities = ["All"]
if 'severity' in df.columns:
    severities += sorted(df['severity'].dropna().unique().tolist())
selected_sev = st.sidebar.multiselect("Filter by Severity", severities, default="All")

# Apply filters
filtered_df = df.copy()
if selected_level != "All" and 'level' in filtered_df.columns:
    filtered_df = filtered_df[filtered_df['level'] == selected_level]
if selected_comp != "All" and 'component' in filtered_df.columns:
    filtered_df = filtered_df[filtered_df['component'] == selected_comp]
if "All" not in selected_sev and selected_sev and 'severity' in filtered_df.columns:
    filtered_df = filtered_df[filtered_df['severity'].isin(selected_sev)]

# -- KPI Metrics --
m1, m2, m3, m4 = st.columns(4)
m1.metric("Total Events", len(df))
m2.metric("Filtered Events", len(filtered_df))
crit_count = len(df[df['severity'].str.lower() == 'critical']) if 'severity' in df.columns else 0
m3.metric("Critical Alerts", crit_count, delta=f"{crit_count} Total", delta_color="inverse")
unique_comps = df['component'].nunique() if 'component' in df.columns else 0
m4.metric("Active Assets", unique_comps)

st.divider()

# -- Tabs for different views --
tab_viz, tab_mitre, tab_timeline, tab_raw = st.tabs(["📊 Distribution Analysis", "🎯 MITRE ATT&CK", "📈 Event Timeline", "📋 Raw Telemetry"])

with tab_viz:
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Severity Distribution")
        if 'severity' in filtered_df.columns:
            sev_counts = filtered_df['severity'].value_counts().reset_index()
            sev_counts.columns = ['severity', 'count']
            fig_sev = px.pie(
                sev_counts, 
                names='severity', 
                values='count',
                color='severity',
                color_discrete_map={
                    'info': '#3b82f6',
                    'medium': '#fbbf24',
                    'high': '#f97316',
                    'critical': '#ef4444',
                    'INFO': '#3b82f6',
                    'MEDIUM': '#fbbf24',
                    'HIGH': '#f97316',
                    'CRITICAL': '#ef4444'
                },
                hole=0.4
            )
            fig_sev.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
            st.plotly_chart(fig_sev, use_container_width=True)
        else:
            st.info("Severity data not available.")

    with col2:
        st.subheader("Level Breakdown")
        if 'level' in filtered_df.columns:
            lvl_counts = filtered_df['level'].value_counts().reset_index()
            lvl_counts.columns = ['level', 'count']
            fig_lvl = px.bar(
                lvl_counts, 
                x='level', 
                y='count',
                color='level',
                color_discrete_sequence=px.colors.qualitative.Pastel
            )
            fig_lvl.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white', showlegend=False)
            st.plotly_chart(fig_lvl, use_container_width=True)
        else:
            st.info("Level data not available.")

    col3, col4 = st.columns(2)
    
    with col3:
        st.subheader("Top Components")
        if 'component' in filtered_df.columns:
            comp_counts = filtered_df['component'].value_counts().head(10).reset_index()
            comp_counts.columns = ['component', 'count']
            fig_comp = px.bar(
                comp_counts, 
                y='component', 
                x='count',
                orientation='h',
                color='count',
                color_continuous_scale='Blues'
            )
            fig_comp.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
            st.plotly_chart(fig_comp, use_container_width=True)
        else:
            st.info("Component data not available.")

    with col4:
        st.subheader("Event Types")
        if 'event_type' in filtered_df.columns:
            type_counts = filtered_df['event_type'].value_counts().head(10).reset_index()
            type_counts.columns = ['event_type', 'count']
            fig_type = px.pie(
                type_counts, 
                names='event_type', 
                values='count',
                hole=0.4
            )
            fig_type.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
            st.plotly_chart(fig_type, use_container_width=True)
        else:
            st.info("Event Type data not available.")

with tab_mitre:
    st.subheader("🎯 MITRE ATT&CK Mapping")
    
    mitre_df = filtered_df.dropna(subset=['mitre_tactic']).copy() if 'mitre_tactic' in filtered_df.columns else pd.DataFrame()
    
    if not mitre_df.empty:
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Tactics Distribution")
            tactic_counts = mitre_df['mitre_tactic'].value_counts().reset_index()
            tactic_counts.columns = ['tactic', 'count']
            fig_tactic = px.pie(tactic_counts, names='tactic', values='count', hole=0.3)
            fig_tactic.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
            st.plotly_chart(fig_tactic, use_container_width=True)
            
        with col2:
            st.subheader("Kill Chain Stages")
            if 'kill_chain_stage' in mitre_df.columns:
                kc_counts = mitre_df['kill_chain_stage'].value_counts().reset_index()
                kc_counts.columns = ['kill_chain_stage', 'count']
                fig_kc = px.bar(kc_counts, x='count', y='kill_chain_stage', orientation='h', color='count', color_continuous_scale='Reds')
                fig_kc.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
                st.plotly_chart(fig_kc, use_container_width=True)

        st.subheader("Technique Summary")
        if 'mitre_technique_id' in mitre_df.columns and 'mitre_technique_name' in mitre_df.columns:
            tbl = mitre_df.groupby(["mitre_technique_id", "mitre_technique_name", "mitre_tactic"]).size().reset_index(name="count")
            tbl = tbl.sort_values("count", ascending=False)
            st.dataframe(tbl, use_container_width=True, height=300)
    else:
        st.info("No MITRE ATT&CK mapping data available in the selected logs.")

with tab_timeline:
    st.subheader("Event Frequency Over Time")
    if not filtered_df.empty and 'timestamp' in filtered_df.columns:
        timeline_df = filtered_df.copy()
        timeline_df = timeline_df.dropna(subset=['timestamp'])
        
        if not timeline_df.empty:
            resample_rate = st.select_slider(
                "Time Resolution",
                options=["10s", "30s", "min", "5min", "15min", "h"],
                value="min",
                help="min=Minute, s=Second, h=Hour"
            )
            
            timeline_df.set_index('timestamp', inplace=True)
            resampled = timeline_df.resample(resample_rate).size().reset_index(name='count')
            
            fig_time = px.line(
                resampled, 
                x='timestamp', 
                y='count',
                title=f"Events per {resample_rate}"
            )
            fig_time.update_traces(line_color='#3b82f6', fill='tozeroy')
            fig_time.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font_color='white')
            st.plotly_chart(fig_time, use_container_width=True)
        else:
            st.info("No valid timestamps found for timeline.")
    else:
        st.info("Timestamp column missing or empty.")

with tab_raw:
    st.subheader("Detailed Event Logs")
    
    # Search functionality
    search_query = st.text_input("🔍 Search messages or details", "")
    if search_query:
        mask = filtered_df.apply(lambda r: search_query.lower() in str(r.to_dict()).lower(), axis=1)
        display_df = filtered_df[mask]
    else:
        display_df = filtered_df
    
    st.write(f"Showing {len(display_df)} events")
    
    # Selection for which columns to show
    all_cols = display_df.columns.tolist()
    default_cols = ['timestamp', 'level', 'component', 'event_type', 'severity', 'mitre_tactic', 'mitre_technique_id', 'message']
    selected_cols = st.multiselect("Visible Columns", all_cols, default=[c for c in default_cols if c in all_cols])
    
    st.dataframe(
        display_df[selected_cols].sort_values('timestamp', ascending=False)
        if 'timestamp' in selected_cols else display_df[selected_cols],
        use_container_width=True,
        height=500
    )
    
    # Download button
    csv = display_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        "⬇️ Download Filtered Logs (CSV)",
        csv,
        "filtered_honeypot_logs.csv",
        "text/csv",
        key='download-csv'
    )

# -- Footer --
st.divider()
st.caption(f"ICS Honeypot Unified Logging System • {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
