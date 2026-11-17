"""FlowGuard — single-page network intrusion detection dashboard.

Run: streamlit run dashboard.py
Dependencies: streamlit, pandas

This UI only displays predictions. It does not capture packets or run an ML model.
Replace predictions.csv with real scoring output using the documented columns.
"""

from __future__ import annotations

from html import escape
from pathlib import Path

import pandas as pd
import streamlit as st


st.set_page_config(
    page_title="FlowGuard | Network Intrusion Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

CSV_PATH = Path(__file__).resolve().parent / "predictions.csv"
REQUIRED_COLUMNS = (
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "prediction",
    "attack_type",
)
VICTIM_IP = "192.168.56.101"

STYLE = """
<style>
:root {color-scheme: dark;}
html, body, [data-testid="stApp"], [data-testid="stAppViewContainer"],
[data-testid="stMain"] {background: #161718 !important; color: #eceef1 !important;}
header[data-testid="stHeader"], #MainMenu, footer, [data-testid="stDecoration"] {display: none !important;}
.block-container {max-width: 1250px !important; padding-top: 3.4rem !important;
                  padding-bottom: 2rem !important; padding-left: 2rem !important;
                  padding-right: 2rem !important;}
.fg-shell {width: 100%;}
.fg-head {display: flex; justify-content: space-between; align-items: center;
          gap: 16px; padding: 3px 0 22px; flex-wrap: wrap;}
.fg-head-left {display: flex; align-items: center; flex-wrap: wrap; gap: 12px;}
.fg-logo {display: inline-flex; align-items: center; gap: 9px;
          font-size: 24px; font-weight: 750; letter-spacing: -0.6px; color: #f5f7f8;}
.fg-logo svg {height: 26px; width: 26px; flex-shrink: 0;}
.fg-victim {font-size: 13px; color: #a1a5ab; white-space: nowrap;}
.fg-badge {background: #461a1e; color: #f999a1; border: 1px solid #692b31;
           border-radius: 6px; padding: 7px 12px; font-size: 12px;
           font-weight: 650; white-space: nowrap;}
.fg-metrics {display: grid; grid-template-columns: repeat(4,minmax(0,1fr));
             gap: 14px; margin-bottom: 24px;}
.fg-metric {background: #1e2022; border: 1px solid #25282b; border-radius: 12px;
            padding: 21px 21px 20px; min-height: 119px; box-sizing: border-box;}
.fg-metric-label {font-size: 13px; color: #aeb2b8; letter-spacing: 0.1px;
                  margin-bottom: 10px;}
.fg-metric-value {font-size: clamp(23px,2.5vw,34px); line-height: 1.15;
                  font-weight: 690; color: #f0f2f4; letter-spacing: -0.5px;
                  overflow-wrap: anywhere; font-variant-numeric: tabular-nums;}
.fg-metric-value.green {color: #42d18c;}
.fg-metric-value.red {color: #ff838d;}
.fg-metric-value.ip {font-size: clamp(18px,2vw,26px); letter-spacing: -0.4px;}
.fg-table-wrap {background: #1b1c1e; border: 1px solid #333537;
                border-radius: 12px; overflow-x: auto; margin-bottom: 17px;}
.fg-table {border-collapse: collapse; width: 100%; min-width: 550px;
           text-align: left; color: #e8eaed;}
.fg-table th {background: #17181a; color: #b7bac0; font-size: 13px;
              font-weight: 650; padding: 14px 19px; border-bottom: 1px solid #353639;}
.fg-table td {padding: 12px 19px; font-size: 13px;
              border-bottom: 1px solid #2d2f31; line-height: 1.45;}
.fg-table tr:last-child td {border-bottom: none;}
.fg-table tbody tr:hover {background: #25272a;}
.fg-table th:nth-child(1), .fg-table td:nth-child(1) {width: 24%;}
.fg-table th:nth-child(2), .fg-table td:nth-child(2) {width: 27%;}
.fg-table th:nth-child(3), .fg-table td:nth-child(3) {width: 17%;}
.fg-verdict {display: inline-block; padding: 4px 10px; border-radius: 5px;
             font-size: 12px; font-weight: 675; line-height: 1.5;}
.fg-verdict.normal {background: #d9f5e5; color: #166437;}
.fg-verdict.attack {background: #ffe0e2; color: #9b1b2a;}
.fg-verdict.other {background: #393c42; color: #e5e7eb;}
.fg-table-note {font-size: 12px; color: #90959d; margin-bottom: 11px;}
.fg-error {color: #ff939e; padding: 7px 0 15px; font-size: 14px; font-weight: 600;}
.fg-footer {display: flex; align-items: center; gap: 8px; font-size: 12px;
            color: #969ca4; padding: 7px 0 0;}
.fg-live-dot {display: inline-block; width: 7px; height: 7px;
              border-radius: 50%; background: #42d18c;}
[data-testid="stFileUploader"] {max-width: 315px;}
[data-testid="stFileUploader"] label {color: #e6e8eb !important; font-size: 13px !important;}
[data-testid="stFileUploaderDropzone"] {min-height: 55px; padding: 7px 12px;
                                        border-radius: 8px; background: #232527 !important;
                                        border: 1px solid #484b4f !important;}
[data-testid="stFileUploaderDropzoneInstructions"] {display: none !important;}
[data-testid="stFileUploaderDropzone"] button {background: #313438 !important;
                         color: #f2f2f2 !important; border-radius: 7px !important;
                         border: 1px solid #50545a !important;}
[data-testid="stFileUploader"] small {display: none !important;}
.stButton > button {background: #282a2d !important; color: #f0f2f4 !important;
                    border: 1px solid #484b4f !important; border-radius: 8px !important;
                    min-height: 39px; padding: 0 17px !important;}
.stButton > button:hover {border-color: #7c828b !important; background: #36393d !important;}
[data-testid="stAlert"] {background: #26282b !important; color: #ededed !important;
                         border-radius: 9px !important;}
@media (max-width: 750px) {
  .fg-metrics {grid-template-columns: repeat(2, minmax(0,1fr));}
  .fg-metric {min-height: 103px; padding: 16px;}
  .block-container {padding-left: 1rem !important; padding-right: 1rem !important;
                    padding-top: 1.7rem !important;}
  .fg-head {align-items: flex-start;}
}
@media (max-width: 460px) {
  .fg-metrics {gap: 9px;}
  .fg-metric-value {font-size: 23px;}
  .fg-victim {font-size: 12px;}
}
</style>
"""

st.markdown(STYLE, unsafe_allow_html=True)


def read_results(uploaded_file):
    """Read the active CSV on *every* rerun; return (dataframe, error message)."""
    if uploaded_file is None:
        if not CSV_PATH.is_file():
            return None, "No results yet. Run the detector or load a results file."
        source = CSV_PATH
    else:
        uploaded_file.seek(0)
        source = uploaded_file

    try:
        data = pd.read_csv(source, dtype=str, keep_default_na=False, encoding="utf-8-sig")
    except (OSError, ValueError, UnicodeError, pd.errors.ParserError, pd.errors.EmptyDataError):
        return None, "Could not read results CSV. Please select a valid CSV file."

    # Strip whitespace/BOM in header names while requiring the exact specified fields.
    data.columns = [str(col).strip().lstrip("\ufeff") for col in data.columns]
    for field in REQUIRED_COLUMNS:
        if field not in data.columns:
            return None, f"Missing column: {field}"

    for field in REQUIRED_COLUMNS:
        data[field] = data[field].fillna("").astype(str).str.strip()
    return data, None


def summarize(data):
    """Summarize predictions, not ground-truth labels or sample stats."""
    normalized = data["prediction"].str.casefold()
    is_normal = normalized.eq("normal")
    is_attack = normalized.eq("attack")
    attackers = data.loc[is_attack, "src_ip"]
    attackers = attackers[attackers.ne("")]
    top_attacker = attackers.value_counts().index[0] if not attackers.empty else "None"
    kinds = data.loc[is_attack, "attack_type"]
    num_types = kinds[kinds.ne("")].nunique()
    return len(data), int(is_normal.sum()), int(is_attack.sum()), top_attacker, num_types


def format_time(value):
    """Display the clock portion of a timestamp, preserving unparseable values."""
    raw = str(value).strip()
    if not raw:
        return "—"
    try:
        ts = pd.to_datetime(raw, errors="coerce")
        if pd.notna(ts):
            return ts.strftime("%H:%M:%S")
    except (TypeError, ValueError, OverflowError):
        pass
    return raw


def recent_rows(data):
    """Newest first by timestamp; use most recently appended if dates are malformed."""
    frame = data.copy()
    frame["_time"] = pd.to_datetime(frame["timestamp"], errors="coerce", utc=True)
    frame["_row"] = range(len(frame))
    if frame["_time"].notna().any():
        frame = frame.sort_values(["_time", "_row"], ascending=[False, False], na_position="last")
        return frame.head(15)
    return frame.tail(15).iloc[::-1]


def show_header(num_types):
    types_text = f"{num_types} attack type{'s' if num_types != 1 else ''} detected" if num_types else "Attacks detected"
    st.markdown(
        '<div class="fg-head">'
        '<div class="fg-head-left">'
        '<div class="fg-logo">'
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
        'fill="none" stroke="#63a8ff" stroke-width="1.9" stroke-linecap="round" '
        'stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
        '<path d="m9 12 2 2 4-4"/></svg>'
        'FlowGuard</div>'
        f'<span class="fg-victim">Victim VM {escape(VICTIM_IP)}</span>'
        '</div>'
        f'<span class="fg-badge">{escape(types_text)}</span>'
        '</div>',
        unsafe_allow_html=True,
    )


def show_metrics(total, normals, attacks, top_attacker):
    def card(label, value, extra=""):
        return (
            '<div class="fg-metric">'
            f'<div class="fg-metric-label">{escape(label)}</div>'
            f'<div class="fg-metric-value {extra}">{escape(str(value))}</div>'
            '</div>'
        )

    st.markdown(
        '<div class="fg-metrics">'
        + card("Flows analyzed", f"{total:,}")
        + card("Normal", f"{normals:,}", "green")
        + card("Attacks", f"{attacks:,}", "red")
        + card("Top attacker", top_attacker, "ip")
        + '</div>',
        unsafe_allow_html=True,
    )


def show_table(data):
    rows = []
    for _, record in recent_rows(data).iterrows():
        prediction = record["prediction"].casefold()
        is_normal = prediction == "normal"
        is_attack = prediction == "attack"
        attack_name = record["attack_type"]
        verdict = attack_name if attack_name else record["prediction"]
        if not verdict:
            verdict = "Unknown"
        style = "normal" if is_normal else "attack" if is_attack else "other"
        row = (
            "<tr>"
            f'<td>{escape(format_time(record["timestamp"]))}</td>'
            f'<td>{escape(record["src_ip"])}</td>'
            f'<td>{escape(record["dst_port"] or "—")}</td>'
            f'<td><span class="fg-verdict {style}">{escape(verdict)}</span></td>'
            "</tr>"
        )
        rows.append(row)

    if not rows:
        rows.append('<tr><td colspan="4">No connections in this file.</td></tr>')

    table = (
        '<div class="fg-table-wrap"><table class="fg-table">'
        '<thead><tr><th>Time</th><th>Source</th><th>Port</th><th>Verdict</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></div>'
    )
    st.markdown(table, unsafe_allow_html=True)
    st.markdown(
        f'<div class="fg-table-note">Showing {min(len(data),15)} most recent '
        f'of {len(data):,} flows</div>',
        unsafe_allow_html=True,
    )


@st.fragment(run_every="5s")
def live_dashboard():
    # Read the uploader state from its prior (or immediately triggering) run.
    # Keeping this entire view in a fragment makes the CSV update every 5 sec.
    uploaded_file = st.session_state.get("results_upload")
    data, problem = read_results(uploaded_file)

    if data is None:
        show_header(0)
        show_metrics(0, 0, 0, "None")
        if problem == "No results yet. Run the detector or load a results file.":
            st.info(problem, icon="ℹ️")
        else:
            st.markdown(f'<div class="fg-error">{escape(problem)}</div>', unsafe_allow_html=True)
    else:
        total, normals, attacks, top_attacker, num_types = summarize(data)
        show_header(num_types)
        show_metrics(total, normals, attacks, top_attacker)
        show_table(data)

    uploader_column, refresh_column, remainder = st.columns([2.5, 1, 3.5], vertical_alignment="bottom")
    with uploader_column:
        st.file_uploader(
            "Load results",
            type=["csv"],
            key="results_upload",
            help="Select a predictions CSV to view instead of the local predictions.csv.",
        )
    with refresh_column:
        if st.button("↻ Refresh", key="refresh_now", use_container_width=True):
            st.rerun(scope="fragment")
    st.markdown(
        '<div class="fg-footer"><span class="fg-live-dot"></span>'
        'Checks for new results every 5 seconds · '
        + ("Viewing uploaded CSV" if uploaded_file is not None else "Reading predictions.csv")
        + '</div>',
        unsafe_allow_html=True,
    )


live_dashboard()
