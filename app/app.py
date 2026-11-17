"""
FlowGuard — upload a capture, run the real model, see the verdicts.

Run:  streamlit run app.py
Accepts a .pcap (needs CICFlowMeter + Java) or an already-extracted
CICFlowMeter flows .csv (scores directly, no Java needed).
"""
from __future__ import annotations
import json, os, subprocess, tempfile
from pathlib import Path

import numpy as np
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parent.parent          # repo root
MODEL = ROOT / "pipeline" / "model" / "flowguard_xgb.json"   # native format (portable, git-safe)
META = ROOT / "pipeline" / "model" / "flowguard_meta.json"
CFM = ROOT / "pipeline" / "extractor" / "cfm.sh"

# CICFlowMeter V3 column names -> model (CIC-IDS2017) feature names
V3 = {'dst_port':'destination_port','total_fwd_packet':'total_fwd_packets','total_bwd_packets':'total_backward_packets',
'total_length_of_fwd_packet':'total_length_of_fwd_packets','total_length_of_bwd_packet':'total_length_of_bwd_packets',
'packet_length_min':'min_packet_length','packet_length_max':'max_packet_length','cwr_flag_count':'cwe_flag_count',
'fwd_segment_size_avg':'avg_fwd_segment_size','bwd_segment_size_avg':'avg_bwd_segment_size',
'fwd_bytes/bulk_avg':'fwd_avg_bytes/bulk','fwd_packet/bulk_avg':'fwd_avg_packets/bulk','fwd_bulk_rate_avg':'fwd_avg_bulk_rate',
'bwd_bytes/bulk_avg':'bwd_avg_bytes/bulk','bwd_packet/bulk_avg':'bwd_avg_packets/bulk','bwd_bulk_rate_avg':'bwd_avg_bulk_rate',
'fwd_init_win_bytes':'init_win_bytes_forward','bwd_init_win_bytes':'init_win_bytes_backward',
'fwd_act_data_pkts':'act_data_pkt_fwd','fwd_seg_size_min':'min_seg_size_forward'}

st.set_page_config(page_title="FlowGuard", page_icon="🛡️", layout="wide")

st.markdown("""<style>
[data-testid="stAppViewContainer"]{background:#15161a}
h1,h2,h3,p,label,span,div{color:#eef0f4}
.block-container{max-width:1050px;padding-top:2.2rem}
.m{background:#1d1f25;border:1px solid #2c2f38;border-radius:13px;padding:18px 20px}
.m .lab{font-size:13px;color:#9aa0ac;margin-bottom:8px}
.m .v{font-size:34px;font-weight:680;letter-spacing:-1px;font-variant-numeric:tabular-nums}
.g{color:#43d18a}.r{color:#ff6b74}.b{color:#5aa2ff}
[data-testid="stFileUploaderDropzone"]{background:#1d1f25;border:1px solid #3a3f49}
</style>""", unsafe_allow_html=True)


@st.cache_resource
def load_model():
    import xgboost as xgb
    clf = xgb.XGBClassifier()
    clf.load_model(str(MODEL))
    return clf, json.load(open(META))["features"]


def extract_pcap(pcap_bytes: bytes, name: str) -> pd.DataFrame:
    """Run the real CICFlowMeter on an uploaded pcap."""
    tmp = Path(tempfile.mkdtemp())
    pcap = tmp / name
    pcap.write_bytes(pcap_bytes)
    out = tmp / "out"; out.mkdir()
    subprocess.run(["bash", str(CFM), str(pcap), str(out) + "/"],
                   check=True, capture_output=True, timeout=600)
    csvs = list(out.glob("*_Flow.csv"))
    if not csvs:
        raise RuntimeError("CICFlowMeter produced no flows (empty or non-TCP/UDP pcap?)")
    return pd.read_csv(csvs[0])


def score(flows: pd.DataFrame, model, feats):
    df = flows.copy()
    df.columns = [c.strip().lower().replace(" ", "_") for c in df.columns]
    df = df.rename(columns=V3)
    X = pd.DataFrame(index=df.index)
    for f in feats:
        X[f] = pd.to_numeric(df[f], errors="coerce") if f in df else 0.0
    X = X.replace([np.inf, -np.inf], 0.0).fillna(0.0)
    pred = model.predict(X)

    def col(*names):
        for n in names:
            if n in df:
                return df[n]
        return ""

    out = pd.DataFrame({
        "Time": col("timestamp"),
        "Source": col("src_ip", "source_ip"),
        "Destination": col("dst_ip", "destination_ip"),
        "Port": col("destination_port"),
        "Verdict": ["Attack" if int(p) == 1 else "Normal" for p in pred],
    })
    return out


st.title("🛡️ FlowGuard")
st.caption("Upload a network capture and run the trained intrusion-detection model on it.")

up = st.file_uploader("Capture file", type=["pcap", "pcapng", "csv"],
                      help="A .pcap (runs CICFlowMeter) or an already-extracted CICFlowMeter flows .csv")

if up is not None:
    model, feats = load_model()
    try:
        if up.name.lower().endswith(".csv"):
            flows = pd.read_csv(up)
        else:
            with st.spinner("Extracting flows with CICFlowMeter…"):
                flows = extract_pcap(up.getvalue(), up.name)
        with st.spinner("Scoring with the model…"):
            res = score(flows, model, feats)
    except Exception as e:
        st.error(f"Could not process this file: {e}")
        st.stop()

    total = len(res)
    attacks = int((res["Verdict"] == "Attack").sum())
    normals = total - attacks
    top = (res.loc[res["Verdict"] == "Attack", "Source"]
           .value_counts().index[0] if attacks else "—")

    c1, c2, c3, c4 = st.columns(4)
    for col, lab, val, cls in [(c1, "Flows analysed", f"{total:,}", "b"),
                               (c2, "Normal", f"{normals:,}", "g"),
                               (c3, "Attacks", f"{attacks:,}", "r"),
                               (c4, "Top source", top, "b")]:
        col.markdown(f'<div class="m"><div class="lab">{lab}</div>'
                     f'<div class="v {cls}">{val}</div></div>', unsafe_allow_html=True)

    st.markdown("###")
    only_attacks = st.checkbox("Show attacks only", value=False)
    view = res[res["Verdict"] == "Attack"] if only_attacks else res
    st.dataframe(
        view.style.apply(
            lambda r: ["background-color:#3a1d22" if r["Verdict"] == "Attack"
                       else "" for _ in r], axis=1),
        use_container_width=True, height=430)
    st.download_button("Download verdicts (CSV)", res.to_csv(index=False),
                       "predictions.csv", "text/csv")
else:
    st.info("Upload a .pcap or a CICFlowMeter flows .csv to begin.")
    st.caption("The model is binary — it labels each flow Attack or Normal. "
               "It detects attack types similar to its CIC-IDS2017 training data; "
               "novel variants (e.g. raw SYN floods) may read as normal — see results/RESULTS.md.")
