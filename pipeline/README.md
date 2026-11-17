# FlowGuard — complete detection pipeline

One command turns a pcap into attack/normal verdicts.

## What's inside
- `extractor/`  — the real Java CICFlowMeter (jar + native libs + cfm.sh)
- `model/`      — trained XGBoost model + feature metadata
- `score.py`    — aligns CICFlowMeter columns to the model and predicts
- `run.sh`      — end-to-end: pcap -> flows -> verdicts

## Setup (Ubuntu / the victim VM)
    sudo apt install -y openjdk-17-jre-headless libpcap0.8 python3-pip
    pip3 install xgboost joblib pandas

## Run
    ./run.sh  lab_capture.pcap  predictions.csv

Output `predictions.csv`: timestamp, src_ip, dst_ip, dst_port, prediction, attack_type.
Feed that CSV to the dashboard, or read it directly.

## Pipeline
    pcap --[CICFlowMeter]--> 77 flow features --[column align]--> XGBoost --> Attack/Normal
