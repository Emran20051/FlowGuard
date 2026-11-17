# FlowGuard — ML-Based Network Intrusion Detection

COE444 project. A flow-based intrusion detector: it turns captured network
traffic into statistical flow features and classifies each flow as **benign**
or **attack** using a gradient-boosted model (XGBoost) trained on CIC-IDS2017.

## What's here
| Folder | Contents |
|---|---|
| `pipeline/` | The complete detector — CICFlowMeter extractor + trained model + scoring. One command: `./run.sh capture.pcap out.csv` |
| `results/`  | Evaluation findings (`RESULTS.md`) and a visual dashboard (`flowguard_results.html`) |
| `dashboard/`| Live monitoring UI (Streamlit) that displays the detector's predictions |

## How it works
```
pcap --[CICFlowMeter]--> 77 flow features --[align]--> XGBoost --> Attack / Normal
```

## Key results
| Evaluation | Attack recall | macro-F1 |
|---|---|---|
| Random split (CIC-IDS2017) | 99.86% | 0.9985 |
| Temporal split (leakage-free) | 96.11% | 0.9883 |
| Live lab — novel attack variants | 0% | — |

The model genuinely learns the attack **types** it was trained on (96% on unseen
flows, not memorisation), but does **not** generalise to attack variants it never
saw — a SYN flood is a DoS attack, yet the model misses it because it looks
nothing like the HTTP floods in its training data. See `results/RESULTS.md`.

## Quick start
```bash
cd pipeline
sudo apt install -y openjdk-17-jre-headless libpcap0.8 python3-pip
pip3 install xgboost joblib pandas
./run.sh your_capture.pcap predictions.csv
```

## Team
Team 6 — Zero Trust · COE444
