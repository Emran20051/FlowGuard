# FlowGuard — ML-Based Network Intrusion Detection

COE444 project. A flow-based intrusion detector: it turns captured network
traffic into statistical flow features and classifies each flow as **benign**
or **attack** using a gradient-boosted model (XGBoost) trained on CIC-IDS2017.

## What's here
| Folder | Contents |
|---|---|
| `pipeline/` | The complete detector — CICFlowMeter extractor + trained model + scoring. One command: `./run.sh capture.pcap out.csv` |
| `results/`  | Evaluation findings (`RESULTS.md`) and a visual dashboard (`flowguard_results.html`) |
| `app/`      | **Upload-and-detect UI** — drop in a pcap or flows CSV, get per-flow verdicts |
| `dashboard/`| Live monitoring UI (Streamlit) that displays streaming predictions |

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

## Run the detection UI (new user — start here)

A web app where you upload a capture and see which flows are attacks. Works on
Windows, macOS, or Linux — you only need **Python 3.9+**.

**1. Get the code**
```bash
git clone https://github.com/Emran20051/FlowGuard.git
cd FlowGuard/app
```
No `git`? On GitHub click the green **Code → Download ZIP**, extract it, and open
a terminal in the `FlowGuard/app` folder.

**2. Install the dependencies** (once)
```bash
pip install -r requirements.txt
```

**3. Launch the app**
```bash
streamlit run app.py
```
It opens automatically in your browser at **http://localhost:8501**.

**4. Upload a file**
- Drag in a **flows `.csv`** (CICFlowMeter output) — scored directly, no extra setup.
- Or a **`.pcap`** — this also needs Java + libpcap so the extractor can run:
  `sudo apt install -y openjdk-17-jre-headless libpcap0.8` (Linux/WSL).

You get per-flow Attack/Normal verdicts, summary counts, and a downloadable
`predictions.csv`.

> **Windows note:** always get the repo with `git clone` or the GitHub ZIP, not
> by copying files around — the model is stored as text (JSON) specifically so it
> survives a clean clone.

## Command-line (no UI)
```bash
cd pipeline
sudo apt install -y openjdk-17-jre-headless libpcap0.8 python3-pip
pip3 install xgboost pandas
./run.sh your_capture.pcap predictions.csv
```

## Team
Team 6 — Zero Trust · COE444
