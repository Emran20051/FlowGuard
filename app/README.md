# FlowGuard — upload & detect UI

A small web app: upload a capture, run the trained model, see which flows are attacks.

## Run
```bash
cd app
pip install -r requirements.txt
streamlit run app.py
```
Opens at http://localhost:8501.

## Input
- **`.pcap` / `.pcapng`** — runs the real CICFlowMeter (needs Java + libpcap:
  `sudo apt install -y openjdk-17-jre-headless libpcap0.8`), then the model.
- **`.csv`** — an already-extracted CICFlowMeter flows file; scored directly, no Java needed.

## Output
Per-flow Attack/Normal verdicts, summary counts, the top attacking source, and a
downloadable `predictions.csv`.

> The model is binary and was trained on CIC-IDS2017. It detects attack behaviours
> similar to its training data; novel variants (e.g. raw SYN floods) can read as
> normal — see `../results/RESULTS.md`.
