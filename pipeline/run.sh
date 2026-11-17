#!/usr/bin/env bash
# FlowGuard end-to-end:  pcap  ->  CICFlowMeter  ->  model  ->  predictions.csv
# Usage: ./run.sh <input.pcap> [output.csv]
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
PCAP="$1"; OUT="${2:-predictions.csv}"
[ -z "$PCAP" ] && { echo "usage: ./run.sh <input.pcap> [output.csv]"; exit 1; }
TMP="$(mktemp -d)"
echo "[1/2] extracting flows with CICFlowMeter ..."
"$HERE/extractor/cfm.sh" "$PCAP" "$TMP/"
FLOWS="$TMP/$(basename "$PCAP")_Flow.csv"
echo "[2/2] scoring with model ..."
python3 "$HERE/score.py" "$FLOWS" "$HERE/model/flowguard_xgb.joblib" "$HERE/model/flowguard_meta.json" "$OUT"
rm -rf "$TMP"
echo "done -> $OUT"
