#!/usr/bin/env bash
# Real CICFlowMeter (Java) — pcap -> flows CSV. Produces the 77 features the model needs.
# Usage: ./cfm.sh <input.pcap | input_dir> <output_dir>
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
# jnetpcap needs system libpcap as libpcap.so  (Ubuntu: sudo apt install libpcap0.8)
if [ ! -e /usr/local/lib/libpcap.so ] && [ ! -e /usr/lib/x86_64-linux-gnu/libpcap.so ]; then
  PC=$(ldconfig -p | grep -m1 'libpcap.so.1' | awk '{print $NF}')
  [ -n "$PC" ] && sudo ln -sf "$PC" /usr/local/lib/libpcap.so && sudo ldconfig
fi
export LD_LIBRARY_PATH="$HERE/native:/usr/local/lib:$LD_LIBRARY_PATH"
java -Djava.library.path="$HERE/native:/usr/local/lib" -cp "$HERE/cicflowmeter.jar" cic.cs.unb.ca.ifm.Cmd "$1" "$2"
