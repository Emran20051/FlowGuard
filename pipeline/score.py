"""Score a CICFlowMeter flow CSV with the FlowGuard model.
Usage: python score.py <flows.csv> <model.joblib> <meta.json> <out.csv>"""
import sys, json, numpy as np, pandas as pd, joblib
flows_csv, model_path, meta_path, out_csv = sys.argv[1:5]
FEATS = json.load(open(meta_path))['features']
model = joblib.load(model_path)
# CICFlowMeter V3 column names -> model (CIC-IDS2017) names
V3 = {'dst_port':'destination_port','total_fwd_packet':'total_fwd_packets','total_bwd_packets':'total_backward_packets',
'total_length_of_fwd_packet':'total_length_of_fwd_packets','total_length_of_bwd_packet':'total_length_of_bwd_packets',
'packet_length_min':'min_packet_length','packet_length_max':'max_packet_length','cwr_flag_count':'cwe_flag_count',
'fwd_segment_size_avg':'avg_fwd_segment_size','bwd_segment_size_avg':'avg_bwd_segment_size',
'fwd_bytes/bulk_avg':'fwd_avg_bytes/bulk','fwd_packet/bulk_avg':'fwd_avg_packets/bulk','fwd_bulk_rate_avg':'fwd_avg_bulk_rate',
'bwd_bytes/bulk_avg':'bwd_avg_bytes/bulk','bwd_packet/bulk_avg':'bwd_avg_packets/bulk','bwd_bulk_rate_avg':'bwd_avg_bulk_rate',
'fwd_init_win_bytes':'init_win_bytes_forward','bwd_init_win_bytes':'init_win_bytes_backward',
'fwd_act_data_pkts':'act_data_pkt_fwd','fwd_seg_size_min':'min_seg_size_forward'}
df = pd.read_csv(flows_csv)
meta_cols = {c.strip().lower().replace(' ','_'):c for c in df.columns}
df.columns = [c.strip().lower().replace(' ','_') for c in df.columns]
df = df.rename(columns=V3)
X = pd.DataFrame(index=df.index)
for f in FEATS: X[f] = pd.to_numeric(df[f], errors='coerce') if f in df else 0.0
X = X.replace([np.inf,-np.inf],0.0).fillna(0.0)
pred = model.predict(X)
out = pd.DataFrame({
  'timestamp': df.get('timestamp',''), 'src_ip': df.get('src_ip',''),
  'dst_ip': df.get('dst_ip',''), 'dst_port': df.get('destination_port',''),
  'prediction': ['Attack' if int(p)==1 else 'Normal' for p in pred], 'attack_type':''})
out.to_csv(out_csv, index=False)
n=len(out); a=int((out['prediction']=='Attack').sum())
print(f"  {n} flows: {a} attack, {n-a} normal -> {out_csv}")
