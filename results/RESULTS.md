# FlowGuard — Results and Evaluation

## Summary

We evaluated the XGBoost detector three ways: a standard random split, a
leakage-free temporal split, and live out-of-distribution traffic captured in
our own lab. Together they show that the model genuinely learns to detect the
attack *types* it was trained on, but does not extrapolate to attack variants
or environments outside its training distribution.

| Evaluation | Attack recall | False-positive rate | macro-F1 |
|---|---|---|---|
| Random split (CIC-IDS2017) | 99.86% | 0.09% | 0.9985 |
| **Temporal split (CIC-IDS2017)** | **96.11%** | **0.03%** | **0.9883** |
| Lab capture (novel attack variants) | 0% | 0% | — |

## 1. Random split (standard benchmark)

Training and testing on a random 80/20 split of the 2.0M-flow dataset gives a
macro-F1 of 0.9985 and 99.86% attack recall. This matches published CIC-IDS2017
results, but it is optimistic: network attacks are continuous bursts, so a random
split places near-identical flows from the same burst in both training and test.
The model can therefore recognise test flows partly by having seen their
near-duplicates during training.

## 2. Temporal split (leakage-free, same attack types)

To remove that leakage we re-split by time: for each capture we trained on the
earliest 70% of flows and tested on the latest 30%. The attack *types* are the
same in both halves, but the test flows occur later and are not near-duplicates
of any training flow.

Performance barely drops — 96.11% recall at a 0.03% false-positive rate
(macro-F1 0.9883). The small gap from the random split (0.9985 → 0.9883) shows
the 99.85% figure was **mostly genuine learning, not memorisation**: the model
really does learn the behaviour of these attack types.

Per-attack detection on the temporal test set:

| Family | Detection rate |
|---|---|
| Port scan | 99.8% |
| Brute force | 99.9% |
| DoS / DDoS | 92.0% |
| Botnet | 0.0% |

Botnet is the one genuine weakness — 0% detection even here. Bot traffic is
engineered to mimic ordinary client behaviour at the flow level, so it is
near-indistinguishable from benign traffic by these features. This is a real
limitation of flow-statistical detection, not an artefact of the split.

## 3. Live lab capture (out-of-distribution)

We built an isolated two-VM lab (Kali attacker, Ubuntu victim) and captured
real traffic: a port scan, a flood, an SSH brute-force attempt, and normal
browsing. Flows were extracted with the same CICFlowMeter used to build the
training data, and scored with the trained model.

The model classified **normal traffic perfectly (0 false positives across 372
benign flows)** but detected **0% of the attacks**. The cause is a mismatch of
attack *variant*, not a pipeline fault. Our attacks were a `nmap -sS` SYN scan
and an `hping3` SYN flood — bare SYN packets with no payload and no completed
connection. CIC-IDS2017's attacks were HTTP-based (DoS Hulk/GoldenEye/slowloris
and fuller scans). The model's decision relies heavily on packet-size features,
which are populated for real bidirectional flows but are **zero** for bare-SYN
attacks:

| Feature | Normal | Port scan | DoS |
|---|---|---|---|
| Average packet size | 1100 | 0 | 0 |
| Bwd packet-length std (top feature) | 3262 | 0 | 0 |
| Max packet length | 7300 | 0 | 0 |

With its most important features absent, every attack flow looks like an empty
or aborted connection and is read as benign.

## Conclusion

The detector is strong within its training distribution — 96% recall on unseen
flows of known attack types, at a very low false-positive rate — which refutes
the idea that its benchmark score is pure memorisation. But it does not
generalise to attack *variants* it never trained on: a SYN flood is a denial-of-
service attack, yet the model misses it entirely because it looks nothing like
the HTTP floods it learned. This is the core lesson of the project, and it
matches the published critiques (Arp et al. 2022; Engelen et al. 2021): a
dataset-trained NIDS learns the specific attack behaviours in its data and
should not be assumed to detect novel variants of the same attack class.
