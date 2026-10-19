# BLACKBOX — Optional supervised ML extension

**Goal:** predict whether a *measured directional flow* is suspicious, then associate model output with actual stored packet evidence. Network-parsing and feature extraction belong to BLACKBOX; Any future ML component must handle training, independent validation and prediction.

## Input contract (implemented)

**Evidence Vault → Export ML flow features (CSV)** calls `GET /api/cases/{case_id}/ml/features.csv` and runs `blackbox/ml_features.py`. Each record is scoped to a single source capture, a **120-second timestamp bucket**, and the directional `(src_ip, dst_ip, src_port, dst_port, protocol)` tuple. The exported `flow_id` is a per-export row identifier, not a globally stable case key.

| Field(s) | Role |
|---|---|
| `src_port`, `dst_port`, `protocol` | Model candidate inputs; protocol must be encoded consistently. |
| `duration_sec`, `packet_count`, `byte_count` | Observed flow features. |
| `flow_rate_pps`, `byte_rate_bps`, `avg_packet_size` | Derived numeric features; single-packet zero-duration flow rates are set to **0**, not infinity. |
| `unique_dst_ports` | Distinct destination ports contacted by a source in the same source-capture/120-s window; shared across its rows, not a single-flow property. |
| `tcp_syn_count`, `tcp_rst_count` | Observed TCP flag counts. |
| `src_ip`, `dst_ip`, `capture_id`, `window_start_epoch`, `start_ts`, `end_ts` | Investigation context; **not** initial model features. |
| `flow_id`, `evidence_packet_ids` | Evidence linking; packet IDs resolve through `/api/cases/{case_id}/packets/{packet_id}`. |
| `label`, `traffic_category` | Intentionally **empty** in PCAP exports. Real supervised labels require trusted external annotations, not guessing from a rule. |

`MODEL_INPUT_FIELDS` in `blackbox/ml_features.py` is the canonical list of candidate ML fields; align the model feature order and preprocessing to it before training.

## Training and evaluation tasks

1. Choose a **documented, labeled network-security dataset**. Verify its class labels and extraction semantics; do not use the synthetic BLACKBOX demonstration data as proof of real-world model performance.
2. Align the model's features with the export above. Prefer a **Random Forest baseline** for numeric/categorical tabular flow features and compare another supervised classifier if practical. Isolation Forest can be evaluated separately for unsupervised anomaly scoring, with different labeling assumptions.
3. Split data by capture/session, host or collection period where feasible. Randomly splitting near-duplicate flows across train/test can cause leakage.
4. Keep `label`, `traffic_category`, IP addresses, capture IDs and packet evidence IDs **out of model inputs**. Use labels for supervised training targets and scoring only. Evaluate per-class precision, recall, F1, confusion matrix and false-positive rate.
5. Deliver model artifact, compatible versions, preprocessing pipeline, feature list, reproducible training script, metrics and a Python prediction function. Never load untrusted serialized pickle/joblib model files.

## Prediction interface (planned, not yet active)

```python
# Implement this contract only after training and validation:
predict_flow(features: dict) -> dict
# Example of shape only, not a real prediction:
# {"label": 1, "score": 0.72, "model_version": "validated-model-id"}
```

`label`: 0 normal, 1 suspicious; `score`: model-defined score (not an attack probability unless calibrated and validated). BLACKBOX will keep `flow_id`/packet references **outside** the feature vector and attach them to the model result in the UI. No trained model is bundled in this release and rule alerts must not be relabeled as ML results.

## Security and data governance

Raw captures and packet metadata can contain personal or proprietary information. Use authorized traffic only. Do not commit private PCAPs, API keys, `.env`, stored SQLite case databases, or individual customer metadata to GitHub. 


## v1.8 live ML baseline

BLACKBOX now includes **unsupervised Isolation Forest**, accessed from More tools → ML anomaly screening. It fits on *this case's flows*, without labels or remote API calls, using log-scaled counts/rates, ports, TCP flag counts and protocol indicators. At least 24 flows are needed. An outlier is not an attack diagnosis, and a capture dominated by malicious flows can make the comparison unreliable. For a real supervised model, provide independently labeled training data, avoid same-capture leakage and report precision, recall, F1 and false positives on held-out captures.
