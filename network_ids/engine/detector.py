import os
import sys
import subprocess

import joblib
import pandas as pd


# ============================================================
# PATHS
# ============================================================

BASE_DIR = r"C:\Users\HP\OneDrive\Desktop\IDS-P"

MODEL_PATH = os.path.join(
    BASE_DIR,
    "Model",
    "network_intrusion_random_forest_full.pkl"
)

PCAP_PATH = os.path.join(
    BASE_DIR,
    "Dataset",
    "Dataset",
    "normal_traffic.pcap"
)

CSV_PATH = os.path.join(
    BASE_DIR,
    "Dataset",
    "Dataset",
    "flows.csv"
)


# ============================================================
# START
# ============================================================

print("=" * 60)
print("       SMART NETWORK INTRUSION DETECTION SYSTEM")
print("=" * 60)


# ============================================================
# 1. LOAD MODEL
# ============================================================

print("\n[1] Loading Random Forest model...")

if not os.path.exists(MODEL_PATH):
    print("ERROR: Model not found:")
    print(MODEL_PATH)
    sys.exit(1)

model = joblib.load(MODEL_PATH)

print("    Model loaded successfully.")
print("    Expected features:", model.n_features_in_)


# ============================================================
# 2. FEATURE MAPPING
# ============================================================

feature_map = {

    "Destination Port": "dst_port",
    "Flow Duration": "flow_duration",

    "Total Fwd Packets": "tot_fwd_pkts",
    "Total Backward Packets": "tot_bwd_pkts",

    "Total Length of Fwd Packets": "totlen_fwd_pkts",
    "Total Length of Bwd Packets": "totlen_bwd_pkts",

    "Fwd Packet Length Max": "fwd_pkt_len_max",
    "Fwd Packet Length Min": "fwd_pkt_len_min",
    "Fwd Packet Length Mean": "fwd_pkt_len_mean",
    "Fwd Packet Length Std": "fwd_pkt_len_std",

    "Bwd Packet Length Max": "bwd_pkt_len_max",
    "Bwd Packet Length Min": "bwd_pkt_len_min",
    "Bwd Packet Length Mean": "bwd_pkt_len_mean",
    "Bwd Packet Length Std": "bwd_pkt_len_std",

    "Flow Bytes/s": "flow_byts_s",
    "Flow Packets/s": "flow_pkts_s",

    "Flow IAT Mean": "flow_iat_mean",
    "Flow IAT Std": "flow_iat_std",
    "Flow IAT Max": "flow_iat_max",
    "Flow IAT Min": "flow_iat_min",

    "Fwd IAT Total": "fwd_iat_tot",
    "Fwd IAT Mean": "fwd_iat_mean",
    "Fwd IAT Std": "fwd_iat_std",
    "Fwd IAT Max": "fwd_iat_max",
    "Fwd IAT Min": "fwd_iat_min",

    "Bwd IAT Total": "bwd_iat_tot",
    "Bwd IAT Mean": "bwd_iat_mean",
    "Bwd IAT Std": "bwd_iat_std",
    "Bwd IAT Max": "bwd_iat_max",
    "Bwd IAT Min": "bwd_iat_min",

    "Fwd PSH Flags": "fwd_psh_flags",
    "Bwd PSH Flags": "bwd_psh_flags",

    "Fwd URG Flags": "fwd_urg_flags",
    "Bwd URG Flags": "bwd_urg_flags",

    "Fwd Header Length": "fwd_header_len",
    "Bwd Header Length": "bwd_header_len",

    "Fwd Packets/s": "fwd_pkts_s",
    "Bwd Packets/s": "bwd_pkts_s",

    "Min Packet Length": "pkt_len_min",
    "Max Packet Length": "pkt_len_max",
    "Packet Length Mean": "pkt_len_mean",
    "Packet Length Std": "pkt_len_std",
    "Packet Length Variance": "pkt_len_var",

    "FIN Flag Count": "fin_flag_cnt",
    "SYN Flag Count": "syn_flag_cnt",
    "RST Flag Count": "rst_flag_cnt",
    "PSH Flag Count": "psh_flag_cnt",
    "ACK Flag Count": "ack_flag_cnt",
    "URG Flag Count": "urg_flag_cnt",

    "CWE Flag Count": "cwr_flag_count",
    "ECE Flag Count": "ece_flag_cnt",

    "Down/Up Ratio": "down_up_ratio",
    "Average Packet Size": "pkt_size_avg",

    "Avg Fwd Segment Size": "fwd_seg_size_avg",
    "Avg Bwd Segment Size": "bwd_seg_size_avg",

    "Fwd Header Length.1": "fwd_header_len",

    "Fwd Avg Bytes/Bulk": "fwd_byts_b_avg",
    "Fwd Avg Packets/Bulk": "fwd_pkts_b_avg",
    "Fwd Avg Bulk Rate": "fwd_blk_rate_avg",

    "Bwd Avg Bytes/Bulk": "bwd_byts_b_avg",
    "Bwd Avg Packets/Bulk": "bwd_pkts_b_avg",
    "Bwd Avg Bulk Rate": "bwd_blk_rate_avg",

    "Subflow Fwd Packets": "subflow_fwd_pkts",
    "Subflow Fwd Bytes": "subflow_fwd_byts",

    "Subflow Bwd Packets": "subflow_bwd_pkts",
    "Subflow Bwd Bytes": "subflow_bwd_byts",

    "Init_Win_bytes_forward": "init_fwd_win_byts",
    "Init_Win_bytes_backward": "init_bwd_win_byts",

    "act_data_pkt_fwd": "fwd_act_data_pkts",
    "min_seg_size_forward": "fwd_seg_size_min",

    "Active Mean": "active_mean",
    "Active Std": "active_std",
    "Active Max": "active_max",
    "Active Min": "active_min",

    "Idle Mean": "idle_mean",
    "Idle Std": "idle_std",
    "Idle Max": "idle_max",
    "Idle Min": "idle_min",
}


print("\n    Feature mapping loaded.")
print("    Mapped features:", len(feature_map))


# ============================================================
# 3. RUN CICFLOWMETER
# ============================================================

print("\n[2] Processing PCAP with CICFlowMeter...")

if not os.path.exists(PCAP_PATH):
    print("ERROR: PCAP not found:")
    print(PCAP_PATH)
    sys.exit(1)

try:

    subprocess.run(
        [
            "cicflowmeter",
            "-f",
            PCAP_PATH,
            "-c",
            CSV_PATH
        ],
        check=True
    )

except FileNotFoundError:

    print("ERROR: CICFlowMeter command not found.")
    print("Make sure CICFlowMeter is installed and available in PATH.")
    sys.exit(1)

except subprocess.CalledProcessError as e:

    print("ERROR: CICFlowMeter failed.")
    print(e)
    sys.exit(1)


print("    CICFlowMeter completed successfully.")


# ============================================================
# 4. LOAD CSV
# ============================================================

print("\n[3] Loading flow data...")

if not os.path.exists(CSV_PATH):
    print("ERROR: flows.csv was not created.")
    sys.exit(1)

df = pd.read_csv(CSV_PATH)

print("    Number of flows:", len(df))
print("    CSV columns:", len(df.columns))


# ============================================================
# 5. BUILD MODEL INPUT
# ============================================================

print("\n[4] Preparing model features...")

X = pd.DataFrame(index=df.index)

missing_columns = []

for model_feature in model.feature_names_in_:

    if model_feature not in feature_map:

        missing_columns.append(
            model_feature
        )

        continue

    csv_feature = feature_map[model_feature]

    if csv_feature not in df.columns:

        missing_columns.append(
            f"{model_feature} -> {csv_feature}"
        )

        continue

    X[model_feature] = df[csv_feature]


# ============================================================
# 6. VALIDATION
# ============================================================

if missing_columns:

    print("\nERROR: Missing features:")

    for feature in missing_columns:
        print("   ", feature)

    sys.exit(1)


print("    Model input shape:", X.shape)
print("    Expected:", model.n_features_in_)

if X.shape[1] != model.n_features_in_:

    print("\nERROR: Feature count mismatch.")
    print("Expected:", model.n_features_in_)
    print("Received:", X.shape[1])

    sys.exit(1)


# Force exact model feature order
X = X[list(model.feature_names_in_)]

print("    Feature mapping successful.")
print("    Feature order verified.")


# ============================================================
# 7. PREDICTION
# ============================================================

print("\n[5] Running intrusion detection...")

predictions = model.predict(X)
probabilities = model.predict_proba(X)


# ============================================================
# 8. DISPLAY RESULTS
# ============================================================

print("\n")
print("=" * 60)
print("                 DETECTION RESULTS")
print("=" * 60)

benign_count = 0
attack_count = 0

for i, prediction in enumerate(predictions):

    confidence = probabilities[i][prediction] * 100

    if prediction == 0:

        label = "BENIGN"
        benign_count += 1

        print(
            f"\nFlow {i + 1}: "
            f"[BENIGN] "
            f"Confidence: {confidence:.2f}%"
        )

    elif prediction == 1:

        label = "ATTACK"
        attack_count += 1

        print(
            f"\nFlow {i + 1}: "
            f"[!!! ATTACK !!!] "
            f"Confidence: {confidence:.2f}%"
        )

        print(
            "    SECURITY ALERT: "
            "Suspicious network activity detected!"
        )


# ============================================================
# 9. SUMMARY
# ============================================================

print("\n")
print("=" * 60)
print("                    SUMMARY")
print("=" * 60)

print("Total flows :", len(predictions))
print("Benign      :", benign_count)
print("Attacks     :", attack_count)

if attack_count > 0:

    print("\nSTATUS: ATTACK DETECTED")

else:

    print("\nSTATUS: NETWORK NORMAL")

print("=" * 60)