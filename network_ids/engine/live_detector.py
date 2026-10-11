import os
import sys
import time
import subprocess
import pandas as pd
import joblib
import requests
from datetime import datetime
WINDUMP_INTERFACE = "4"

# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = r"C:\Users\HP\OneDrive\Desktop\IDS-P"

MODEL_PATH = os.path.join(
    BASE_DIR,
    "Model",
    "network_intrusion_random_forest_full.pkl"
)

CAPTURE_DIR = os.path.join(
    BASE_DIR,
    "Dataset",
    "Dataset"
)

PCAP_PATH = os.path.join(
    CAPTURE_DIR,
    "live_capture.pcap"
)

CSV_PATH = os.path.join(
    CAPTURE_DIR,
    "live_flows.csv"
)

CAPTURE_SECONDS = 10


# ============================================================
# LOAD MODEL
# ============================================================

print("=" * 65)
print("          SMART NETWORK IDS - LIVE MODE")
print("=" * 65)

print("\n[1] Loading Random Forest model...")

if not os.path.exists(MODEL_PATH):
    print("ERROR: Model not found:")
    print(MODEL_PATH)
    sys.exit(1)

model = joblib.load(MODEL_PATH)

print("    Model loaded successfully.")
print("    Expected features:", model.n_features_in_)


# ============================================================
# FEATURE MAPPING
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


# ============================================================
# CAPTURE FUNCTION
# ============================================================

def capture_traffic():

    print("\n" + "=" * 65)
    print("CAPTURING NETWORK TRAFFIC")
    print("=" * 65)

    print(f"\nCapturing for {CAPTURE_SECONDS} seconds...")
    print("Generate some normal network activity now.")

    # Remove old files
    if os.path.exists(PCAP_PATH):
        os.remove(PCAP_PATH)

    if os.path.exists(CSV_PATH):
        os.remove(CSV_PATH)

    try:

       subprocess.run(
    [
        "windump",
        "-i",
        WINDUMP_INTERFACE,
        "-q",
        "-w",
        PCAP_PATH,
        "-c",
        "10000"
    ],
    timeout=CAPTURE_SECONDS
)

    except subprocess.TimeoutExpired:

        print("\nCapture time completed.")

    except FileNotFoundError:

        print("\nERROR: windump was not found.")
        print("Check that:")
        print("    where windump")
        print("returns the correct executable.")

        return False

    return os.path.exists(PCAP_PATH)


# ============================================================
# PROCESS PCAP
# ============================================================

def process_pcap():

    print("\n[2] Processing captured traffic...")

    if not os.path.exists(PCAP_PATH):
        print("ERROR: No PCAP file was created.")
        return False

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

    except subprocess.CalledProcessError:

        print("ERROR: CICFlowMeter failed.")
        return False

    if not os.path.exists(CSV_PATH):

        print("ERROR: CICFlowMeter did not create CSV.")
        return False

    return True


# ============================================================
# PREDICT
# ============================================================
def detect():
 print("\n[3] Loading flow data...")

 # Check whether CSV exists
 if not os.path.exists(CSV_PATH):
 
     print("WARNING: CICFlowMeter did not create the CSV.")
     print("Skipping this capture cycle.")
     return


 # Check whether CSV is empty
 if os.path.getsize(CSV_PATH) == 0:
 
     print("WARNING: CICFlowMeter created an empty CSV.")
     print("No usable flows were generated in this capture.")
     print("Skipping this capture cycle.")
     return


 try:
 
     df = pd.read_csv(CSV_PATH)
 
 except pd.errors.EmptyDataError:
 
     print("WARNING: CSV contains no columns.")
     print("No usable flows were generated.")
     print("Skipping this capture cycle.")
     return

 except Exception as e:

    print("CSV error:", e)
    return


# Check for zero rows
 if df.empty:

    print("WARNING: CSV contains no flows.")
    print("Skipping this capture cycle.")
    return


 print("    Flows detected:", len(df))
    # ----------------------------------------
    # Build model input
    # ----------------------------------------

X = pd.DataFrame(index=df.index)
for model_feature in model.feature_names_in_:

        if model_feature not in feature_map:

            print(
                "ERROR: Missing mapping:",
                model_feature
            )

        return

        csv_feature = feature_map[model_feature]

        if csv_feature not in df.columns:

            print(
                "ERROR: Missing CSV column:",
                csv_feature
            )

        return

        X[model_feature] = df[csv_feature]

    # Exact feature order
X = X[list(model.feature_names_in_)]

print("    Model input:", X.shape)

    # ----------------------------------------
    # Prediction
    # ----------------------------------------

predictions = model.predict(X)
probabilities = model.predict_proba(X)
results = []

benign_count = 0
attack_count = 0
 
print("\n" + "=" * 65)
print("                 LIVE DETECTION RESULTS")
print("=" * 65)

for i, prediction in enumerate(predictions):

        confidence = probabilities[i][prediction] * 100
        result = {
    "time": datetime.now().strftime("%H:%M:%S"),
    "src": f"{df.iloc[i]['src_ip']}:{df.iloc[i]['src_port']}",
    "dst": f"{df.iloc[i]['dst_ip']}:{df.iloc[i]['dst_port']}",
    "protocol": str(df.iloc[i]["protocol"]),
    "prediction": "ATTACK" if prediction == 1 else "BENIGN",
    "confidence": float(confidence)
            }

        results.append(result)
         

        src_ip = df.iloc[i]["src_ip"]
        dst_ip = df.iloc[i]["dst_ip"]

        src_port = df.iloc[i]["src_port"]
        dst_port = df.iloc[i]["dst_port"]

        protocol = df.iloc[i]["protocol"]

        if prediction == 0:

            benign_count += 1

            print(
                f"\nFlow {i + 1}"
                f"\n  {src_ip}:{src_port}"
                f" -> {dst_ip}:{dst_port}"
                f"\n  Protocol   : {protocol}"
                f"\n  Prediction : BENIGN"
                f"\n  Confidence : {confidence:.2f}%"
            )

        else:

            attack_count += 1

            print("\n" + "!" * 65)

            print(
                f"🚨 SECURITY ALERT - ATTACK DETECTED"
                f"\n\nFlow {i + 1}"
                f"\n  {src_ip}:{src_port}"
                f" -> {dst_ip}:{dst_port}"
                f"\n  Protocol   : {protocol}"
                f"\n  Prediction : ATTACK"
                f"\n  Confidence : {confidence:.2f}%"
            )

            print("!" * 65)

    # ----------------------------------------
    # Summary
    # ----------------------------------------

print("\n" + "=" * 65)
print("                       SUMMARY")
print("=" * 65)

print(f"Total flows : {len(predictions)}")
print(f"Benign      : {benign_count}")
print(f"Attacks     : {attack_count}")

if attack_count > 0:

        print("\nSTATUS: 🚨 ATTACK DETECTED")

else:

        print("\nSTATUS: 🟢 NETWORK NORMAL")

print("=" * 65)


# ============================================================
# MAIN LOOP
# ============================================================

try:

    while True:

        print("\n\n")
        print("=" * 65)
        print("             SMART NETWORK IDS - LIVE")
        print("=" * 65)

        capture_success = capture_traffic()

        if capture_success:

            process_success = process_pcap()

            if process_success:

                detect()

        print("\nWaiting 2 seconds before next capture...")

        time.sleep(2)


except KeyboardInterrupt:

    print("\n\nStopping IDS...")

    if os.path.exists(PCAP_PATH):
        os.remove(PCAP_PATH)

    if os.path.exists(CSV_PATH):
        os.remove(CSV_PATH)

    print("IDS stopped.")

#sending request to backend
def send_to_dashboard(results):

    try:

        response = requests.post(
            "http://127.0.0.1:5000/api/update",
            json=results,
            timeout=2
        )

        if response.status_code == 200:
            print("    Dashboard updated.")

    except requests.exceptions.RequestException:

        print("    WARNING: Dashboard backend unavailable.")