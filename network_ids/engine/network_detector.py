
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


# --------------------------------------------------
# PATH CONFIGURATION
# --------------------------------------------------

# network_detector.py is located in:
# CYBERGUARD/network_ids/engine/network_detector.py

PROJECT_DIR = Path(__file__).resolve().parents[2]
MODEL_DIR = PROJECT_DIR / "network_ids" / "models"

BINARY_MODEL_PATH = MODEL_DIR / "network_intrusion_random_forest_full.pkl"
ATTACK_MODEL_PATH = MODEL_DIR / "network_attack_classifier.pkl"


# --------------------------------------------------
# CICFlowMeter FEATURE MAPPING
# Original model feature name -> shortened CSV name
# --------------------------------------------------

FEATURE_MAP = {
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


# --------------------------------------------------
# NETWORK IDS DETECTOR
# --------------------------------------------------

class NetworkIDSDetector:

    def __init__(
        self,
        binary_model_path=BINARY_MODEL_PATH,
        attack_model_path=ATTACK_MODEL_PATH,
    ):
        self.binary_model_path = Path(binary_model_path)
        self.attack_model_path = Path(attack_model_path)

        if not self.binary_model_path.exists():
            raise FileNotFoundError(
                f"Binary model not found: {self.binary_model_path}"
            )

        if not self.attack_model_path.exists():
            raise FileNotFoundError(
                f"Attack classifier not found: {self.attack_model_path}"
            )

        self.binary_model = joblib.load(self.binary_model_path)
        self.attack_model = joblib.load(self.attack_model_path)

        if not hasattr(self.binary_model, "feature_names_in_"):
            raise ValueError(
                "Binary model does not contain feature_names_in_."
            )

        if not hasattr(self.attack_model, "feature_names_in_"):
            raise ValueError(
                "Attack model does not contain feature_names_in_."
            )

        self.feature_names = list(self.binary_model.feature_names_in_)
        attack_features = list(self.attack_model.feature_names_in_)

        if self.feature_names != attack_features:
            raise ValueError(
                "The binary and attack models require different feature "
                "names or feature orders."
            )

        print("Network IDS models loaded successfully.")
        print(f"Binary model: {self.binary_model_path.name}")
        print(f"Attack model: {self.attack_model_path.name}")
        print(f"Required features: {len(self.feature_names)}")

    # --------------------------------------------------
    # PREPARE CSV FEATURES FOR THE MODELS
    # --------------------------------------------------

    def _prepare_features(self, flows):
        flows = flows.copy()

        # Normalize column names without changing their meaning.
        flows.columns = [str(col).strip() for col in flows.columns]

        if flows.columns.duplicated().any():
            duplicates = flows.columns[flows.columns.duplicated()].tolist()
            raise ValueError(
                f"Duplicate CSV column names found: {duplicates}"
            )

        model_frame = flows.copy()

        # Create original CICFlowMeter feature columns from the
        # shortened feature names used by the live CSV.
        for model_name, csv_name in FEATURE_MAP.items():
            if (
                model_name not in model_frame.columns
                and csv_name in flows.columns
            ):
                model_frame[model_name] = flows[csv_name]

        missing = [
            name for name in self.feature_names
            if name not in model_frame.columns
        ]

        if missing:
            raise ValueError(
                "Required model features are missing after mapping.\n"
                f"Missing count: {len(missing)}\n"
                f"Missing features: {missing}"
            )

        # Preserve the exact feature order used during training.
        X = model_frame.loc[:, self.feature_names].copy()

        for col in X.columns:
            X[col] = pd.to_numeric(X[col], errors="coerce")

        X = X.replace([np.inf, -np.inf], np.nan)

        # Rows with missing or invalid model features are not predicted.
        valid_mask = X.notna().all(axis=1)
        valid_X = X.loc[valid_mask]

        return flows, valid_X, valid_mask

    # --------------------------------------------------
    # PREDICT FLOWS
    # --------------------------------------------------

    def predict_dataframe(self, flows):
        if not isinstance(flows, pd.DataFrame):
            raise TypeError("flows must be a pandas DataFrame.")

        if flows.empty:
            return flows.copy()

        flows, valid_X, valid_mask = self._prepare_features(flows)

        # Keep original metadata columns in the output.
        results = flows.copy()

        results["Binary_Prediction"] = "INVALID_FLOW"
        results["Attack_Type"] = None
        results["Binary_Model_Score"] = np.nan
        results["Attack_Model_Score"] = np.nan
        results["Detection_Status"] = "invalid_features"

        if valid_X.empty:
            return results

        # Step 1: Binary classification: BENIGN or ATTACK.
        binary_predictions = self.binary_model.predict(valid_X)

        binary_classes = list(self.binary_model.classes_)
        if 0 not in binary_classes or 1 not in binary_classes:
            raise ValueError(
                "Expected binary model classes 0 (BENIGN) and 1 (ATTACK), "
                f"but found: {binary_classes}"
            )

        binary_scores = None
        if hasattr(self.binary_model, "predict_proba"):
            probabilities = self.binary_model.predict_proba(valid_X)
            attack_class_index = binary_classes.index(1)
            binary_scores = probabilities[:, attack_class_index]

        results.loc[valid_X.index, "Binary_Prediction"] = np.where(
            binary_predictions == 0,
            "BENIGN",
            "ATTACK",
        )

        results.loc[valid_X.index, "Detection_Status"] = np.where(
            binary_predictions == 0,
            "benign",
            "attack_detected",
        )

        if binary_scores is not None:
            results.loc[valid_X.index, "Binary_Model_Score"] = binary_scores

        # Step 2: Classify only flows predicted as attacks.
        attack_positions = np.flatnonzero(binary_predictions == 1)

        if len(attack_positions) > 0:
            attack_X = valid_X.iloc[attack_positions]
            attack_indices = attack_X.index

            attack_predictions = self.attack_model.predict(attack_X)

            results.loc[attack_indices, "Attack_Type"] = attack_predictions

            # Store the highest predicted class probability, when available.
            if hasattr(self.attack_model, "predict_proba"):
                attack_probabilities = self.attack_model.predict_proba(
                    attack_X
                )
                max_attack_scores = attack_probabilities.max(axis=1)

                results.loc[
                    attack_indices, "Attack_Model_Score"
                ] = max_attack_scores

        return results

    # --------------------------------------------------
    # PREDICT DIRECTLY FROM A CSV FILE
    # --------------------------------------------------

    def predict_csv(self, csv_path, output_path=None):
        csv_path = Path(csv_path)

        if not csv_path.exists():
            raise FileNotFoundError(f"CSV file not found: {csv_path}")

        flows = pd.read_csv(csv_path)
        results = self.predict_dataframe(flows)

        if output_path is not None:
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            results.to_csv(output_path, index=False)
            print(f"Detection results saved to: {output_path}")

        return results
