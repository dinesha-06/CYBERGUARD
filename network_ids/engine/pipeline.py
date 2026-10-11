
from pathlib import Path
from datetime import datetime
import inspect
import shutil
import subprocess
import time

import pandas as pd

from network_ids.engine.live_capture import start_live_capture
from network_ids.engine.network_detector import NetworkIDSDetector


# --------------------------------------------------
# PATHS
# --------------------------------------------------

PROJECT_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = PROJECT_DIR / "network_ids" / "data"

PCAP_PATH = DATA_DIR / "live_capture.pcap"
FLOW_CSV_PATH = DATA_DIR / "live_flows.csv"
RESULTS_CSV_PATH = DATA_DIR / "live_detection_results.csv"

CICFLOWMETER = (
    shutil.which("cicflowmeter")
    or r"C:\Users\HP\AppData\Local\Programs\Python"
       r"\Python314\Scripts\cicflowmeter.EXE"
)

CAPTURE_SECONDS = 30


# --------------------------------------------------
# STEP 1: CAPTURE LIVE NETWORK TRAFFIC
# --------------------------------------------------


def capture_traffic(duration_seconds=CAPTURE_SECONDS):
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    print(
        f"\n[1/4] Capturing traffic for "
        f"{duration_seconds} seconds..."
    )

    # Your existing function requires output_pcap.
    start_live_capture(
        output_pcap=str(PCAP_PATH),
        duration_seconds=duration_seconds,
    )

    if not PCAP_PATH.is_file() or PCAP_PATH.stat().st_size == 0:
        raise RuntimeError(
            f"Capture file was not created or is empty: {PCAP_PATH}"
        )

    print(f"Capture saved: {PCAP_PATH}")
    print(f"PCAP size: {PCAP_PATH.stat().st_size:,} bytes")

# --------------------------------------------------
# STEP 2: CONVERT PCAP TO CICFLOWMETER CSV
# --------------------------------------------------

def convert_pcap_to_csv():
    print("\n[2/4] Converting PCAP to flow CSV...")

    if not PCAP_PATH.is_file():
        raise FileNotFoundError(f"PCAP not found: {PCAP_PATH}")

    if not CICFLOWMETER or not Path(CICFLOWMETER).is_file():
        raise FileNotFoundError(
            "CICFlowMeter executable not found. "
            "Check the CICFLOWMETER path."
        )

    command = [
        CICFLOWMETER,
        "-f", str(PCAP_PATH),
        "-c", str(FLOW_CSV_PATH),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=180,
        check=False,
    )

    if result.stdout:
        print(result.stdout[-2000:])

    if result.stderr:
        print(result.stderr[-2000:])

    if result.returncode != 0:
        raise RuntimeError(
            f"CICFlowMeter failed with exit code {result.returncode}"
        )

    if not FLOW_CSV_PATH.is_file():
        raise RuntimeError("CICFlowMeter did not create the CSV file.")

    print(f"Flow CSV saved: {FLOW_CSV_PATH}")


# --------------------------------------------------
# STEP 3: RUN THE NETWORK IDS MODELS
# --------------------------------------------------

def detect_flows():
    print("\n[3/4] Running Network IDS models...")

    flows = pd.read_csv(FLOW_CSV_PATH)

    if flows.empty:
        raise RuntimeError(
            "CICFlowMeter produced no flows. "
            "Try a longer capture duration."
        )

    print(f"Flows extracted: {len(flows)}")

    detector = NetworkIDSDetector()
    predictions = detector.predict_dataframe(flows)

    print("\nDetection summary:")
    print(predictions["Binary_Prediction"].value_counts(dropna=False))

    return predictions


# --------------------------------------------------
# STEP 4: SAVE RESULTS
# --------------------------------------------------

def save_results(predictions):
    print("\n[4/4] Saving detection results...")

    predictions = predictions.copy()

    # Add a timestamp indicating when this processing run occurred.
    predictions["Detection_Time"] = datetime.now().isoformat(
        timespec="seconds"
    )

    if RESULTS_CSV_PATH.exists():
        previous = pd.read_csv(RESULTS_CSV_PATH)
        predictions = pd.concat(
            [previous, predictions],
            ignore_index=True,
        )

    predictions.to_csv(RESULTS_CSV_PATH, index=False)

    print(f"Results saved: {RESULTS_CSV_PATH}")
    print(f"Total saved rows: {len(predictions)}")


# --------------------------------------------------
# RUN ONE COMPLETE CYCLE
# --------------------------------------------------

def run_pipeline(duration_seconds=CAPTURE_SECONDS):
    started = time.time()

    capture_traffic(duration_seconds)
    convert_pcap_to_csv()

    predictions = detect_flows()
    save_results(predictions)

    elapsed = time.time() - started

    print("\nPipeline completed successfully.")
    print(f"Elapsed time: {elapsed:.2f} seconds")

    return predictions


if __name__ == "__main__":
    run_pipeline()
