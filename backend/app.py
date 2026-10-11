
from __future__ import annotations

import logging
import re
import subprocess
import sys
import threading
import time
import webbrowser
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import joblib
import pandas as pd
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS


# ============================================================
# PATHS AND CONFIGURATION
# ============================================================

PROJECT_DIR = Path(__file__).resolve().parents[1]
FRONTEND_DIR = PROJECT_DIR / "frontend"

NETWORK_DIR = PROJECT_DIR / "network_ids"
NETWORK_DATA_DIR = NETWORK_DIR / "data"
NETWORK_RESULTS_PATH = NETWORK_DATA_DIR / "live_detection_results.csv"
PIPELINE_MODULE = "network_ids.engine.pipeline"

PHISHING_MODEL_DIR = PROJECT_DIR / "phishing_detection" / "models"
PHISHING_MODEL_PATH = PHISHING_MODEL_DIR / "cyberguard_calibrated_svm.pkl"
PHISHING_VECTORIZER_PATH = PHISHING_MODEL_DIR / "cyberguard_tfidf.pkl"

HOST = "127.0.0.1"
PORT = 5000

# Delay before retrying a pipeline process that exits.
PIPELINE_RESTART_DELAY = 3

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
)
logger = logging.getLogger("CyberGuard")

app = Flask(__name__, static_folder=None)
CORS(app)

# Ensure imports and the pipeline module resolve from the project root.
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))


# ============================================================
# THREAD-SAFE LIVE IDS WORKER STATE
# ============================================================

capture_lock = threading.Lock()
capture_stop_event = threading.Event()

capture_thread = None
pipeline_process = None

capture_status = {
    "running": False,
    "state": "waiting",
    "started_at": None,
    "last_started": None,
    "last_completed": None,
    "last_exit_code": None,
    "last_error": None,
    "process_restarts": 0,
}


def utc_timestamp():
    return datetime.now(timezone.utc).isoformat()


def start_live_ids_worker():
    """Start at most one background worker for the IDS pipeline."""
    global capture_thread

    with capture_lock:
        if capture_thread is not None and capture_thread.is_alive():
            return False

        capture_stop_event.clear()
        capture_status["running"] = True
        capture_status["state"] = "starting"
        capture_status["started_at"] = utc_timestamp()
        capture_status["last_error"] = None

        capture_thread = threading.Thread(
            target=live_ids_worker,
            name="CyberGuard-Live-IDS",
            daemon=True,
        )
        capture_thread.start()

        logger.info("Automatic live IDS worker requested.")
        return True


def live_ids_worker():
    """
    Run the existing pipeline module in a child process.

    If the pipeline completes one capture cycle and exits, restart it
    after a short delay. If it contains its own continuous loop, it
    remains running in the child process until it exits.
    """
    global pipeline_process

    capture_status["running"] = True

    try:
        while not capture_stop_event.is_set():
            capture_status["state"] = "starting_pipeline"
            capture_status["last_started"] = utc_timestamp()

            command = [
                sys.executable,
                "-m",
                PIPELINE_MODULE,
            ]

            logger.info("Starting IDS pipeline: %s", " ".join(command))

            try:
                pipeline_process = subprocess.Popen(
                    command,
                    cwd=str(PROJECT_DIR),
                )

                capture_status["state"] = "capturing_and_detecting"

                while pipeline_process.poll() is None:
                    if capture_stop_event.wait(1):
                        logger.info("Stopping IDS pipeline process.")
                        pipeline_process.terminate()

                        try:
                            pipeline_process.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            pipeline_process.kill()
                            pipeline_process.wait(timeout=5)

                        break

                exit_code = pipeline_process.poll()
                capture_status["last_exit_code"] = exit_code

                if capture_stop_event.is_set():
                    break

                if exit_code == 0:
                    capture_status["last_completed"] = utc_timestamp()
                    capture_status["last_error"] = None
                    capture_status["state"] = "cycle_completed"
                    logger.info("IDS pipeline process completed.")
                else:
                    message = (
                        f"IDS pipeline exited with code {exit_code}. "
                        "Check the terminal output for details."
                    )
                    capture_status["last_error"] = message
                    capture_status["state"] = "error"
                    logger.error(message)

                capture_status["process_restarts"] += 1

            except Exception as exc:
                capture_status["last_error"] = str(exc)
                capture_status["state"] = "error"
                logger.exception("Could not launch the IDS pipeline.")

            finally:
                pipeline_process = None

            # Restart after a completed one-shot pipeline or an error.
            if capture_stop_event.wait(PIPELINE_RESTART_DELAY):
                break

    finally:
        capture_status["running"] = False
        capture_status["state"] = "stopped"
        logger.info("Live IDS worker stopped.")


def stop_live_ids_worker():
    """Stop the child process when the backend is shutting down."""
    capture_stop_event.set()

    process = pipeline_process
    if process is not None and process.poll() is None:
        try:
            process.terminate()
            process.wait(timeout=5)
        except Exception:
            try:
                process.kill()
            except Exception:
                pass


# ============================================================
# LOAD URL AND PHISHING MODELS
# ============================================================

url_detector = None
url_detector_available = False
url_detector_error = None

phishing_model = None
phishing_vectorizer = None
phishing_detector_available = False
phishing_detector_error = None

try:
    from malicious_url.src.url_detector import analyze_url

    url_detector = analyze_url
    url_detector_available = True
    logger.info("Malicious URL detector loaded.")

except Exception as exc:
    url_detector_error = str(exc)
    logger.exception("Could not load the malicious URL detector.")

try:
    if not PHISHING_MODEL_PATH.exists():
        raise FileNotFoundError(str(PHISHING_MODEL_PATH))

    if not PHISHING_VECTORIZER_PATH.exists():
        raise FileNotFoundError(str(PHISHING_VECTORIZER_PATH))

    phishing_model = joblib.load(PHISHING_MODEL_PATH)
    phishing_vectorizer = joblib.load(PHISHING_VECTORIZER_PATH)

    phishing_detector_available = True
    logger.info("Phishing detector loaded.")

except Exception as exc:
    phishing_detector_error = str(exc)
    logger.exception("Could not load the phishing detector.")


# ============================================================
# GENERAL HELPERS
# ============================================================

def json_error(message, status_code=400, **extra):
    payload = {
        "success": False,
        "error": message,
        "timestamp": utc_timestamp(),
    }
    payload.update(extra)
    return jsonify(payload), status_code


def clean_url_input(raw_url):
    """Clean ordinary or Markdown-wrapped URL input."""
    if not isinstance(raw_url, str):
        return ""

    url = raw_url.strip().replace("\\", "").strip()

    match = re.search(
        r"\[[^\]]*\]\((https?://[^)\s]+)\)",
        url,
        flags=re.IGNORECASE,
    )

    if match:
        url = match.group(1)

    if url.startswith("<") and url.endswith(">"):
        url = url[1:-1].strip()

    return url.strip()


def read_network_results():
    """Read the latest results CSV."""
    if not NETWORK_RESULTS_PATH.exists():
        return pd.DataFrame()

    try:
        return pd.read_csv(NETWORK_RESULTS_PATH, low_memory=False)
    except pd.errors.EmptyDataError:
        return pd.DataFrame()
    except Exception:
        logger.exception("Could not read network results CSV.")
        return pd.DataFrame()


def json_safe_records(df, limit=None):
    if df.empty:
        return []

    result = df.tail(limit).copy() if limit else df.copy()
    result = result.astype(object).where(pd.notna(result), None)
    return result.to_dict(orient="records")


def find_column(df, candidates):
    normalized = {
        str(column).strip().lower(): column
        for column in df.columns
    }

    for candidate in candidates:
        column = normalized.get(candidate.strip().lower())
        if column is not None:
            return column

    return None


def normalize_text(value):
    return str(value).strip().lower() if value is not None else ""


def get_network_summary(df):
    if df.empty:
        return {
            "total_flows": 0,
            "benign_flows": 0,
            "attack_flows": 0,
            "unknown_flows": 0,
            "attack_types": {},
        }

    prediction_col = find_column(
        df, ["Binary_Prediction", "Prediction", "Label", "Class"]
    )
    status_col = find_column(df, ["Detection_Status", "Status"])
    attack_col = find_column(df, ["Attack_Type", "Attack Type"])

    benign = 0
    attacks = 0
    unknown = 0

    for _, row in df.iterrows():
        prediction = (
            normalize_text(row[prediction_col])
            if prediction_col is not None else ""
        )
        status = (
            normalize_text(row[status_col])
            if status_col is not None else ""
        )

        if prediction in {"0", "0.0", "benign", "normal"}:
            benign += 1
        elif prediction in {"1", "1.0", "attack", "malicious"}:
            attacks += 1
        elif status in {"benign", "normal"}:
            benign += 1
        elif status in {"attack", "malicious", "alert", "detected"}:
            attacks += 1
        else:
            unknown += 1

    attack_types = {}

    if attack_col is not None:
        values = df[attack_col].dropna().astype(str).str.strip()
        values = values[
            ~values.str.lower().isin(
                {"", "nan", "none", "benign", "normal"}
            )
        ]
        attack_types = dict(Counter(values).most_common(10))

    return {
        "total_flows": int(len(df)),
        "benign_flows": int(benign),
        "attack_flows": int(attacks),
        "unknown_flows": int(unknown),
        "attack_types": attack_types,
    }


def get_attack_rows(df):
    if df.empty:
        return pd.DataFrame()

    prediction_col = find_column(
        df, ["Binary_Prediction", "Prediction", "Label", "Class"]
    )
    status_col = find_column(df, ["Detection_Status", "Status"])

    mask = pd.Series(False, index=df.index)

    if prediction_col is not None:
        predictions = df[prediction_col].astype(str).str.strip().str.lower()
        mask |= predictions.isin({"1", "1.0", "attack", "malicious"})

    if status_col is not None:
        statuses = df[status_col].astype(str).str.strip().str.lower()
        mask |= statuses.isin({"attack", "malicious", "alert", "detected"})

    return df.loc[mask]


# ============================================================
# FRONTEND ROUTE — START CAPTURE ON DASHBOARD OPEN
# ============================================================

@app.route("/", methods=["GET"])
def index():
    start_live_ids_worker()

    index_file = FRONTEND_DIR / "index.html"
    if not index_file.exists():
        return "CyberGuard frontend/index.html was not found.", 404

    return send_from_directory(str(FRONTEND_DIR), "index.html")


# ============================================================
# HEALTH AND CAPTURE STATUS
# ============================================================

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "service": "CyberGuard API",
        "status": "online",
        "timestamp": utc_timestamp(),
        "modules": {
            "network_ids": {
                "available": NETWORK_RESULTS_PATH.exists(),
                "pipeline_module_exists": (
                    (NETWORK_DIR / "engine" / "pipeline.py").exists()
                ),
            },
            "malicious_url": {
                "available": url_detector_available,
                "error": url_detector_error,
            },
            "phishing_detection": {
                "available": phishing_detector_available,
                "error": phishing_detector_error,
            },
        },
    })


@app.route("/api/network/capture/status", methods=["GET"])
def live_capture_status():
    return jsonify({
        "success": True,
        **capture_status,
        "pipeline_module": PIPELINE_MODULE,
        "timestamp": utc_timestamp(),
    })


@app.route("/api/network/status", methods=["GET"])
def network_status():
    exists = NETWORK_RESULTS_PATH.exists()
    updated = None
    size_bytes = 0

    if exists:
        try:
            stat = NETWORK_RESULTS_PATH.stat()
            updated = datetime.fromtimestamp(
                stat.st_mtime,
                tz=timezone.utc,
            ).isoformat()
            size_bytes = stat.st_size
        except OSError:
            logger.exception("Could not inspect network CSV.")

    df = read_network_results()

    return jsonify({
        "success": True,
        "available": exists,
        "results_file": str(NETWORK_RESULTS_PATH),
        "last_updated": updated,
        "file_size_bytes": size_bytes,
        "total_rows": int(len(df)),
        "timestamp": utc_timestamp(),
    })


# ============================================================
# DASHBOARD SUMMARY
# ============================================================

@app.route("/api/dashboard", methods=["GET"])
def dashboard():
    df = read_network_results()
    summary = get_network_summary(df)
    alerts = get_attack_rows(df)

    return jsonify({
        "success": True,
        "timestamp": utc_timestamp(),
        **summary,
        "recent_alerts": json_safe_records(alerts, limit=10),
        "modules": {
            "network_ids": True,
            "malicious_url": url_detector_available,
            "phishing_detection": phishing_detector_available,
        },
    })


# ============================================================
# NETWORK FLOWS AND ALERTS
# ============================================================

@app.route("/api/network/flows", methods=["GET"])
def network_flows():
    df = read_network_results()

    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 1000))
    except (TypeError, ValueError):
        limit = 100

    return jsonify({
        "success": True,
        "count": min(len(df), limit),
        "total": int(len(df)),
        "flows": json_safe_records(df, limit=limit),
        "timestamp": utc_timestamp(),
    })


@app.route("/api/network/alerts", methods=["GET"])
def network_alerts():
    df = read_network_results()
    alerts = get_attack_rows(df)

    try:
        limit = max(1, min(int(request.args.get("limit", 100)), 1000))
    except (TypeError, ValueError):
        limit = 100

    return jsonify({
        "success": True,
        "count": min(len(alerts), limit),
        "total_alerts": int(len(alerts)),
        "alerts": json_safe_records(alerts, limit=limit),
        "timestamp": utc_timestamp(),
    })


# ============================================================
# MALICIOUS URL ANALYSIS
# ============================================================

@app.route("/api/url/analyze", methods=["POST"])
def analyze_malicious_url():
    if not url_detector_available:
        return json_error(
            "Malicious URL detector is unavailable.",
            503,
            details=url_detector_error,
        )

    if not request.is_json:
        return json_error("Send the request as JSON.")

    payload = request.get_json(silent=True) or {}
    url = clean_url_input(payload.get("url", ""))

    if not url:
        return json_error("Please provide a URL.")

    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        return json_error(
            "Enter a complete URL starting with http:// or https://."
        )

    try:
        result = url_detector(url)

        if not isinstance(result, dict):
            return json_error(
                "The URL detector returned an unexpected response.",
                500,
            )

        response = {
            "success": True,
            **result,
            "url": result.get("url", url),
            "timestamp": utc_timestamp(),
        }
        return jsonify(response)

    except Exception as exc:
        logger.exception("URL analysis failed.")
        return json_error("URL analysis failed.", 500, details=str(exc))


# ============================================================
# PHISHING TEXT ANALYSIS
# ============================================================

@app.route("/api/phishing/analyze", methods=["POST"])
def analyze_phishing_text():
    if not phishing_detector_available:
        return json_error(
            "Phishing detector is unavailable.",
            503,
            details=phishing_detector_error,
        )

    if not request.is_json:
        return json_error("Send the request as JSON.")

    payload = request.get_json(silent=True) or {}
    text_input = payload.get("text", "")

    if not isinstance(text_input, str) or not text_input.strip():
        return json_error("Please provide email or message text.")

    text_input = text_input.strip()

    if len(text_input) > 100_000:
        return json_error("Maximum input length is 100,000 characters.")

    try:
        features = phishing_vectorizer.transform([text_input])
        prediction = phishing_model.predict(features)[0]
        label = str(prediction).strip().lower()

        suspicious_labels = {
            "1", "1.0", "phishing", "suspicious", "spam", "malicious"
        }
        legitimate_labels = {
            "0", "0.0", "legitimate", "benign", "ham", "safe"
        }

        if label in suspicious_labels:
            classification = "Suspicious"
            recommendation = (
                "Do not click links, open unexpected attachments, "
                "or share credentials until the sender is verified."
            )
        elif label in legitimate_labels:
            classification = "Likely Legitimate"
            recommendation = (
                "The model did not flag the message. This does not "
                "guarantee the message is safe."
            )
        else:
            classification = "Unrecognized Model Label"
            recommendation = (
                "Verify the model's class-label mapping before relying "
                "on this result."
            )

        suspicious_probability = None

        if hasattr(phishing_model, "predict_proba"):
            probabilities = phishing_model.predict_proba(features)[0]
            classes = list(phishing_model.classes_)

            for index, class_label in enumerate(classes):
                if str(class_label).strip().lower() in suspicious_labels:
                    suspicious_probability = float(probabilities[index])
                    break

        return jsonify({
            "success": True,
            "classification": classification,
            "prediction": str(prediction),
            "suspicious_probability": suspicious_probability,
            "confidence_percent": (
                round(suspicious_probability * 100, 2)
                if suspicious_probability is not None else None
            ),
            "recommended_action": recommendation,
            "text_length": len(text_input),
            "timestamp": utc_timestamp(),
        })

    except Exception as exc:
        logger.exception("Phishing analysis failed.")
        return json_error(
            "Phishing analysis failed.",
            500,
            details=str(exc),
        )


# ============================================================
# ERROR HANDLERS
# ============================================================

@app.errorhandler(404)
def not_found(error):
    if request.path.startswith("/api/"):
        return json_error("API endpoint not found.", 404)
    return "Page not found.", 404


@app.errorhandler(405)
def method_not_allowed(error):
    if request.path.startswith("/api/"):
        return json_error("HTTP method not allowed.", 405)
    return "Method not allowed.", 405


# ============================================================
# START FLASK
# ============================================================

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("       CYBERGUARD AI SECURITY CENTER")
    print("=" * 60)
    print(f"Project root      : {PROJECT_DIR}")
    print(f"Dashboard         : http://{HOST}:{PORT}/")
    print(f"Health API        : http://{HOST}:{PORT}/api/health")
    print(f"Capture status    : http://{HOST}:{PORT}/api/network/capture/status")
    print(f"IDS pipeline      : {NETWORK_DIR / 'engine' / 'pipeline.py'}")
    print(f"URL detector      : {'Available' if url_detector_available else 'Unavailable'}")
    print(f"Phishing detector : {'Available' if phishing_detector_available else 'Unavailable'}")
    print("=" * 60 + "\n")

    try:
        threading.Timer(
            1.0,
            lambda: webbrowser.open(f"http://{HOST}:{PORT}/"),
        ).start()

        app.run(
            host=HOST,
            port=PORT,
            debug=False,
            use_reloader=False,
            threaded=True,
        )
    finally:
        stop_live_ids_worker()
