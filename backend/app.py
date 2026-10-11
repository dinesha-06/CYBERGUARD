
from pathlib import Path
from datetime import datetime, timezone
from threading import Timer
import webbrowser

import pandas as pd
from flask import (
    Flask,
    jsonify,
    request,
    send_from_directory,
)
from flask_cors import CORS


# =========================================================
# 1. PROJECT CONFIGURATION
# =========================================================

PROJECT_DIR = Path(__file__).resolve().parents[1]
FRONTEND_DIR = PROJECT_DIR / "frontend"

NETWORK_RESULTS = (
    PROJECT_DIR
    / "network_ids"
    / "data"
    / "live_detection_results.csv"
)

HOST = "127.0.0.1"
PORT = 5000

app = Flask(__name__)
CORS(app)


# =========================================================
# 2. DATA HELPERS
# =========================================================

def load_network_results():
    """Read the latest saved Network IDS predictions."""

    if not NETWORK_RESULTS.is_file():
        return pd.DataFrame()

    try:
        return pd.read_csv(NETWORK_RESULTS)
    except (OSError, pd.errors.ParserError) as exc:
        raise RuntimeError(
            f"Unable to read Network IDS results: {exc}"
        ) from exc


def records_for_api(dataframe):
    """Convert DataFrame records to JSON-safe dictionaries."""

    clean_df = dataframe.astype(object).where(
        pd.notna(dataframe), None
    )

    return clean_df.to_dict(orient="records")


def get_prediction_columns(df):
    """Return normalized prediction and status columns."""

    if "Binary_Prediction" in df.columns:
        predictions = (
            df["Binary_Prediction"]
            .fillna("")
            .astype(str)
            .str.strip()
            .str.upper()
        )
    else:
        predictions = pd.Series("", index=df.index)

    if "Detection_Status" in df.columns:
        statuses = (
            df["Detection_Status"]
            .fillna("")
            .astype(str)
            .str.strip()
            .str.lower()
        )
    else:
        statuses = pd.Series("", index=df.index)

    return predictions, statuses


def error_response(exc):
    """Return a consistent API error response."""

    app.logger.exception("CyberGuard API error: %s", exc)

    return jsonify({
        "error": str(exc),
    }), 500


# =========================================================
# 3. FRONTEND ROUTES
# =========================================================

@app.get("/")
def home():
    """Serve the CyberGuard dashboard."""

    if not (FRONTEND_DIR / "index.html").is_file():
        return (
            "CyberGuard frontend not found. "
            "Create frontend/index.html first.",
            404,
        )

    return send_from_directory(FRONTEND_DIR, "index.html")


@app.get("/favicon.ico")
def favicon():
    """Avoid a 404 when the browser requests a favicon."""

    favicon_path = FRONTEND_DIR / "favicon.ico"

    if favicon_path.is_file():
        return send_from_directory(FRONTEND_DIR, "favicon.ico")

    return "", 204


# =========================================================
# 4. HEALTH CHECK
# =========================================================

@app.get("/api/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "CyberGuard API",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "frontend_available": (
            FRONTEND_DIR / "index.html"
        ).is_file(),
        "network_results_available": NETWORK_RESULTS.is_file(),
    })


# =========================================================
# 5. DASHBOARD SUMMARY
# =========================================================

@app.get("/api/dashboard")
def dashboard():
    try:
        df = load_network_results()

        if df.empty:
            return jsonify({
                "total_flows": 0,
                "benign_flows": 0,
                "attacks_detected": 0,
                "invalid_flows": 0,
                "attack_types": {},
                "recent_alerts": [],
                "message": "No Network IDS results available yet.",
            })

        predictions, statuses = get_prediction_columns(df)

        attack_mask = predictions.eq("ATTACK")
        benign_mask = predictions.eq("BENIGN")
        invalid_mask = statuses.eq("invalid_features")

        attack_types = {}

        if "Attack_Type" in df.columns:
            types = (
                df.loc[attack_mask, "Attack_Type"]
                .dropna()
                .astype(str)
            )

            attack_types = {
                str(name): int(count)
                for name, count in types.value_counts().items()
            }

        recent_alerts = (
            df.loc[attack_mask]
            .tail(10)
            .iloc[::-1]
        )

        return jsonify({
            "total_flows": int(len(df)),
            "benign_flows": int(benign_mask.sum()),
            "attacks_detected": int(attack_mask.sum()),
            "invalid_flows": int(invalid_mask.sum()),
            "attack_types": attack_types,
            "recent_alerts": records_for_api(recent_alerts),
            "last_updated": datetime.now(
                timezone.utc
            ).isoformat(),
        })

    except RuntimeError as exc:
        return error_response(exc)


# =========================================================
# 6. NETWORK FLOW ENDPOINT
# =========================================================

@app.get("/api/network/flows")
def network_flows():
    try:
        df = load_network_results()

        limit = request.args.get("limit", default=50, type=int)

        if limit is None or limit < 1:
            return jsonify({
                "error": "limit must be a positive integer"
            }), 400

        limit = min(limit, 500)

        recent = df.tail(limit).iloc[::-1]

        return jsonify({
            "count": int(len(recent)),
            "flows": records_for_api(recent),
        })

    except RuntimeError as exc:
        return error_response(exc)


# =========================================================
# 7. NETWORK ALERTS ENDPOINT
# =========================================================

@app.get("/api/network/alerts")
def network_alerts():
    try:
        df = load_network_results()

        if "Binary_Prediction" not in df.columns:
            return jsonify({
                "count": 0,
                "alerts": [],
            })

        predictions, _ = get_prediction_columns(df)
        attack_mask = predictions.eq("ATTACK")

        alerts = (
            df.loc[attack_mask]
            .tail(100)
            .iloc[::-1]
        )

        return jsonify({
            "count": int(len(alerts)),
            "alerts": records_for_api(alerts),
        })

    except RuntimeError as exc:
        return error_response(exc)


# =========================================================
# 8. NETWORK IDS FILE STATUS
# =========================================================

@app.get("/api/network/status")
def network_status():
    """Report result-file status without running packet capture."""

    return jsonify({
        "results_file": str(NETWORK_RESULTS),
        "results_available": NETWORK_RESULTS.is_file(),
        "results_size_bytes": (
            NETWORK_RESULTS.stat().st_size
            if NETWORK_RESULTS.is_file()
            else 0
        ),
        "capture_pipeline": "separate process",
        "note": (
            "This API reads saved predictions. "
            "It does not start live packet capture."
        ),
    })


# =========================================================
# 9. START CYBERGUARD
# =========================================================

if __name__ == "__main__":
    dashboard_url = f"http://{HOST}:{PORT}/"

    print("\n" + "=" * 58)
    print("             CYBERGUARD SECURITY PLATFORM")
    print("=" * 58)
    print(f"Dashboard:       {dashboard_url}")
    print(f"Health API:      {dashboard_url}api/health")
    print(f"Dashboard API:   {dashboard_url}api/dashboard")
    print(f"Network flows:   {dashboard_url}api/network/flows")
    print(f"Network alerts:  {dashboard_url}api/network/alerts")
    print("=" * 58)

    if not (FRONTEND_DIR / "index.html").is_file():
        print("WARNING: frontend/index.html was not found.")

    # Open the dashboard once the local server starts.
    Timer(
        1.0,
        lambda: webbrowser.open(dashboard_url),
    ).start()

    app.run(
        host=HOST,
        port=PORT,
        debug=False,
        use_reloader=False,
    )
