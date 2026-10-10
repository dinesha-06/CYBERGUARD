import json
import joblib
from pathlib import Path

from url_features import extract_url_features


BASE_DIR = Path(__file__).resolve().parents[1]
MODEL_DIR = r"C:\Users\HP\OneDrive\Desktop\BPUT\CYBERGUARD\malicious_url\models"

MODEL_PATH = r"C:\Users\HP\OneDrive\Desktop\BPUT\CYBERGUARD\malicious_url\models\cyberguard_url_random_forest_consistent.pkl"
FEATURE_PATH =r"C:\Users\HP\OneDrive\Desktop\BPUT\CYBERGUARD\malicious_url\models\url_only_features_consistent.json"

model = joblib.load(MODEL_PATH)

with open(FEATURE_PATH, "r", encoding="utf-8") as f:
    FEATURE_NAMES = json.load(f)


def analyze_url(url: str) -> dict:
    features = extract_url_features(url)

    # The feature order must exactly match the training schema.
    row = [[features[name] for name in FEATURE_NAMES]]

    prediction = int(model.predict(row)[0])

    probabilities = model.predict_proba(row)[0]
    class_index = list(model.classes_).index(1)
    malicious_probability = float(probabilities[class_index])

    evidence = []

    if features["IsDomainIP"]:
        evidence.append("The hostname is an IP address.")

    if features["HasObfuscation"]:
        evidence.append("Potential URL obfuscation was detected.")

    if features["NoOfSubDomain"] >= 3:
        evidence.append("The hostname contains multiple subdomain labels.")

    if not features["IsHTTPS"]:
        evidence.append("The URL does not use HTTPS.")

    return {
        "url": url,
        "prediction": "Malicious" if prediction == 1 else "Legitimate",
        "malicious_probability": round(malicious_probability, 6),
        "evidence": evidence,
        "recommended_action": (
            "Avoid opening this URL and verify it through an independent source."
            if prediction == 1
            else "No malicious classification was triggered; this does not guarantee safety."
        ),
    }