
import json
from pathlib import Path

import joblib

from .url_features import extract_url_features

import re
from urllib.parse import urlsplit, urlunsplit



import re
from urllib.parse import urlsplit, urlunsplit


def normalize_url(raw_url):
    """Convert Markdown-formatted links into plain URLs."""

    if not isinstance(raw_url, str):
        raise ValueError("URL must be a string.")

    url = raw_url.strip()

    # Remove backslashes inserted before punctuation by escaped text.
    url = re.sub(r"\\([:/\\.?=&%#\-])", r"\1", url)

    # Extract the destination from Markdown: [label](https://destination)
    markdown_match = re.fullmatch(
        r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
        url,
        flags=re.IGNORECASE,
    )

    if markdown_match:
        url = markdown_match.group(2)

    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        raise ValueError("Enter a URL starting with http:// or https://.")

    parsed = urlsplit(url)

    if not parsed.hostname:
        raise ValueError("The URL must contain a valid hostname.")

    return urlunsplit((
        parsed.scheme.lower(),
        parsed.netloc,
        parsed.path,
        parsed.query,
        "",
    ))



# Project paths are derived from this file, not hard-coded.
MODULE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = MODULE_DIR.parents[1]
MODEL_DIR = PROJECT_DIR / "malicious_url" / "models"

MODEL_PATH = (
    MODEL_DIR / "cyberguard_url_random_forest_consistent.pkl"
)
FEATURE_PATH = (
    MODEL_DIR / "url_only_features_consistent.json"
)


# Load the trained artifacts once when the module is imported.
if not MODEL_PATH.is_file():
    raise FileNotFoundError(
        f"Malicious URL model not found: {MODEL_PATH}"
    )

if not FEATURE_PATH.is_file():
    raise FileNotFoundError(
        f"URL feature schema not found: {FEATURE_PATH}"
    )

model = joblib.load(MODEL_PATH)

with FEATURE_PATH.open("r", encoding="utf-8") as file:
    FEATURE_NAMES = json.load(file)

if not hasattr(model, "feature_names_in_"):
    raise ValueError(
        "The URL model does not expose feature_names_in_. "
        "Verify its training feature schema."
    )

if list(model.feature_names_in_) != FEATURE_NAMES:
    raise ValueError(
        "URL model feature names do not match the saved schema."
    )


def analyze_url(url):
    url = normalize_url(url)
    features = extract_url_features(url)

    row = [[features[name] for name in FEATURE_NAMES]]

    prediction = int(model.predict(row)[0])
    probabilities = model.predict_proba(row)[0]

    # Define classes before using them.
    classes = list(model.classes_)

    if 1 not in classes:
        raise ValueError(
            "The URL model does not contain the expected malicious class (1)."
        )

    class_index = classes.index(1)
    malicious_probability = float(probabilities[class_index])

    # Keep your existing evidence-generation logic here.
    evidence = []

    if features.get("IsDomainIP", 0) == 1:
        evidence.append("The hostname is an IP address.")

    if features.get("HasObfuscation", 0) == 1:
        evidence.append("The URL contains possible obfuscation.")

    if features.get("IsHTTPS", 1) == 0:
        evidence.append("The URL does not use HTTPS.")

    if prediction == 1:
        recommended_action = (
            "Avoid opening this URL and verify it through an independent source."
        )
    else:
        recommended_action = (
            "No malicious classification was triggered; "
            "this does not guarantee safety."
        )

    return {
        "url": url,
        "prediction": "Malicious" if prediction == 1 else "Legitimate",
        "malicious_probability": round(malicious_probability, 6),
        "evidence": evidence,
        "recommended_action": recommended_action,
    }