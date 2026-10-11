import pandas as pd
import numpy as np
import joblib


# -----------------------------
# Load models
# -----------------------------

binary_model = joblib.load(
    r"C:\Users\HP\OneDrive\Desktop\IDS-P\Model\network_intrusion_random_forest_full.pkl"
)

attack_model = joblib.load(
    r"C:\Users\HP\OneDrive\Desktop\IDS-P\Model\network_attack_classifier.pkl"
)

print("Models loaded successfully!")


# -----------------------------
# Load CICFlowMeter CSV
# -----------------------------

csv_file = "../data/live_flows.csv"

df = pd.read_csv(csv_file)

print("Flows loaded:", len(df))


# -----------------------------
# Clean column names
# -----------------------------

df.columns = df.columns.str.strip()


# -----------------------------
# Get feature names
# -----------------------------

binary_features = list(
    binary_model.feature_names_in_
)


# -----------------------------
# Check features
# -----------------------------

missing = [
    feature
    for feature in binary_features
    if feature not in df.columns
]

if missing:
    print("\nMissing features:")
    for feature in missing:
        print(feature)

    raise ValueError(
        "CICFlowMeter CSV does not match the model features."
    )


# -----------------------------
# Prepare input
# -----------------------------

X = df[binary_features].copy()

X = X.replace(
    [np.inf, -np.inf],
    np.nan
)

valid = ~X.isna().any(axis=1)

X = X[valid]
original_rows = df[valid].copy()


print("Valid flows:", len(X))


# -----------------------------
# MODEL B
# BENIGN / ATTACK
# -----------------------------

binary_prediction = binary_model.predict(X)


# -----------------------------
# Store results
# -----------------------------

results = original_rows.copy()

results["Binary_Prediction"] = np.where(
    binary_prediction == 0,
    "BENIGN",
    "ATTACK"
)


# -----------------------------
# MODEL C
# Attack classification
# -----------------------------

attack_indices = (
    binary_prediction == 1
)

if attack_indices.any():

    X_attacks = X.loc[attack_indices]

    attack_predictions = attack_model.predict(
        X_attacks
    )

    results.loc[
        attack_indices,
        "Attack_Type"
    ] = attack_predictions


# -----------------------------
# Display results
# -----------------------------

print("\nDetection Results:")

print(
    results[
        ["Binary_Prediction", "Attack_Type"]
    ].value_counts()
)


# -----------------------------
# Save results
# -----------------------------

results.to_csv(
    "../alerts/detection_results.csv",
    index=False
)

print("\nResults saved!")