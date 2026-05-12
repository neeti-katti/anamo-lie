import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report

FEATURES = [
    "hour",
    "failed_attempts",
    "new_location",
    "geo_impossible",
    "ip_reputation_score",
    "is_vpn_tor"
]

def train(csv_path="data/login_events.csv"):
    df = pd.read_csv(csv_path)
    X  = df[FEATURES]
    y  = df["is_anomaly"]

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators=200,
        contamination=0.15,
        random_state=42
    )
    model.fit(X_scaled)

    preds        = model.predict(X_scaled)
    preds_binary = [1 if p == -1 else 0 for p in preds]

    print("\nModel Evaluation:")
    print(classification_report(y, preds_binary,
          target_names=["Normal", "Anomaly"]))

    with open("model/anomaly_model.pkl", "wb") as f:
        pickle.dump(model, f)
    with open("model/scaler.pkl", "wb") as f:
        pickle.dump(scaler, f)

    print("anomaly_model.pkl saved")
    print("scaler.pkl saved")
    return model, scaler

if __name__ == "__main__":
    train()