import pickle
import numpy as np
import pandas as pd
from detection.auto_detect import detect_attack_type

FEATURES = [
    "hour",
    "failed_attempts",
    "new_location",
    "geo_impossible",
    "ip_reputation_score",
    "is_vpn_tor"
]

def load_artifacts():
    with open("model/anomaly_model.pkl", "rb") as f:
        model = pickle.load(f)
    with open("model/scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    return model, scaler

model, scaler = load_artifacts()

def analyse_login(event: dict) -> dict:
    df   = pd.DataFrame([event])[FEATURES]
    X_sc = scaler.transform(df)
    raw  = model.decision_function(X_sc)[0]
    risk = int(np.clip((1 - raw) * 50, 0, 100))

    reasons = []

    if event.get("geo_impossible") == 1:
        risk = min(100, risk + 25)
        reasons.append("Geo-impossible login detected")

    if event.get("is_vpn_tor") == 1:
        risk = min(100, risk + 20)
        reasons.append("Tor/VPN usage detected")

    if event.get("failed_attempts", 0) >= 5:
        risk = min(100, risk + 15)
        reasons.append(f"High failed attempts: {event['failed_attempts']}")

    if event.get("ip_reputation_score", 0) >= 70:
        risk = min(100, risk + 10)
        reasons.append(f"Malicious IP score: {event['ip_reputation_score']}/100")

    if event.get("hour", 12) <= 4:
        risk = min(100, risk + 8)
        reasons.append(f"Unusual login hour: {event['hour']}:00 AM")

    if event.get("new_location") == 1:
        risk = min(100, risk + 10)
        reasons.append("Login from a new location")

    if risk <= 30:
        decision, level = "Allow",         "safe"
    elif risk <= 60:
        decision, level = "Trigger MFA",   "warning"
    elif risk <= 80:
        decision, level = "Block",         "danger"
    else:
        decision, level = "Block + Alert", "critical"

    if not reasons:
        reasons.append("Login pattern matches normal behaviour")

    attack_type = detect_attack_type(event, level)

    return {
        "risk_score" : risk,
        "decision"   : decision,
        "level"      : level,
        "reasons"    : reasons,
        "attack_type": attack_type
    }