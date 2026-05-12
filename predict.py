import pickle
import numpy as np
import pandas as pd

FEATURES = [
    "hour",
    "failed_attempts",
    "new_device",
    "new_location",
    "geo_impossible",
    "ip_reputation_score",
    "is_vpn_tor",
    "session_duration_sec"
]

def load_artifacts():
    with open("model/anomaly_model.pkl", "rb") as f:
        model = pickle.load(f)
    with open("model/scaler.pkl", "rb") as f:
        scaler = pickle.load(f)
    return model, scaler

model, scaler = load_artifacts()

def analyse_login(event: dict) -> dict:
    df    = pd.DataFrame([event])[FEATURES]
    X_sc  = scaler.transform(df)
    raw   = model.decision_function(X_sc)[0]
    risk  = int(np.clip((1 - raw) * 50, 0, 100))

    reasons = []

    if event.get("geo_impossible") == 1:
        risk = min(100, risk + 25)
        reasons.append("Geo-impossible login detected")

    if event.get("is_vpn_tor") == 1:
        risk = min(100, risk + 20)
        reasons.append("Tor / VPN usage detected")

    if event.get("failed_attempts", 0) >= 5:
        risk = min(100, risk + 15)
        reasons.append(f"High failed attempts: {event['failed_attempts']}")

    if event.get("ip_reputation_score", 0) >= 70:
        risk = min(100, risk + 10)
        reasons.append(f"Malicious IP score: {event['ip_reputation_score']}/100")

    if event.get("hour", 12) <= 4:
        risk = min(100, risk + 8)
        reasons.append(f"Unusual login hour: {event['hour']}:00 AM")

    if event.get("new_device") == 1 and event.get("new_location") == 1:
        risk = min(100, risk + 10)
        reasons.append("New device and new location simultaneously")

    if event.get("session_duration_sec", 999) < 15:
        risk = min(100, risk + 8)
        reasons.append("Extremely short session — possible bot")

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

    return {
        "risk_score" : risk,
        "decision"   : decision,
        "level"      : level,
        "reasons"    : reasons
    }

if __name__ == "__main__":

    # Test 1 — Very suspicious login
    suspicious = {
        "hour"                : 3,
        "failed_attempts"     : 7,
        "new_device"          : 1,
        "new_location"        : 1,
        "geo_impossible"      : 1,
        "ip_reputation_score" : 88,
        "is_vpn_tor"          : 1,
        "session_duration_sec": 10
    }

    # Test 2 — Normal login
    normal = {
        "hour"                : 10,
        "failed_attempts"     : 0,
        "new_device"          : 0,
        "new_location"        : 0,
        "geo_impossible"      : 0,
        "ip_reputation_score" : 10,
        "is_vpn_tor"          : 0,
        "session_duration_sec": 300
    }

    print("--- Suspicious Login ---")
    r = analyse_login(suspicious)
    print(f"Risk Score : {r['risk_score']}/100")
    print(f"Decision   : {r['decision']}")
    print(f"Reasons    : {r['reasons']}")

    print("\n--- Normal Login ---")
    r = analyse_login(normal)
    print(f"Risk Score : {r['risk_score']}/100")
    print(f"Decision   : {r['decision']}")
    print(f"Reasons    : {r['reasons']}")