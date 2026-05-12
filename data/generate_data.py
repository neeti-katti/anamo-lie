import pandas as pd
import numpy as np
from faker import Faker
import random

fake = Faker()

RISKY_COUNTRIES = ["Russia", "China", "North Korea", "Iran", "Belarus"]
SAFE_COUNTRIES  = ["India", "India", "India", "US", "Germany"]

RISKY_DEVICES   = ["Tor Browser", "Unknown Linux", "HeadlessChrome", "curl/7.x"]
SAFE_DEVICES    = ["Chrome/Windows", "Safari/Mac", "Chrome/Android", "Firefox/Windows"]

def generate_login_events(n=1000, anomaly_ratio=0.15):
    data = []
    users = [f"user_{i}@example.com" for i in range(50)]

    for _ in range(n):
        user       = random.choice(users)
        is_anomaly = random.random() < anomaly_ratio

        if is_anomaly:
            base = {
                "user_id"             : user,
                "country"             : random.choice(RISKY_COUNTRIES),
                "hour"                : random.randint(0, 5),
                "failed_attempts"     : random.randint(3, 10),
                "new_device"          : 1,
                "new_location"        : 1,
                "geo_impossible"      : random.choice([0, 1]),
                "ip_reputation_score" : random.randint(60, 100),
                "is_vpn_tor"          : random.choice([0, 1]),
                "session_duration_sec": random.randint(5, 30),
                "is_anomaly"          : 1
            }
        else:
            base = {
                "user_id"             : user,
                "country"             : random.choice(SAFE_COUNTRIES),
                "hour"                : random.randint(8, 22),
                "failed_attempts"     : random.randint(0, 1),
                "new_device"          : random.choice([0, 0, 0, 1]),
                "new_location"        : random.choice([0, 0, 0, 1]),
                "geo_impossible"      : 0,
                "ip_reputation_score" : random.randint(0, 25),
                "is_vpn_tor"          : 0,
                "session_duration_sec": random.randint(60, 1800),
                "is_anomaly"          : 0
            }

        data.append(base)

    df = pd.DataFrame(data)
    df.to_csv("data/login_events.csv", index=False)
    print(f"Generated {n} login events ({int(n*anomaly_ratio)} anomalies)")
    return df

if __name__ == "__main__":
    generate_login_events()