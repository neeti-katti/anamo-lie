import sqlite3
import pandas as pd

# =====================================
# IMPORT AI MODEL FUNCTION
# =====================================



# =====================================
# CREATE DATABASE + TABLE
# =====================================

conn = sqlite3.connect("database/login_logs.db")

cursor = conn.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS login_logs (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    hour INTEGER,
    failed_attempts INTEGER,
    new_device INTEGER,
    new_location INTEGER,
    geo_impossible INTEGER,
    ip_reputation_score INTEGER,
    is_vpn_tor INTEGER,
    session_duration_sec INTEGER,

    risk_score INTEGER,
    decision TEXT,
    level TEXT,
    reasons TEXT,

    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")

conn.commit()
conn.close()


# =====================================
# SAVE LOGIN EVENT
# =====================================

def save_login(event):

    # AI prediction
    result = analyse_login(event)

    conn = sqlite3.connect("database/login_logs.db")

    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO login_logs (

        hour,
        failed_attempts,
        new_device,
        new_location,
        geo_impossible,
        ip_reputation_score,
        is_vpn_tor,
        session_duration_sec,

        risk_score,
        decision,
        level,
        reasons

    )

    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)

    """, (

        event["hour"],
        event["failed_attempts"],
        event["new_device"],
        event["new_location"],
        event["geo_impossible"],
        event["ip_reputation_score"],
        event["is_vpn_tor"],
        event["session_duration_sec"],

        result["risk_score"],
        result["decision"],
        result["level"],
        str(result["reasons"])
    ))

    conn.commit()
    conn.close()

    print("Login event stored successfully!")

    return result


# =====================================
# FETCH ALL LOGS
# =====================================

def fetch_logs():

    conn = sqlite3.connect("database/login_logs.db")

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("SELECT * FROM login_logs")

    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]


# =====================================
# FETCH HIGH RISK LOGS
# =====================================

def fetch_high_risk():

    conn = sqlite3.connect("database/login_logs.db")

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
    SELECT * FROM login_logs
    WHERE risk_score >= 70
    """)

    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]


# =====================================
# FETCH RECENT LOGS
# =====================================

def fetch_recent_logs():

    conn = sqlite3.connect("database/login_logs.db")

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
    SELECT * FROM login_logs
    ORDER BY timestamp DESC
    LIMIT 5
    """)

    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]


# =====================================
# EXPORT LOGS TO CSV
# =====================================

def export_logs_to_csv():

    logs = fetch_logs()

    df = pd.DataFrame(logs)

    df.to_csv("login_logs_export.csv", index=False)

    print("Logs exported successfully!")

    # =====================================
# TEMPORARY AI FUNCTION
# =====================================

def analyse_login(event):

    risk_score = 0
    reasons = []

    if event["hour"] < 5:
        risk_score += 20
        reasons.append("Odd login hour")

    if event["failed_attempts"] > 5:
        risk_score += 30
        reasons.append("Multiple failed attempts")

    if event["new_device"] == 1:
        risk_score += 15
        reasons.append("New device detected")

    if event["new_location"] == 1:
        risk_score += 15
        reasons.append("New location detected")

    if event["geo_impossible"] == 1:
        risk_score += 25
        reasons.append("Impossible travel detected")

    if event["is_vpn_tor"] == 1:
        risk_score += 20
        reasons.append("VPN/TOR usage detected")

    if event["ip_reputation_score"] > 70:
        risk_score += 20
        reasons.append("Suspicious IP reputation")

    if event["session_duration_sec"] < 30:
        risk_score += 10
        reasons.append("Very short session duration")

    if risk_score >= 70:
        level = "HIGH"
        decision = "ANOMALY"

    elif risk_score >= 40:
        level = "MEDIUM"
        decision = "SUSPICIOUS"

    else:
        level = "LOW"
        decision = "SAFE"

    return {
        "risk_score": risk_score,
        "decision": decision,
        "level": level,
        "reasons": reasons
    }