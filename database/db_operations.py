import sqlite3
import hashlib
import json

DB = "database/login_app.db"

def verify_password(email, password):
    hashed = hashlib.sha256(password.encode()).hexdigest()
    conn   = sqlite3.connect(DB)
    user   = conn.execute("""
        SELECT user_id, email, city, country, latitude, longitude
        FROM users WHERE email=? AND password=?
    """, (email, hashed)).fetchone()
    conn.close()
    if user:
        return {
            "user_id"  : user[0],
            "email"    : user[1],
            "city"     : user[2],
            "country"  : user[3],
            "latitude" : user[4],
            "longitude": user[5]
        }
    return None

def get_failed_attempts(email, minutes=10):
    conn  = sqlite3.connect(DB)
    count = conn.execute("""
        SELECT COUNT(*) FROM login_logs
        WHERE email=? AND success=0
        AND timestamp > datetime('now', ?)
    """, (email, f"-{minutes} minutes")).fetchone()[0]
    conn.close()
    return count

def get_last_login(user_id):
    conn = sqlite3.connect(DB)
    row  = conn.execute("""
        SELECT country, city, ip_address,
               timestamp, latitude, longitude
        FROM login_logs
        WHERE user_id=? AND success=1
        ORDER BY timestamp DESC LIMIT 1
    """, (user_id,)).fetchone()
    conn.close()
    if row:
        return {
            "country"  : row[0],
            "city"     : row[1],
            "ip"       : row[2],
            "timestamp": row[3],
            "latitude" : row[4] or 0,
            "longitude": row[5] or 0
        }
    return None

def check_new_location(user_id, country):
    conn = sqlite3.connect(DB)
    seen = conn.execute("""
        SELECT COUNT(*) FROM login_logs
        WHERE user_id=? AND country=? AND success=1
    """, (user_id, country)).fetchone()[0]
    conn.close()
    return 0 if seen > 0 else 1

def log_login_event(data):
    conn = sqlite3.connect(DB)
    reasons = data.get("reasons", [])
    if isinstance(reasons, list):
        reasons = json.dumps(reasons)
    conn.execute("""
        INSERT INTO login_logs (
            user_id, email, timestamp, ip_address,
            country, city, latitude, longitude,
            is_vpn_tor, failed_attempts, new_location,
            geo_impossible, ip_reputation_score,
            session_duration_sec, hour, risk_score,
            decision, level, attack_type, reasons, success
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        data.get("user_id"),
        data.get("email"),
        data.get("timestamp"),
        data.get("ip_address"),
        data.get("country"),
        data.get("city"),
        data.get("latitude", 0),
        data.get("longitude", 0),
        data.get("is_vpn_tor", 0),
        data.get("failed_attempts", 0),
        data.get("new_location", 0),
        data.get("geo_impossible", 0),
        data.get("ip_reputation_score", 0),
        data.get("session_duration_sec", 0),
        data.get("hour", 0),
        data.get("risk_score", 0),
        data.get("decision", ""),
        data.get("level", ""),
        data.get("attack_type", ""),
        reasons,
        data.get("success", 0)
    ))
    conn.commit()
    conn.close()

def get_latest_log():
    conn = sqlite3.connect(DB)
    row  = conn.execute("""
        SELECT * FROM login_logs
        ORDER BY timestamp DESC LIMIT 1
    """).fetchone()
    conn.close()
    return row

def get_all_logs():
    import pandas as pd
    conn = sqlite3.connect(DB)
    df   = pd.read_sql_query("""
        SELECT timestamp, email, country, city,
               risk_score, level, decision,
               attack_type, is_vpn_tor,
               failed_attempts, success
        FROM login_logs
        ORDER BY timestamp DESC
        LIMIT 50
    """, conn)
    conn.close()
    return df

# =====================================
# GET USER LOGIN HISTORY
# =====================================

def get_user_logs(email):

    conn = sqlite3.connect(DB)

    conn.row_factory = sqlite3.Row

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM login_logs
        WHERE email = ?
        ORDER BY timestamp DESC
    """, (email,))

    rows = cursor.fetchall()

    conn.close()

    return [dict(row) for row in rows]