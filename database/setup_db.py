import sqlite3
import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def setup_database():
    conn   = sqlite3.connect("database/login_app.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id   TEXT PRIMARY KEY,
            email     TEXT UNIQUE,
            password  TEXT,
            city      TEXT,
            country   TEXT,
            latitude  REAL,
            longitude REAL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_logs (
            id                   INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id              TEXT,
            email                TEXT,
            timestamp            TEXT,
            ip_address           TEXT,
            country              TEXT,
            city                 TEXT,
            latitude             REAL,
            longitude            REAL,
            is_vpn_tor           INTEGER,
            failed_attempts      INTEGER,
            new_location         INTEGER,
            geo_impossible       INTEGER,
            ip_reputation_score  INTEGER,
            session_duration_sec INTEGER,
            hour                 INTEGER,
            risk_score           INTEGER,
            decision             TEXT,
            level                TEXT,
            attack_type          TEXT,
            reasons              TEXT,
            success              INTEGER
        )
    """)

    users = [
        ("u001", "alice@securebank.com",   hash_password("alice123"),   "Bengaluru", "India", 12.9716, 77.5946),
        ("u002", "bob@securebank.com",     hash_password("bob456"),     "Mumbai",    "India", 19.0760, 72.8777),
        ("u003", "charlie@securebank.com", hash_password("charlie789"), "Delhi",     "India", 28.6139, 77.2090),
        ("u004", "diana@securebank.com",   hash_password("diana321"),   "Chennai",   "India", 13.0827, 80.2707),
        ("u005", "eve@securebank.com",     hash_password("eve654"),     "Hyderabad", "India", 17.3850, 78.4867),
    ]

    cursor.executemany("""
        INSERT OR IGNORE INTO users
        (user_id, email, password, city, country, latitude, longitude)
        VALUES (?,?,?,?,?,?,?)
    """, users)

    conn.commit()
    conn.close()
    print("✅ Database ready")
    print("✅ 5 dummy users created")
    print("")
    print("Demo Credentials:")
    print("  alice@securebank.com   / alice123")
    print("  bob@securebank.com     / bob456")
    print("  charlie@securebank.com / charlie789")
    print("  diana@securebank.com   / diana321")
    print("  eve@securebank.com     / eve654")

if __name__ == "__main__":
    setup_database()
