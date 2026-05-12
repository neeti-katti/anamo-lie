# website1_login.py
import streamlit as st
import sqlite3
import datetime
import hashlib
import joblib
import numpy as np
import os

# --- Configuration ---
DB_PATH = "database/login_app.db"
MODEL_PATH = "model/anomaly_model.pkl"
SCALER_PATH = "model/scaler.pkl"

# --- Helper Functions ---
def get_db_connection():
    """Connect to the SQLite database"""
    conn = sqlite3.connect(DB_PATH)
    return conn

def hash_password(password):
    """Hash password using SHA-256 (same as setup_db.py)"""
    return hashlib.sha256(password.encode()).hexdigest()

def load_model():
    """Load trained ML model"""
    if not os.path.exists(MODEL_PATH):
        return None, None
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        return model, scaler
    except Exception:
        return None, None

def get_user_by_email(email):
    """Fetch user details from database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT user_id, email, password, city, country, latitude, longitude
        FROM users WHERE email = ?
    """, (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def log_login_attempt(user_id, email, ip_address, country, city, latitude, longitude,
                      is_vpn_tor, failed_attempts, new_location, geo_impossible,
                      ip_reputation_score, session_duration_sec, hour, risk_score,
                      decision, level, attack_type, reasons, success):
    """Log login attempt to database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    
    cursor.execute("""
        INSERT INTO login_logs
        (user_id, email, timestamp, ip_address, country, city, latitude, longitude,
         is_vpn_tor, failed_attempts, new_location, geo_impossible, ip_reputation_score,
         session_duration_sec, hour, risk_score, decision, level, attack_type,
         reasons, success)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (user_id, email, timestamp, ip_address, country, city, latitude, longitude,
          is_vpn_tor, failed_attempts, new_location, geo_impossible, ip_reputation_score,
          session_duration_sec, hour, risk_score, decision, level, attack_type,
          reasons, success))
    
    conn.commit()
    conn.close()

def calculate_risk_and_decision(email, failed_attempts, is_vpn, country, hour):
    """
    Calculate risk score and make decision using ML model + rules
    Returns: (risk_score, decision, level, attack_type, reasons)
    """
    reasons = []
    attack_type = "None"
    level = "Low"
    
    # Load model for prediction
    model, scaler = load_model()
    
    if model is not None and scaler is not None:
        try:
            # Feature Engineering
            features = np.array([[
                failed_attempts,
                1 if is_vpn else 0,
                len(email),
                hour,
                1 if country in ["Russia", "North Korea", "China"] else 0
            ]])
            
            features_scaled = scaler.transform(features)
            prediction = model.predict(features_scaled)
            score = model.score_samples(features_scaled)
            
            # Isolation Forest: -1 = anomaly, 1 = normal
            base_risk = 0.9 if prediction == -1 else 0.2
            
        except Exception as e:
            base_risk = 0.5  # Default if prediction fails
    else:
        base_risk = 0.3  # Default if no model
    
    # Rule-Based Overlays (Hybrid Logic)
    if failed_attempts > 3:
        base_risk = max(base_risk, 0.85)
        reasons.append("Multiple failed attempts")
        attack_type = "Brute Force"
        level = "High"
    
    if is_vpn:
        base_risk = max(base_risk, 0.65)
        reasons.append("VPN/Tor detected")
        attack_type = "Identity Masking" if attack_type == "None" else attack_type + " + Identity Masking"
        level = "Medium" if level == "Low" else level
    
    if country in ["Russia", "North Korea", "China"]:
        base_risk = max(base_risk, 0.7)
        reasons.append("High-risk country")
        attack_type = "Suspicious Location" if attack_type == "None" else attack_type + " + Suspicious Location"
        level = "Medium" if level == "Low" else level
    
    # Cap risk score at 1.0
    risk_score = min(base_risk, 1.0)
    
    # Decision
    if risk_score >= 0.8:
        decision = "BLOCKED"
        level = "Critical"
    elif risk_score >= 0.5:
        decision = "MFA_REQUIRED"
        level = "High"
    elif risk_score >= 0.3:
        decision = "WARNING"
        level = "Medium"
    else:
        decision = "ALLOWED"
        level = "Low"
    
    return risk_score, decision, level, attack_type, "; ".join(reasons) if reasons else "Normal login"

# --- Session State ---
if 'session_email' not in st.session_state:
    st.session_state.session_email = None
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'current_user_id' not in st.session_state:
    st.session_state.current_user_id = None

# --- UI Layout ---
st.set_page_config(page_title="SecureBank Login", page_icon="🏦", layout="centered")

st.title("🏦 SecureBank")
st.markdown("**Secure Login Portal**")

# --- Sidebar: Simulation Controls ---
with st.sidebar:
    st.header("🕵️‍♂️ Attack Simulation")
    simulate_vpn = st.checkbox("🔒 Simulate VPN/Tor", value=False)
    simulate_brute = st.checkbox("⚡ Simulate Brute Force", value=False)
    simulate_country = st.selectbox("🌍 Simulate Country", 
                                    ["India", "USA", "Russia", "North Korea", "China", "Germany"])
    
    st.divider()
    if st.button("🔄 Reset Session"):
        st.session_state.session_email = None
        st.session_state.failed_attempts = 0
        st.session_state.current_user_id = None
        st.rerun()

# --- Main Login Form ---
if st.session_state.session_email:
    st.success(f"✅ Logged in as: **{st.session_state.session_email}**")
    if st.button("🚪 Logout"):
        st.session_state.session_email = None
        st.session_state.failed_attempts = 0
        st.session_state.current_user_id = None
        st.rerun()
else:
    with st.form("login_form", clear_on_submit=True):
        email = st.text_input("📧 Email Address", placeholder="alice@securebank.com")
        password = st.text_input("🔑 Password", type="password")
        
        submitted = st.form_submit_button("🔐 Login")
        
        if submitted:
            if not email or "@" not in email:
                st.error("❌ Please enter a valid email address.")
                st.stop()
            
            if not password:
                st.error("❌ Please enter your password.")
                st.stop()
            
            # Get current time
            current_hour = datetime.datetime.now().hour
            
            # Simulated location data
            ip_address = "192.168.1.50"
            country = simulate_country
            city = "Unknown"
            latitude, longitude = 0.0, 0.0
            
            # Get user from database
            user = get_user_by_email(email)
            
            if user:
                user_id, db_email, db_password, db_city, db_country, db_lat, db_lon = user
                city, country, latitude, longitude = db_city, db_country, db_lat, db_lon
                
                # Check password
                if hash_password(password) == db_password:
                    # Correct password
                    if simulate_brute and st.session_state.failed_attempts > 0:
                        # Simulate brute force attack (even with correct password)
                        pass
                    
                    # Calculate risk
                    risk_score, decision, level, attack_type, reasons = calculate_risk_and_decision(
                        email, 
                        st.session_state.failed_attempts, 
                        simulate_vpn, 
                        country, 
                        current_hour
                    )
                    
                    # Log attempt
                    log_login_attempt(
                        user_id=user_id,
                        email=email,
                        ip_address=ip_address,
                        country=country,
                        city=city,
                        latitude=latitude,
                        longitude=longitude,
                        is_vpn_tor=1 if simulate_vpn else 0,
                        failed_attempts=st.session_state.failed_attempts,
                        new_location=0,
                        geo_impossible=0,
                        ip_reputation_score=50,  # Simulated
                        session_duration_sec=0,
                        hour=current_hour,
                        risk_score=risk_score,
                        decision=decision,
                        level=level,
                        attack_type=attack_type,
                        reasons=reasons,
                        success=1 if decision == "ALLOWED" else 0
                    )
                    
                    # Show result
                    if decision == "ALLOWED":
                        st.success(f"✅ Login Successful! Welcome, {email}")
                        st.info(f"Risk Level: **{level}** | Risk Score: **{risk_score:.2f}**")
                        st.session_state.session_email = email
                        st.session_state.current_user_id = user_id
                        st.session_state.failed_attempts = 0
                    elif decision == "MFA_REQUIRED":
                        st.warning(f"⚠️ MFA Required: **{reasons}**")
                        st.info(f"Risk Score: **{risk_score:.2f}**")
                        st.stop()
                    else:
                        st.error(f"🚫 **ACCESS DENIED**: {reasons}")
                        st.info(f"Risk Score: **{risk_score:.2f}** | Level: **{level}**")
                        if not simulate_brute:
                            st.session_state.failed_attempts += 1
                else:
                    # Wrong password
                    st.session_state.failed_attempts += 1
                    
                    # Calculate risk for failed attempt
                    risk_score, decision, level, attack_type, reasons = calculate_risk_and_decision(
                        email, 
                        st.session_state.failed_attempts, 
                        simulate_vpn, 
                        country, 
                        current_hour
                    )
                    
                    # Log failed attempt
                    log_login_attempt(
                        user_id=None,
                        email=email,
                        ip_address=ip_address,
                        country=country,
                        city=city,
                        latitude=latitude,
                        longitude=longitude,
                        is_vpn_tor=1 if simulate_vpn else 0,
                        failed_attempts=st.session_state.failed_attempts,
                        new_location=0,
                        geo_impossible=0,
                        ip_reputation_score=50,
                        session_duration_sec=0,
                        hour=current_hour,
                        risk_score=risk_score,
                        decision="FAILED",
                        level=level,
                        attack_type="Invalid Credentials" if st.session_state.failed_attempts == 1 else "Brute Force",
                        reasons="Invalid password" if st.session_state.failed_attempts == 1 else f"Multiple failed attempts ({st.session_state.failed_attempts})",
                        success=0
                    )
                    
                    st.error(f"❌ Login Failed! Invalid password. (Attempt {st.session_state.failed_attempts})")
                    
                    if st.session_state.failed_attempts >= 5:
                        st.error("🚨 Too many failed attempts. Account temporarily locked.")
                        st.stop()
            else:
                # User not found
                st.error(f"❌ User not found: {email}")
                st.info("Demo Credentials: alice@securebank.com / alice123")

# --- Footer ---
st.markdown("---")
st.caption("SecureBank © 2026 | Anamo-Lie AI Security System")
