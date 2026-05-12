# website1_login.py
import streamlit as st
import sqlite3
import datetime
import joblib
import numpy as np
import pandas as pd
import os

# --- Configuration ---
DB_PATH = "database/login_app.db"
MODEL_PATH = "model/anomaly_model.pkl"
SCALER_PATH = "model/scaler.pkl"

# --- Helper Functions ---
def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    return conn

def load_model():
    if not os.path.exists(MODEL_PATH):
        st.error("Model not found! Please run Person 2's setup first.")
        return None, None
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    return model, scaler

def calculate_risk(username, ip, failed_attempts, is_vpn=False):
    """Simplified risk logic for demo. 
       In a real app, this would call Person 2's predict.py logic."""
    # Fallback if model isn't loaded
    if not os.path.exists(MODEL_PATH):
        # Simulate risk based on failed attempts
        if failed_attempts > 3: return 0.9, "BLOCKED"
        if is_vpn: return 0.7, "MEDIUM"
        return 0.1, "ALLOWED"

    # Real Prediction Logic (if model exists)
    try:
        model, scaler = load_model()
        features = np.array([[failed_attempts, 1 if is_vpn else 0, len(username)]])
        features_scaled = scaler.transform(features)
        prediction = model.predict(features_scaled)
        score = model.score_samples(features_scaled)
        
        # Isolation Forest: -1 is anomaly, 1 is normal
        risk_score = 0.9 if prediction == -1 else 0.2
        status = "BLOCKED" if prediction == -1 else "ALLOWED"
        
        return risk_score, status
    except Exception as e:
        st.error(f"Prediction error: {e}")
        return 0.5, "UNKNOWN"

def log_login(username, ip, status, risk_score, failed_count):
    conn = get_db_connection()
    c = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    
    c.execute('''
        INSERT INTO login_attempts (username, ip_address, status, risk_score, failed_attempts, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (username, ip, status, risk_score, failed_count, timestamp))
    
    conn.commit()
    conn.close()

# --- Session State for Tracking Failed Attempts ---
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'last_login_user' not in st.session_state:
    st.session_state.last_login_user = None

# --- UI Layout ---
st.set_page_config(page_title="SecureBank Login", page_icon="🏦")

st.title("🏦 SecureBank Login")
st.markdown("### Secure Access Portal")

# Sidebar for simulation controls (for demo purposes)
with st.sidebar:
    st.header("🕵️ Attacker Controls")
    simulate_vpn = st.checkbox("Simulate VPN/Tor", value=False)
    simulate_brute = st.checkbox("Simulate Brute Force (Auto-Fail)", value=False)
    reset_session = st.button("Reset Session")
    
    if reset_session:
        st.session_state.failed_attempts = 0
        st.session_state.last_login_user = None
        st.rerun()

# Main Login Form
with st.form("login_form"):
    email = st.text_input("Email Address", placeholder="alice@securebank.com")
    password = st.text_input("Password", type="password")
    submitted = st.form_submit_button("🔐 Login")

    if submitted:
        ip_address = "192.168.1.100" # Simulated IP
        if simulate_vpn:
            ip_address = "10.20.30.40" # Tor Exit Node IP
        
        # Logic for Brute Force Simulation
        if simulate_brute and st.session_state.failed_attempts < 5:
            st.session_state.failed_attempts += 1
            st.error(f"❌ Login Failed! (Attempt {st.session_state.failed_attempts}/5)")
            log_login(email, ip_address, "FAILED", 0.6, st.session_state.failed_attempts)
            st.stop() # Stop execution for this "failed" attempt

        # Real Login Logic
        risk_score, status = calculate_risk(email, ip_address, st.session_state.failed_attempts, simulate_vpn)
        
        # Log the attempt
        log_login(email, ip_address, status, risk_score, st.session_state.failed_attempts)
        
        # Reset failed attempts on successful login
        if status == "ALLOWED":
            st.session_state.failed_attempts = 0
            st.session_state.last_login_user = email
            st.success(f"✅ Login Successful! Welcome, {email}")
        else:
            st.error(f"🚫 ACCESS DENIED: Anomaly Detected (Risk Score: {risk_score:.2f})")
            st.session_state.failed_attempts += 1

# Display Status
if st.session_state.last_login_user:
    st.info(f"Currently logged in as: **{st.session_state.last_login_user}**")
    if st.button("Logout"):
        st.session_state.last_login_user = None
        st.session_state.failed_attempts = 0
        st.rerun()