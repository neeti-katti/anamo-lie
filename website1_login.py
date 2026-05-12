# website1_login.py
import streamlit as st
import sqlite3
import datetime
import joblib
import numpy as np
import pandas as pd
import os
import random

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
        return None, None
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        return model, scaler
    except Exception:
        return None, None

def calculate_risk(email, ip, failed_attempts, is_vpn=False):
    """
    Calculates risk based on failed attempts and model prediction.
    """
    # Fallback if model isn't loaded
    if not os.path.exists(MODEL_PATH):
        if failed_attempts > 3: return 0.9, "BLOCKED"
        if is_vpn: return 0.7, "MEDIUM"
        return 0.1, "ALLOWED"

    try:
        model, scaler = load_model()
        # Feature Engineering: 
        # 1. Failed Attempts, 2. VPN Flag, 3. Email Length (simple proxy for bot vs human)
        features = np.array([[failed_attempts, 1 if is_vpn else 0, len(email)]])
        features_scaled = scaler.transform(features)
        
        prediction = model.predict(features_scaled)
        score = model.score_samples(features_scaled)
        
        # Isolation Forest: -1 is anomaly, 1 is normal
        risk_score = 0.9 if prediction == -1 else 0.2
        status = "BLOCKED" if prediction == -1 else "ALLOWED"
        
        return risk_score, status
    except Exception as e:
        return 0.5, "UNKNOWN"

def log_login_attempt(email, ip, status, risk_score, failed_count):
    conn = get_db_connection()
    c = conn.cursor()
    timestamp = datetime.datetime.now().isoformat()
    
    c.execute('''
        INSERT INTO login_logs (user_id,email, ip_address, status, risk_score, failed_attempts, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (email, ip, status, risk_score, failed_count, timestamp))
    
    conn.commit()
    conn.close()

# --- Session State Management ---
# Tracks failed attempts per email session
if 'session_email' not in st.session_state:
    st.session_state.session_email = None
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# --- UI Layout ---
st.set_page_config(page_title="SecureBank Login", page_icon="🏦", layout="centered")

# Custom CSS for a cleaner look
st.markdown("""
    <style>
    .main-header {
        text-align: center;
        color: #1f77b4;
        font-family: 'Arial', sans-serif;
        margin-bottom: 30px;
    }
    .stForm {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
    }
    </style>
""", unsafe_allow_html=True)

st.title("🏦 SecureBank")
st.markdown("**Login to your secure account**")

# --- Sidebar: Simulation Controls (For Hackathon Demo) ---
with st.sidebar:
    st.header("🕵️‍♂️ Attacker Controls")
    st.write("Use these to simulate attacks for evaluation.")
    
    simulate_vpn = st.checkbox("🔒 Simulate VPN / Tor", value=False)
    simulate_brute = st.checkbox("⚡ Simulate Brute Force (Auto-Fail)", value=False)
    simulate_geo = st.selectbox("🌍 Simulate Location", ["Local", "USA", "India", "Russia", "North Korea"])
    
    st.divider()
    if st.button("🔄 Reset Session"):
        st.session_state.session_email = None
        st.session_state.failed_attempts = 0
        st.rerun()

# --- Main Login Form ---
if st.session_state.session_email:
    # Display current session info
    st.success(f"✅ Session Active: **{st.session_state.session_email}**")
    if st.button("🚪 Logout"):
        st.session_state.session_email = None
        st.session_state.failed_attempts = 0
        st.rerun()
else:
    # Login Form
    with st.form("login_form", clear_on_submit=True):
        # CHANGED: Username -> Email Address
        email = st.text_input("📧 Email Address", placeholder="alice@securebank.com")
        password = st.text_input("🔑 Password", type="password")
        
        submitted = st.form_submit_button("🔐 Login Securely")

        if submitted:
            # Validate Email
            if not email or "@" not in email:
                st.error("❌ Please enter a valid email address.")
                st.stop()

            # --- Simulation Logic ---
            ip_address = "192.168.1.50" # Local IP
            if simulate_vpn:
                ip_address = "10.20.30.40" # Tor Exit Node IP
            
            # Determine Location ID (for logging)
            location_id = "LOCAL"
            if simulate_geo != "Local":
                location_id = simulate_geo

            # Handle Brute Force Simulation
            if simulate_brute and st.session_state.session_email != email:
                # First attempt for this new email
                st.session_state.session_email = email
                st.session_state.failed_attempts = 1
            elif simulate_brute and st.session_state.session_email == email:
                # Subsequent attempts
                st.session_state.failed_attempts += 1
            
            # If not simulating brute force, reset counter on new login
            if not simulate_brute:
                st.session_state.session_email = email
                st.session_state.failed_attempts = 0

            current_attempts = st.session_state.failed_attempts

            # Calculate Risk
            risk_score, status = calculate_risk(email, ip_address, current_attempts, simulate_vpn)

            # Log the Attempt
            log_login_attempt(email, ip_address, status, risk_score, current_attempts)

            # --- Feedback ---
            if status == "BLOCKED":
                st.error(f"🚫 **ACCESS DENIED**: Anomaly Detected!")
                st.warning(f"Risk Score: **{risk_score:.2f}** (High)")
                st.info(f"Reason: Too many failed attempts ({current_attempts}) from {simulate_geo} ({'VPN' if simulate_vpn else 'Normal'})")
                
                # Increment counter for next attempt if blocked
                if not simulate_brute:
                    st.session_state.failed_attempts += 1

            elif status == "MEDIUM":
                st.warning(f"⚠️ **Security Alert**: Unusual Activity Detected")
                st.info(f"Risk Score: **{risk_score:.2f}** (Medium)")
                st.info(f"Reason: Suspicious location ({simulate_geo}) or {simulate_geo} VPN usage.")
                # In a real app, this would trigger MFA
                st.stop() # Stop processing, wait for user to decide

            else: # ALLOWED
                st.success(f"✅ **Login Successful**!")
                st.balloons() # Celebration effect
                st.info(f"Welcome back, **{email}**")
                # Reset counter on success
                st.session_state.failed_attempts = 0

# --- Footer ---
st.markdown("---")
st.caption("SecureBank © 2026 | Powered by Anamo-Lie AI")
