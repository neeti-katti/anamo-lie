from predict import analyse_login
import streamlit as st

# Page settings
st.set_page_config(
    page_title="Anamo-Lie",
    page_icon="🛡",
    layout="wide"
)

# Title
st.title("🛡 Anamo-Lie")
st.subheader("AI-Powered Login Anomaly Detector")

st.divider()

# Metrics section
col1, col2, col3 = st.columns(3)

col1.metric("Total Logins", "12,450")
col2.metric("Threats Detected", "148")
col3.metric("System Status", "Active")

st.divider()

# Alert section
st.error("🚨 High Risk Login Detected")
st.warning("⚠ Multiple Failed Login Attempts")
st.success("✅ AI Monitoring Active")

st.divider()

st.header("🔍 Login Simulation")

username = st.text_input("Username")

country = st.selectbox(
    "Login Country",
    ["India", "USA", "Russia", "Germany", "China"]
)

device = st.selectbox(
    "Device Type",
    ["Windows", "Mac", "Linux", "Android"]
)

failed_attempts = st.slider(
    "Failed Login Attempts",
    0,
    20
)

login_hour = st.slider(
    "Login Hour",
    0,
    23
)

analyze = st.button("Analyze Login")

if analyze:

    result = analyse_login({
        "hour": login_hour,
        "failed_attempts": failed_attempts,
        "new_device": 1,
        "new_location": 1,
        "geo_impossible": 0,
        "ip_reputation_score": 65,
        "is_vpn_tor": 1,
        "session_duration_sec": 120
    })

    # ALERT COLORS
    if result["level"] == "safe":
        st.success("✅ Safe Login")

    elif result["level"] == "warning":
        st.warning("⚠ Suspicious Login")

    elif result["level"] == "danger":
        st.error("🚨 Dangerous Login")

    else:
        st.error("🛑 CRITICAL THREAT DETECTED")

    # Risk score
    st.subheader("Risk Score")

    st.progress(result["risk_score"])

    st.metric(
        "Risk Score",
        f'{result["risk_score"]}/100'
    )

    # Decision
    st.subheader("AI Decision")

    st.info(result["decision"])

    # Reasons
    st.subheader("Detection Reasons")

    for reason in result["reasons"]:
        st.write(f"- {reason}")