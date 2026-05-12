import streamlit as st
import pandas as pd
from db_operations.py import get_user_logs

# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="Anamo-Lie",
    page_icon="🚨",
    layout="wide"
)

# =========================================================
# CUSTOM CSS — AMONG US THEME
# =========================================================

st.markdown("""
<style>

/* MAIN BACKGROUND */
.stApp {
    background-color: #0f172a;
    color: white;
    font-family: 'Trebuchet MS', sans-serif;
}

/* SIDEBAR */
section[data-testid="stSidebar"] {
    background-color: #111827;
}

/* MAIN TITLE */
.main-title {
    font-size: 55px;
    color: #ff4b4b;
    text-align: center;
    font-weight: bold;
    text-shadow: 0px 0px 20px red;
    margin-bottom: 10px;
}

/* SUBTITLE */
.subtitle {
    text-align: center;
    color: #cbd5e1;
    font-size: 20px;
    margin-bottom: 40px;
}

/* CARD */
.custom-card {
    background-color: #1e293b;
    padding: 20px;
    border-radius: 20px;
    border: 2px solid #334155;
    margin-bottom: 20px;
}

/* CRITICAL CARD */
.critical-card {
    background-color: #2b0b0b;
    padding: 20px;
    border-radius: 20px;
    border: 2px solid #ff4b4b;
    box-shadow: 0px 0px 20px rgba(255,0,0,0.5);
    margin-bottom: 20px;
}

/* BUTTONS */
.stButton > button {
    background-color: #ff4b4b;
    color: white;
    border-radius: 12px;
    border: none;
    font-weight: bold;
    padding: 10px 20px;
}

.stButton > button:hover {
    background-color: #ff0000;
    color: white;
}

</style>
""", unsafe_allow_html=True)

# =========================================================
# SIDEBAR NAVIGATION
# =========================================================

st.sidebar.title("🚨 ANAMO-LIE")

page = st.sidebar.radio(
    "Ship Navigation",
    [
        "Welcome",
        "Live Detection",
        "Threat Logs",
        "Critical Users"
    ]
)

# =========================================================
# SESSION STATE FOR SEARCH HISTORY
# =========================================================

if "search_history" not in st.session_state:
    st.session_state.search_history = []

# =========================================================
# WELCOME PAGE
# =========================================================

if page == "Welcome":

    st.markdown(
        '<div class="main-title">🚨 WELCOME TO ANAMO-LIE 🚨</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">AI Powered Security Monitoring System Inspired by Among Us</div>',
        unsafe_allow_html=True
    )

    st.markdown("""
    <div class="custom-card">

    ## 👨‍🚀 About Anamo-Lie

    Anamo-Lie is an AI-powered cybersecurity monitoring system designed to detect suspicious login behaviour and identify potential impostors inside the network.

    This system continuously monitors:
    - login behaviour
    - unusual locations
    - VPN/TOR activity
    - impossible travel attacks
    - brute force attempts
    - malicious IP activity

    Security analysts can investigate users, monitor critical threats, and review suspicious activity in real time.

    </div>
    """, unsafe_allow_html=True)

    st.markdown("""
    <div class="custom-card">

    ## 🛰 Navigation Guide

    ### 🔍 Live Detection
    Investigate a specific crewmate and analyze their login behaviour.

    ### 📜 Threat Logs
    View previously investigated usernames and their activity.

    ### ☠️ Critical Users
    Monitor confirmed impostors and high-risk users requiring immediate action.

    </div>
    """, unsafe_allow_html=True)

# =========================================================
# LIVE DETECTION PAGE
# =========================================================

elif page == "Live Detection":

    st.markdown(
        '<div class="main-title">🔍 LIVE DETECTION</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">Emergency Monitoring Console</div>',
        unsafe_allow_html=True
    )

    email = st.text_input("👨‍🚀 Enter Crewmate Email")

    analyze = st.button("🚨 Analyze User")

    if analyze and email:

        logs = get_user_logs(email)

        # Save search history
        if email not in st.session_state.search_history:
            st.session_state.search_history.append(email)

        if logs:

            latest = logs[0]

            risk_score = latest["risk_score"]
            level = latest["level"]
            attack_type = latest["attack_type"]
            decision = latest["decision"]

            # =========================================================
            # ALERT BANNER
            # =========================================================

            if level == "critical":

                st.markdown(f"""
                <div class="critical-card">
                <h1>☠️ CONFIRMED IMPOSTOR DETECTED</h1>
                <h3>{attack_type}</h3>
                </div>
                """, unsafe_allow_html=True)

            elif level == "danger":

                st.error(f"🔴 Dangerous Activity Detected — {attack_type}")

            elif level == "warning":

                st.warning(f"🟡 Suspicious Crewmate Activity — {attack_type}")

            else:

                st.success("🟢 VERIFIED CREWMATE")

            # =========================================================
            # TOP METRICS
            # =========================================================

            c1, c2, c3, c4 = st.columns(4)

            c1.metric("Risk Score", f"{risk_score}/100")
            c2.metric("Threat Level", level.upper())
            c3.metric("Decision", decision)
            c4.metric("Attack Type", attack_type)

            st.divider()

            # =========================================================
            # LOGIN DETAILS
            # =========================================================

            col1, col2 = st.columns(2)

            with col1:

                st.subheader("📍 Login Details")

                st.markdown(f"**👤 User:** `{email}`")
                st.markdown(f"**🕐 Timestamp:** `{latest['timestamp']}`")
                st.markdown(f"**🌍 Country:** `{latest['country']}`")
                st.markdown(f"**🏙 City:** `{latest['city']}`")
                st.markdown(f"**🌐 IP Address:** `{latest['ip_address']}`")
                st.markdown(f"**🔒 VPN/TOR:** {'YES 🚩' if latest['is_vpn_tor'] else 'NO'}")
                st.markdown(f"**❌ Failed Attempts:** `{latest['failed_attempts']}`")

                login_result = (
                    "✅ SUCCESS"
                    if latest["success"]
                    else "❌ FAILED"
                )

                st.markdown(f"**🔑 Login Result:** {login_result}")

            with col2:

                st.subheader("🧠 AI Threat Analysis")

                st.info(
                    f"""
                    Attack Type: {attack_type}

                    Risk Score: {risk_score}/100

                    Recommended Action:
                    {decision}
                    """
                )

                st.progress(min(risk_score, 100))

            # =========================================================
            # FULL LOGIN HISTORY
            # =========================================================

            st.divider()

            st.subheader("📜 Full Login History")

            df = pd.DataFrame(logs)

            st.dataframe(
                df,
                use_container_width=True,
                height=350
            )

        else:

            st.error("No logs found for this crewmate.")

# =========================================================
# THREAT LOGS PAGE
# =========================================================

elif page == "Threat Logs":

    st.markdown(
        '<div class="main-title">📜 THREAT LOGS</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">Previously Investigated Crewmates</div>',
        unsafe_allow_html=True
    )

    if st.session_state.search_history:

        history_df = pd.DataFrame({
            "Investigated Users": st.session_state.search_history
        })

        st.dataframe(
            history_df,
            use_container_width=True
        )

    else:

        st.info("No previous investigations yet.")

# =========================================================
# CRITICAL USERS PAGE
# =========================================================

elif page == "Critical Users":

    st.markdown(
        '<div class="main-title">☠️ CRITICAL USERS</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">Users Requiring Immediate Action</div>',
        unsafe_allow_html=True
    )

    st.markdown("""
    <div class="critical-card">

    <h2>🚨 ACTIVE THREAT MONITORING ENABLED 🚨</h2>

    <p>
    This section will display users classified as:
    - danger
    - critical
    - blocked
    - high risk
    </p>

    <p>
    Waiting for backend integration from database team.
    </p>

    </div>
    """, unsafe_allow_html=True)