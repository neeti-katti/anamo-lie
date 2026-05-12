import streamlit as st
import pandas as pd
from database.db_operations import get_user_logs

# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="ANAMO-LIE // ARCADE EDITION",
    page_icon="🕹️",
    layout="wide"
)

# =========================================================
# THE 80S ARCADE ENGINE (CLEAN VERSION)
# =========================================================

# =========================================================
# THE 80S ARCADE ENGINE (FIXED)
# =========================================================

st.markdown("""
<style>

@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;900&family=Press+Start+2P&display=swap');

/* MAIN APP */
.stApp {

    background: linear-gradient(
        180deg,
        #05010c 0%,
        #1a0136 50%,
        #2d0154 100%
    );

    color: #00ffff;

    font-family: 'Orbitron', sans-serif;

    overflow-x: hidden;
}

/* RETRO FLOOR GRID */
.stApp::after {

    content: "";

    position: fixed;

    bottom: 0;

    left: 0;

    width: 100%;

    height: 15vh;

    background-image:
        linear-gradient(
            0deg,
            transparent 24%,
            rgba(255,0,255,.3) 25%,
            rgba(255,0,255,.3) 26%,
            transparent 27%,
            transparent 74%,
            rgba(255,0,255,.3) 75%,
            rgba(255,0,255,.3) 76%,
            transparent 77%,
            transparent
        ),

        linear-gradient(
            90deg,
            transparent 24%,
            rgba(255,0,255,.3) 25%,
            rgba(255,0,255,.3) 26%,
            transparent 27%,
            transparent 74%,
            rgba(255,0,255,.3) 75%,
            rgba(255,0,255,.3) 76%,
            transparent 77%,
            transparent
        );

    background-size: 50px 50px;

    z-index: 0;

    transform: perspective(100px) rotateX(45deg);

    pointer-events: none;
}

/* SIDEBAR */
section[data-testid="stSidebar"] {

    background-color: #05010c;

    border-right: 4px solid #ff00ff;

    box-shadow: 5px 0px 15px #ff00ff;
}

/* MAIN CONTENT */
[data-testid="stVerticalBlock"] {

    position: relative;

    z-index: 5;
}

/* TITLES */
.main-title {

    font-family: 'Press Start 2P', cursive;

    font-size: 40px;

    text-align: center;

    color: #ffffff;

    text-shadow:
        3px 3px #ff00ff,
        -3px -3px #00ffff;

    padding: 20px;
}

.subtitle {

    text-align: center;

    color: #00ffff;

    font-weight: bold;

    text-transform: uppercase;

    letter-spacing: 3px;

    margin-bottom: 30px;
}

/* RETRO CARDS */
.pixel-card {

    background: rgba(26, 1, 54, 0.9);

    border: 3px solid #00ffff;

    padding: 25px;

    margin-bottom: 20px;

    box-shadow:
        0 0 15px #00ffff,
        inset 0 0 10px #00ffff;
}

/* ALERT CARD */
.danger-card {

    background: rgba(50, 0, 0, 0.9);

    border: 4px solid #ff0000;

    padding: 25px;

    margin-bottom: 20px;

    box-shadow: 0 0 30px #ff0000;

    color: white;

    text-align: center;
}

/* BUTTONS */
.stButton > button {

    background-color: transparent;

    color: #00ffff;

    border: 2px solid #00ffff;

    border-radius: 0px;

    font-family: 'Press Start 2P', cursive;

    font-size: 14px;

    padding: 10px 20px;

    transition: 0.3s;

    box-shadow: 4px 4px 0px #ff00ff;
}

.stButton > button:hover {

    background-color: #00ffff;

    color: black;

    box-shadow: 0 0 20px #00ffff;
}

/* TEXT INPUT */
.stTextInput input {

    background-color: #1a0136 !important;

    color: #ff00ff !important;

    border: 2px solid #ff00ff !important;
}

/* DATAFRAME */
[data-testid="stDataFrame"] {

    border: 2px solid #00ffff;

    background: #000;
}

</style>
""", unsafe_allow_html=True)

# =========================================================
# SIDEBAR NAVIGATION
# =========================================================

st.sidebar.markdown(
    """
    <h2 style='
        color: #ff00ff;
        font-family: "Press Start 2P";
        font-size: 14px;
    '>
    🕹️ MENU SELECTION
    </h2>
    """,
    unsafe_allow_html=True
)

page = st.sidebar.radio(
    "Navigation",
    [
        "Welcome",
        "Live Detection",
        "Threat Logs",
        "Critical Users"
    ]
)

# =========================================================
# SESSION STATE
# =========================================================

if "search_history" not in st.session_state:
    st.session_state.search_history = []

# =========================================================
# WELCOME PAGE
# =========================================================

if page == "Welcome":

    st.markdown(
        '<div class="main-title">ANAMO-LIE ARCADE</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">AI LOGIN DEFENSE // SYSTEM STATUS: OPERATIONAL</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '''
        <div class="pixel-card">

        <h2 style="
            color:#ff00ff;
            font-family: 'Press Start 2P';
            font-size: 18px;
        ">
        🛰 MISSION OBJECTIVES
        </h2>

        <p>
        • <b>LIVE RADAR:</b> Monitor crewmate logins in real-time.
        </p>

        <p>
        • <b>DATA LOGS:</b> Access high-score threat history.
        </p>

        <p>
        • <b>TERMINATE:</b> Identify and block critical impostors.
        </p>

        </div>
        ''',
        unsafe_allow_html=True
    )

# =========================================================
# LIVE DETECTION PAGE
# =========================================================

elif page == "Live Detection":

    st.markdown(
        '<div class="main-title">LIVE RADAR</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">SCANNING FOR ANOMALIES...</div>',
        unsafe_allow_html=True
    )

    email = st.text_input("👨‍🚀 CREWMATE ID (EMAIL)")

    analyze = st.button("🚨 EXECUTE SCAN")

    if analyze and email:

        logs = get_user_logs(email)

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

                st.markdown(
                    f'''
                    <div class="danger-card">
                    <h1>☠️ IMPOSTOR DETECTED ☠️</h1>
                    <h3>ATTACK TYPE: {attack_type}</h3>
                    </div>
                    ''',
                    unsafe_allow_html=True
                )

            elif level == "danger":

                st.error(
                    f"🔴 DANGER LEVEL HIGH — {attack_type}"
                )

            elif level == "warning":

                st.warning(
                    f"🟡 SUSPICIOUS BEHAVIOR — {attack_type}"
                )

            else:

                st.success("🟢 CREWMATE VERIFIED")

            # =========================================================
            # METRICS
            # =========================================================

            c1, c2, c3, c4 = st.columns(4)

            c1.metric("RISK", f"{risk_score}%")

            c2.metric("THREAT", level.upper())

            c3.metric("RESULT", decision)

            c4.metric("CLASS", attack_type)

            st.divider()

            # =========================================================
            # DETAILS
            # =========================================================

            col1, col2 = st.columns(2)

            with col1:

                st.markdown(
                    '<div class="pixel-card">',
                    unsafe_allow_html=True
                )

                st.subheader("📍 CO-ORDINATES")

                st.markdown(f"**👤 ID:** `{email}`")

                st.markdown(
                    f"**🌍 LOC:** `{latest['city']}, {latest['country']}`"
                )

                st.markdown(
                    f"**🌐 IP:** `{latest['ip_address']}`"
                )

                st.markdown(
                    f"**🔒 TUNNEL:** {'VPN/TOR DETECTED 🚩' if latest['is_vpn_tor'] else 'CLEAN'}"
                )

                login_result = (
                    "✅ PASS"
                    if latest["success"]
                    else "❌ FAIL"
                )

                st.markdown(
                    f"**🔑 STATUS:** {login_result}"
                )

                st.markdown(
                    "</div>",
                    unsafe_allow_html=True
                )

            with col2:

                st.markdown(
                    '<div class="pixel-card">',
                    unsafe_allow_html=True
                )

                st.subheader("🧠 CORE ANALYSIS")

                st.info(
                    f"""
                    AI RECOMMENDATION:

                    {decision}
                    """
                )

                st.progress(
                    min(risk_score, 100)
                )

                st.markdown(
                    "</div>",
                    unsafe_allow_html=True
                )

            # =========================================================
            # LOGIN HISTORY
            # =========================================================

            st.divider()

            st.subheader("📜 DATA STREAM")

            st.dataframe(
                pd.DataFrame(logs),
                use_container_width=True,
                height=350
            )

        else:

            st.error(
                "DATABASE ERROR: CREWMATE NOT FOUND."
            )

# =========================================================
# THREAT LOGS PAGE
# =========================================================

elif page == "Threat Logs":

    st.markdown(
        '<div class="main-title">THREAT LOGS</div>',
        unsafe_allow_html=True
    )

    if st.session_state.search_history:

        history_df = pd.DataFrame({
            "Investigated Users":
            st.session_state.search_history
        })

        st.dataframe(
            history_df,
            use_container_width=True
        )

    else:

        st.info(
            "NO RECENT INVESTIGATIONS RECORDED."
        )

# =========================================================
# CRITICAL USERS PAGE
# =========================================================

elif page == "Critical Users":

    st.markdown(
        '<div class="main-title">CRITICAL USERS</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        """
        <div class="danger-card">

        <h2>
        🚨 ACTIVE THREAT MONITORING 🚨
        </h2>

        <p>
        Waiting for direct backend handshake...
        </p>

        </div>
        """,
        unsafe_allow_html=True
    )