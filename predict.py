def analyse_login(data):

    return {
        "risk_score": 78,
        "decision": "Trigger MFA",
        "level": "warning",
        "reasons": [
            "Unusual login location",
            "Multiple failed attempts",
            "VPN usage detected"
        ]
    }