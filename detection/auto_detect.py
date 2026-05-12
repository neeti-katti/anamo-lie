import requests
from math import radians, sin, cos, sqrt, atan2

def get_real_location():
    try:
        r    = requests.get("https://ipapi.co/json/", timeout=5)
        data = r.json()
        return {
            "ip"       : data.get("ip",           "unknown"),
            "country"  : data.get("country_name", "Unknown"),
            "city"     : data.get("city",         "Unknown"),
            "latitude" : data.get("latitude",      0),
            "longitude": data.get("longitude",     0),
        }
    except:
        return {
            "ip": "unknown", "country": "Unknown",
            "city": "Unknown", "latitude": 0, "longitude": 0
        }

def check_vpn_tor(ip):
    try:
        r   = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        org = r.json().get("org", "").lower()
        keywords = [
            "vpn", "tor", "proxy", "hosting",
            "datacenter", "digitalocean", "linode",
            "vultr", "aws", "azure", "google cloud"
        ]
        return 1 if any(k in org for k in keywords) else 0
    except:
        return 0

def get_ip_reputation(ip):
    try:
        r   = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        org = r.json().get("org", "").lower()
        if any(k in org for k in ["tor", "proxy", "abuse", "spam"]):
            return 85
        elif any(k in org for k in ["vpn", "hosting", "datacenter", "cloud"]):
            return 55
        return 10
    except:
        return 10

def check_geo_impossible(lat1, lon1, lat2, lon2, minutes):
    try:
        R        = 6371
        rl1, rl2 = radians(lat1), radians(lat2)
        dlat     = radians(lat2 - lat1)
        dlon     = radians(lon2 - lon1)
        a        = (sin(dlat/2)**2 +
                    cos(rl1) * cos(rl2) * sin(dlon/2)**2)
        dist     = R * 2 * atan2(sqrt(a), sqrt(1 - a))
        return 1 if dist > (minutes / 60) * 900 else 0
    except:
        return 0

def detect_attack_type(event, level):
    if level == "safe":
        return "No Attack"
    if event.get("geo_impossible") == 1:
        return "Impossible Travel Attack"
    if event.get("failed_attempts", 0) >= 5:
        return "Brute Force Attack"
    if event.get("is_vpn_tor") == 1:
        return "Identity Masking via VPN/Tor"
    if event.get("ip_reputation_score", 0) >= 70:
        return "Malicious IP Attack"
    if event.get("new_location") == 1:
        return "Suspicious Location Login"
    if event.get("hour", 12) <= 4:
        return "Odd Hour Login Attempt"
    return "Anomalous Login Pattern"