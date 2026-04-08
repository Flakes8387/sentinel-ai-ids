import requests
import json
import time

URL = "http://127.0.0.1:8000/api/analyze"

def send_traffic(client_ip, method, host, path, src_bytes=0, count=1):
    payload = {
        "client_ip": client_ip,
        "method": method,
        "host": host,
        "path": path,
        "content_length": src_bytes,
        "duration": 0.05,
        "failed_logins": 0,
        "dst_bytes": 0,
        "srv_count": count,
        "count": count
    }
    resp = requests.post(URL, json=payload).json()
    return resp

print("============= EXTENSIVE FEATURE TESTING =============\n")

# 1. Single Payload Signature (XSS) on Low-Value Asset (assets = 0.1 weight)
print("[TEST 1] Single Payload Signature (XSS) on Low-Value Asset")
r1 = send_traffic("10.10.10.1", "GET", "testphp.vulnweb.com", "/assets/images/logo.png?search=<script>alert(1)</script>")
print(f"Risk Score: {(r1.get('risk_score', 0) * 10):.1f}")
print(f"Threat Type: {r1.get('threat_type')}")
print(f"Explanations: {r1.get('explanations')}\n")

# 2. Temporal Correlation Engine (Multiple attacks in 60s from same IP)
print("[TEST 2] Temporal Correlation Engine (Rapid succession of attacks)")
send_traffic("10.10.10.2", "GET", "testphp.vulnweb.com", "/assets/images/logo.png?search=1' OR '1'='1")
send_traffic("10.10.10.2", "GET", "testphp.vulnweb.com", "/assets/images/logo.png?search=1' OR '1'='1")
send_traffic("10.10.10.2", "GET", "testphp.vulnweb.com", "/assets/images/logo.png?search=1' OR '1'='1")
r2 = send_traffic("10.10.10.2", "GET", "testphp.vulnweb.com", "/assets/images/logo.png?search=1' OR '1'='1")
print(f"Risk Score: {(r2.get('risk_score', 0) * 10):.1f}")
print(f"Explanations: {r2.get('explanations')}\n")

# 3. Attack Pattern Memory AND Threat Escalation
print("[TEST 3] Attack Pattern Memory AND Threat Escalation")
send_traffic("10.10.10.3", "GET", "testphp.vulnweb.com", "/?nikto=test") # Recon
time.sleep(0.1)
r3 = send_traffic("10.10.10.3", "GET", "testphp.vulnweb.com", "/search.php?query=../../../../etc/passwd") # Exploit & Memory
print(f"Risk Score: {(r3.get('risk_score', 0) * 10):.1f}")
print(f"Explanations: {r3.get('explanations')}\n")

# 4. Critical Asset Multiplication (Admin Portal SQLi - 1.0 weight)
print("[TEST 4] Critical Infrastructure Attack (Admin Portal SQLi)")
r4 = send_traffic("10.10.10.4", "GET", "testphp.vulnweb.com", "/admin/config.php?db=1; DROP TABLE users")
print(f"Risk Score: {(r4.get('risk_score', 0) * 10):.1f}")
print(f"Explanations: {r4.get('explanations')}\n")

# 5. ML Behavioral Fallback (Data Exfiltration logic)
print("[TEST 5] Pure ML Behavioral Anomaly (Data Exfiltration via Massive Payload)")
r5 = send_traffic("10.10.10.5", "POST", "testphp.vulnweb.com", "/api/upload", src_bytes=5000)
print(f"Risk Score: {(r5.get('risk_score', 0) * 10):.1f}")
print(f"Threat Type: {r5.get('threat_type')}")
print(f"Explanations: {r5.get('explanations')}\n")

# 6. Analyst Feedback Loop (Clear IP History)
print("[TEST 6] Analyst Feedback Loop (Clearing History)")
requests.post("http://127.0.0.1:8000/api/feedback", json={"client_ip": "10.10.10.3", "is_safe": True})
r6 = send_traffic("10.10.10.3", "GET", "testphp.vulnweb.com", "/?nikto=test") # Should no longer have memory penalty
print(f"Risk Score after feedback: {(r6.get('risk_score', 0) * 10):.1f}")
print(f"Explanations after feedback: {r6.get('explanations')}\n")

