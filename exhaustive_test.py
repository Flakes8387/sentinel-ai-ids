import requests
import concurrent.futures
import time
import urllib3

# Suppress insecure request warnings if MITM intercepts HTTPS
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

TARGET = "http://testphp.vulnweb.com"

print("🔥 EXHAUSTIVE SENTINEL IDS VALIDATION SUITE 🔥")
print("Routing Traffic through MITM Proxy (127.0.0.1:8080)")
print("Validating ALL Machine Learning, Signature, Memory, Escalation, and Correlation logic.\n" + "="*80)

# -----------------------------------------------------------------------------------------
# Test 1: Single Signature Verification & Low CARS asset
# -----------------------------------------------------------------------------------------
print("\n[TEST 1] Single Payload Signature (XSS) on Low-Value Asset (CARS should be LOW)")
print("   -> Expectation: Threat detected (XSS), but score remains low due to asset weight.")
try:
    requests.get(TARGET + "/assets/images/logo.png?search=<script>alert(1)</script>", proxies=proxies, timeout=3)
except: pass
time.sleep(2)

# -----------------------------------------------------------------------------------------
# Test 2: Temporal Correlation Engine (Multiple attacks in 60s from same IP)
# -----------------------------------------------------------------------------------------
print("\n[TEST 2] Temporal Correlation Engine (Rapid succession of low-level attacks)")
print("   -> Expectation: System notices 3+ attacks from the SAME IP and escalates risk.")
for i in range(4):
    try:
        requests.get(TARGET + f"/assets/images/logo.png?search=1' OR '{i}'='{i}", proxies=proxies, timeout=3)
        time.sleep(0.5)
    except: pass
time.sleep(2)

# -----------------------------------------------------------------------------------------
# Test 3: Attack Pattern Memory (Known offender tracking decay)
# -----------------------------------------------------------------------------------------
print("\n[TEST 3] Attack Pattern Memory (Long-term repeat offender tracking)")
print("   -> Expectation: ML Backend recognizes this IP is continuously attacking and logs historical incident count.")
try:
    requests.get(TARGET + "/search.php?query=../../../../etc/passwd", proxies=proxies, timeout=3)
except: pass
time.sleep(2)

# -----------------------------------------------------------------------------------------
# Test 4: Threat Escalation Model (Lifecycle progression)
# -----------------------------------------------------------------------------------------
print("\n[TEST 4] Threat Escalation (Reconnaissance -> Action on Objectives)")
print("   -> Expectation: System detects the attacker shifted from simple Scanning to active Brute Forcing.")
try:
    # Recon Phase
    requests.get(TARGET + "/?nikto=test", proxies=proxies, timeout=3)
    time.sleep(1)
    # Action on Objective Phase
    requests.post(TARGET + "/login.php", data={"uname": "admin", "pass": "admin"}, proxies=proxies, timeout=3)
except: pass
time.sleep(2)

# -----------------------------------------------------------------------------------------
# Test 5: Dynamic Risk Threshold & Network State (Brute Force DDoS vs Normal Load)
# -----------------------------------------------------------------------------------------
print("\n[TEST 5] Dynamic Network State (Heavy Load adjusting Brute Force thresholds)")
print("   -> Expectation: 25 threads fire simultaneously. Network load spikes. Threshold adapts to HIGH.")
def intense_brute_force(attempt):
    try:
        requests.post(TARGET + "/login.php", data={"uname": "admin", "pass": f"test{attempt}"}, proxies=proxies, timeout=3)
    except: pass

with concurrent.futures.ThreadPoolExecutor(max_workers=25) as executor:
    futures = [executor.submit(intense_brute_force, i) for i in range(40)]
    concurrent.futures.wait(futures)

time.sleep(2)

# -----------------------------------------------------------------------------------------
# Test 6: Critical Asset Multiplication (High CARS scoring)
# -----------------------------------------------------------------------------------------
print("\n[TEST 6] Critical Infrastructure Attack (Admin Portal SQLi -> CARS ~10.0)")
print("   -> Expectation: Even a single SQLi string hits the maximum severity because it targets /admin")
try:
    requests.get(TARGET + "/admin/config.php?db=1; DROP TABLE users", proxies=proxies, timeout=3)
except: pass
time.sleep(2)

# -----------------------------------------------------------------------------------------
# Test 7: ML Behavioral Fallback (Data Exfiltration via Massive Payload)
# -----------------------------------------------------------------------------------------
print("\n[TEST 7] Pure ML Behavioral Anomaly (Data Exfiltration logic / NO Signatures)")
print("   -> Expectation: Signature engine finds nothing, but ML flags the 5000 byte outbound anomaly.")
try:
    huge_payload = "A" * 5000
    requests.post(TARGET + "/api/upload", data={"data": huge_payload}, proxies=proxies, timeout=3)
except: pass


print("\n" + "="*80)
print("✅ ALL EXHAUSTIVE VALIDATION TESTS COMPLETED.")
print("Look at the Sentinel React UI logs to verify 'Explainability Engine' readouts for every layer!")
