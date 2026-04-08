import requests
import concurrent.futures
import time

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080"
}

TARGET = "http://testphp.vulnweb.com"

print("🔥 Launching MAXIMUM SEVERITY Attacks through MITM Proxy (127.0.0.1:8080)")
print("Targeting high-value infrastructure (Admin, Database, Checkout) to trigger 10.0 CARS scores.\n" + "="*60)

payloads = [
    # 1. SQL Injections against 'admin' and 'db' (Weights 1.0 and 0.9 -> CARS 10.0)
    ("/admin/portal.php?user=1' OR '1'='1", "SQL Injection on Admin Portal"),
    ("/db/query.php?action=drop table users", "SQL Injection on Database Interface"),
    
    # 2. Path Traversals against 'checkout' and 'admin' (Weights 0.95 and 1.0 -> CARS 10.0)
    ("/checkout/cart.php?template=../../../../etc/passwd", "Path Traversal on Checkout Module"),
    ("/admin/config.php?load=../../../../Windows/win.ini", "Path Traversal on Admin Configuration"),
    
    # 3. XSS against 'dashboard' (Weight 0.7 -> CARS ~9.0)
    ("/dashboard/stats.php?user=<script>alert('xss')</script>", "Cross-Site Scripting on Dashboard"),
    
    # 4. Automated scanning against 'api' (Weight 0.5)
    ("/api/v1/users?nikto=test", "Automated Scan on API Gateway")
]

print("[*] Dispatching High-Value Signature Exploits...")
for path, desc in payloads:
    try:
        print(f"    -> Sending: {desc}")
        requests.get(TARGET + path, proxies=proxies, timeout=3)
        time.sleep(0.5)
    except:
        pass

# 5. Critical Brute Force DDoS on /admin/login (High weight + DDoS -> CARS ~10.0)
print("\n[*] Initiating Distributed High-Velocity Brute Force on /admin/login.php...")
def brute_force(attempt):
    try:
        requests.post(
            TARGET + "/admin/login.php", 
            data={"uname": "admin", "pass": f"password{attempt}"}, 
            proxies=proxies, 
            timeout=3
        )
    except:
        pass

with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
    futures = [executor.submit(brute_force, i) for i in range(30)]
    concurrent.futures.wait(futures)

print("=" * 60)
print("✅ Devastating High-Severity attacks dispatched to critical infrastructure paths!")
print("Look at your UI: The Posture should be 'Critical Threat' and CARS scores should hit 10.0!")
