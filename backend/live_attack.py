import requests
import os
import concurrent.futures
import time

proxies = {
    "http": "http://127.0.0.1:8080",
    "https": "http://127.0.0.1:8080",
}

# Point directly to mitmproxy's Root Certificate Authority to completely bypass SSL/TLS errors.
# This forces "requests" to legally trust the Man-in-the-Middle decryption bridge.
ca_cert = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")

print(f"🔒 Engaging Native SSL Decryption using CA: {ca_cert}")
print("🚀 Initiating LIVE HTTPS Brute Force Attack against https://httpbin.org/status/401")
print("This will send 40 concurrent encrypted HTTPS requests...")

def send_request():
    try:
        # We explicitly target an HTTPS endpoint and provide the verify CA cert.
        # We target a /401 path which naturally simulates an Authentication Failure.
        requests.get("https://httpbin.org/status/401", proxies=proxies, verify=ca_cert, timeout=5)
    except Exception as e:
        pass

start = time.time()

# Flood the target HTTPS server with 40 requests rapidly
with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
    futures = [executor.submit(send_request) for _ in range(40)]
    concurrent.futures.wait(futures)

duration = time.time() - start
print(f"✅ Live HTTPS Attack complete in {duration:.2f} seconds.")
print("Look at your Sentinel Dashboard to see the intercepted unencrypted packets organically tracked!")
