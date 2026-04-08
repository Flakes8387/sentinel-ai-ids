import json
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import socketio
import joblib
import pandas as pd

import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin

from sklearn.neural_network import MLPRegressor

# Required for joblib unpickling
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Input, Dense

class KerasAutoEncoderFeatureExtractor(BaseEstimator, TransformerMixin):
    def __init__(self, input_dim=3, latent_dim=2, epochs=20, batch_size=256):
        self.input_dim = input_dim
        self.latent_dim = latent_dim
        self.epochs = epochs
        self.batch_size = batch_size
        self.autoencoder = None
        
    def _build_model(self):
        input_layer = Input(shape=(self.input_dim,))
        encoded = Dense(16, activation='relu')(input_layer)
        encoded = Dense(8, activation='relu')(encoded)
        latent = Dense(self.latent_dim, activation='relu', name='bottleneck')(encoded)
        
        decoded = Dense(8, activation='relu')(latent)
        decoded = Dense(16, activation='relu')(decoded)
        output_layer = Dense(self.input_dim, activation='linear')(decoded)
        
        autoencoder = Model(inputs=input_layer, outputs=output_layer)
        autoencoder.compile(optimizer='adam', loss='mse')
        return autoencoder

    def fit(self, X, y=None):
        return self
        
    def transform(self, X):
        X_num = X.values if isinstance(X, pd.DataFrame) else X
        
        reconstructed = self.autoencoder.predict(X_num, verbose=0)
        mse = np.mean(np.square(X_num - reconstructed), axis=1).reshape(-1, 1)
        
        return np.hstack([X_num, mse])
        
    def __getstate__(self):
        state = self.__dict__.copy()
        if self.autoencoder is not None:
            state['keras_weights'] = self.autoencoder.get_weights()
            state['autoencoder'] = None
        return state
        
    def __setstate__(self, state):
        self.__dict__.update(state)
        if 'keras_weights' in state:
            self.autoencoder = self._build_model()
            self.autoencoder.set_weights(state['keras_weights'])
            del self.__dict__['keras_weights']

logging.basicConfig(level=logging.INFO, filename="alert.log", format="%(asctime)s - %(levelname)s - %(message)s")

app = FastAPI(title="IDS Backend", version="1.0.0")

# Setup CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

import sys

# Setup Socket.IO
sio = socketio.AsyncServer(async_mode='asgi', cors_allowed_origins="*")

# Try to load model
artifact = None
try:
    # Explicitly map the class to __main__ because Colab pickled it from its __main__ notebook namespace
    sys.modules['__main__'].KerasAutoEncoderFeatureExtractor = KerasAutoEncoderFeatureExtractor
    
    artifact = joblib.load("model.joblib")
    logging.info(f"Model artifact loaded successfully: {artifact['description']} (Version {artifact['version']})")
except Exception as e:
    logging.warning(f"Failed to load model on startup: {e}")

@app.get("/")
def read_root():
    return {"status": "ok", "message": "IDS Backend Running"}

from fastapi import HTTPException
@app.post("/api/v1/auth/login")
def dummy_login():
    raise HTTPException(status_code=401, detail="Invalid Credentials")

@app.post("/api/feedback")
async def analyst_feedback(data: dict):
    client_ip = data.get("client_ip")
    if client_ip:
        ip_historical_memory[client_ip] = 0
        if client_ip in ip_escalation_stages:
            ip_escalation_stages[client_ip].clear()
        if client_ip in ip_anomaly_tracker:
            ip_anomaly_tracker[client_ip].clear()
        logging.info(f"Analyst marked IP {client_ip} as safe. History cleared.")
        return {"status": "success", "message": "Feedback received."}
    return {"status": "ignored"}

import time
import hashlib
from collections import defaultdict

# Alert Correlation Engine State (IP -> list of timestamps)
ip_anomaly_tracker = defaultdict(list)

# Global Network State Tracker
global_traffic_timestamps = []

# Attack Pattern Memory
ip_historical_memory = defaultdict(int)

# Threat Escalation Score (Lifecycle tracking)
ip_escalation_stages = defaultdict(set)

@app.post("/api/analyze")
async def analyze_traffic(traffic_data: dict):
    start_time = time.time()
    
    # 1️⃣ Dynamic Risk Threshold Based on Network State
    global global_traffic_timestamps
    current_t = time.time()
    global_traffic_timestamps = [t for t in global_traffic_timestamps if current_t - t < 10.0]  # Rolling 10s window
    global_traffic_timestamps.append(current_t)
    
    network_load = len(global_traffic_timestamps)
    # If the backend is processing > 20 requests per 10 seconds, it's considered high load
    if network_load > 20:
        dynamic_brute_force_threshold = 15
    else:
        dynamic_brute_force_threshold = 5

    is_anomaly = False
    risk_score = 0.0
    threat_type = "Normal"
    explanations = []
    
    # 1. Resolve GeoIP Coordinates
    # Deterministically hash the IP into a coordinate to simulate Global Locations without an external API key blocker
    client_ip = traffic_data.get("client_ip", "127.0.0.1")
    ip_hash = int(hashlib.md5(client_ip.encode()).hexdigest(), 16)
    lat = float((ip_hash % 140) - 70) # Restrict lat slightly so dots don't spawn on absolute poles
    lon = float(((ip_hash // 180) % 360) - 180)
    
    if artifact:
        model = artifact['model']
        
        # Map authentic MITM traffic parameters to the 16 advanced features expected by the NSL-KDD trained model
        dur = traffic_data.get("duration", 0.0)
        src_bytes = traffic_data.get("src_bytes", traffic_data.get("content_length", 0))
        dst_bytes = traffic_data.get("dst_bytes", 0)
        count = traffic_data.get("count", 0)
        srv_count = traffic_data.get("srv_count", count)
        
        # Build features seamlessly using the TRUE 16 extracted variables directly
        features = pd.DataFrame([{
            'duration': float(dur),
            'src_bytes': float(src_bytes),
            'dst_bytes': float(dst_bytes),
            'count': float(count),
            'srv_count': float(srv_count),
            'serror_rate': float(traffic_data.get("serror_rate", 0.0)),
            'srv_serror_rate': float(traffic_data.get("srv_serror_rate", 0.0)),
            'rerror_rate': float(traffic_data.get("rerror_rate", 0.0)),
            'same_srv_rate': float(traffic_data.get("same_srv_rate", 1.0)),
            'diff_srv_rate': float(traffic_data.get("diff_srv_rate", 0.0)),
            'dst_host_count': float(traffic_data.get("dst_host_count", 1.0)),
            'dst_host_srv_count': float(traffic_data.get("dst_host_srv_count", 1.0)),
            'dst_host_same_srv_rate': float(traffic_data.get("dst_host_same_srv_rate", 1.0)),
            'dst_host_diff_srv_rate': float(traffic_data.get("dst_host_diff_srv_rate", 0.0)),
            'dst_host_serror_rate': float(traffic_data.get("dst_host_serror_rate", 0.0)),
            'dst_host_srv_serror_rate': float(traffic_data.get("dst_host_srv_serror_rate", 0.0))
        }])
        
        # Inference
        pred = model.predict(features)[0]
        prob = model.predict_proba(features)[0]
        
        # Hybrid Detection Engine: 1. Deep Packet Signature Matching
        import urllib.parse
        raw_path_str = traffic_data.get("path", "")
        path_str = urllib.parse.unquote(raw_path_str).lower()
        
        if "1=1" in path_str or "1'='1" in path_str or "select " in path_str or "union " in path_str or "drop table" in path_str:
            is_anomaly = True
            threat_type = "SQL Injection (SQLi)"
            risk_score = 0.95  # Highest confidence
            explanations.append("Deep Packet Signature match: SQLi artifacts found in URL")
        elif "../" in path_str or "etc/passwd" in path_str or "win.ini" in path_str:
            is_anomaly = True
            threat_type = "Path Traversal / LFI"
            risk_score = 0.90
            explanations.append("Deep Packet Signature match: Directory traversal dots/paths found")
        elif "<script" in path_str or "javascript:" in path_str or "onerror=" in path_str:
            is_anomaly = True
            threat_type = "Cross-Site Scripting (XSS)"
            risk_score = 0.85
            explanations.append("Deep Packet Signature match: Client-side JS tags identified in payload")
        elif "nmap" in path_str or "nikto" in path_str or "sqlmap" in path_str:
            is_anomaly = True
            threat_type = "Automated Vulnerability Scanner"
            risk_score = 0.80
            explanations.append("Deep Packet Signature match: Scanner footprint detected in query")
        else:
            # Hybrid Detection Engine: 2. Behavioral ML Anomaly Modeling
            if pred == 1:
                is_anomaly = True
                risk_score = float(prob[1])
                explanations.append(f"AI Anomaly Detected (Probability: {(risk_score*100):.1f}%)")
                
            # If a large burst of identical connections happens, or it strictly attacks auth endpoints
            if count > dynamic_brute_force_threshold or "login" in path_str or "userinfo" in path_str:
                is_anomaly = True
                risk_score = max(risk_score, 0.8)
                threat_type = "Brute Force (U2R) / Credential Stuffing"
                explanations.append(f"Anomalous burst of concurrent requests ({int(count)} vs Dynamic Threshold {dynamic_brute_force_threshold})")
                if network_load > 20:
                    explanations.append("System adapted threshold to HIGH due to intense network traffic load.")
                else:
                    explanations.append("System adapted threshold to LOW due to nominal network traffic load.")
            elif src_bytes > 2000:
                is_anomaly = True
                risk_score = max(risk_score, 0.8)
                threat_type = "Data Exfiltration Anomaly"
                explanations.append(f"Massive outbound payload spike detected ({int(src_bytes)} Bytes) on non-media path.")
            elif is_anomaly:
                threat_type = "R2L Web Exploit Anomaly"
                explanations.append("Generic timing and size abnormalities triggered behavioral model fallback.")
                
    else:
        # No ML model available, do not scan
        logging.error("Inference failed: ML model artifact is missing or offline.")
        return {
            "is_anomaly": False,
            "threat_type": "Unscanned (Model Offline)",
            "risk_score": 0.0,
            "traffic": traffic_data,
            "error": "Service Unavailable"
        }
            
    # Calculate CARS Contextual impact via external inventory file
    weight = 0.3
    try:
        import json
        with open("asset_inventory.json", "r") as f:
            inventory = json.load(f)
            weights = inventory.get("weights", {})
            weight = inventory.get("default_weight", 0.3)
            
            # Map path/host to criticality weight
            path_str = traffic_data.get("path", "").lower()
            host_str = traffic_data.get("host", "").lower()
            
            for k, v in weights.items():
                if k in path_str or k in host_str:
                    weight = v
                    break
    except Exception as e:
        logging.error(f"Failed to calculate CARS weight from inventory: {e}")
            
    # Final Risk Score = Likelihood (ML prob) * Impact (Weight)
    final_risk = risk_score * weight if is_anomaly else risk_score
    
    if is_anomaly:
        # Alert Correlation Engine: Temporal Analysis by IP
        current_t = time.time()
        ip_anomaly_tracker[client_ip] = [t for t in ip_anomaly_tracker[client_ip] if current_t - t < 60.0]
        ip_anomaly_tracker[client_ip].append(current_t)
        anomaly_count = len(ip_anomaly_tracker[client_ip])
        
        if anomaly_count > 3:
            correlation_penalty = min(0.3, anomaly_count * 0.05)
            final_risk = min(1.0, final_risk + correlation_penalty)
            explanations.append(f"Event Correlation Engine: Threat Escalated. Recorded {anomaly_count} distinct attacks from IP {client_ip} within 60s.")
            
        # 2️⃣ Attack Pattern Memory (Lightweight Learning)
        ip_historical_memory[client_ip] += 1
        historical_count = ip_historical_memory[client_ip]
        if historical_count > 1:
            import math
            memory_penalty = min(0.2, 0.05 * math.log10(historical_count * 10))
            final_risk = min(1.0, final_risk + memory_penalty)
            explanations.append(f"Attack Pattern Memory: Known repeat offender ({historical_count} historical incidents).")

        # 4️⃣ Threat Escalation Score (Lifecycle tracking)
        if "Scanner" in threat_type:
            macro_stage = "Reconnaissance"
        elif "Brute Force" in threat_type:
            macro_stage = "Action on Objectives (Login)"
        elif "Exfiltration" in threat_type:
            macro_stage = "Data Exfiltration"
        else:
            macro_stage = "Exploitation"
            
        ip_escalation_stages[client_ip].add(macro_stage)
        stages_completed = len(ip_escalation_stages[client_ip])
        if stages_completed > 1:
            escalation_penalty = 0.15 * (stages_completed - 1)
            final_risk = min(1.0, final_risk + escalation_penalty)
            explanations.append(f"Threat Escalation Engine: Multi-stage attack detected from this IP. Progression: {', '.join(ip_escalation_stages[client_ip])}.")
            
        # Normalize final risk back to 0-1 for frontend visualization scale
        final_risk = min(final_risk + 0.3, 1.0)
        
    # Calculate true inference latency
    latency_ms = round((time.time() - start_time) * 1000, 2)
    
    result = {
        "is_anomaly": is_anomaly,
        "threat_type": threat_type,
        "risk_score": final_risk,
        "traffic": traffic_data,
        "location": {"lat": lat, "lon": lon},
        "latency_ms": latency_ms,
        "explanations": explanations
    }
    
    if is_anomaly:
        logging.warning(f"ANOMALY DETECTED: {json.dumps(result)}")
        await sio.emit("new_alert", result)
        
    return result

@sio.on("connect")
async def connect(sid, environ):
    print(f"Client connected: {sid}")

@sio.on("disconnect")
def disconnect(sid):
    print(f"Client disconnected: {sid}")

# Wrap the FastAPI application into the Socket.IO ASGI application so they run seamlessly on the same port globally.
app = socketio.ASGIApp(sio, other_asgi_app=app)
