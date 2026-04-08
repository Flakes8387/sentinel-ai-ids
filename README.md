# 🛡️ Sentinel AI - Context-Aware Intrusion Detection System

**Sentinel AI** is a next-generation, hybrid Intrusion Detection System (IDS) that mathematically detects, verifies, and prioritizes cyber threats in real-time. Moving beyond binary signature matching, Sentinel employs a multi-layered detection pipeline:
1. **Deep Packet Signature Engine:** Instantly recognizes known attack vectors (SQLi, XSS, LFI).
2. **Behavioral ML Anomaly Modeling:** Verifies suspicious network payloads, exfiltrations, and traffic bursts using Machine Learning.
3. **Alert Correlation & Pattern Memory:** Retains attacker IP history to mathematically escalate Threat risk based on event clustering or multi-stage lifecycles (Reconnaissance -> Action).
4. **Context-Aware Risk Scoring (CARS):** Prioritizes the severity of an attack (0-10) based not just on the payload, but on the *business criticality* of the targeted asset.

## 🚀 Features

*   **Real-Time Threat Dashboard:** A state-of-the-art React dashboard equipped with live Geographical mapping, dynamic network posture scoring, and a thermal decay algorithm that "cools off" when attacks subside.
*   **Explainability Engine:** Translates complex ML classifications into human-readable SOC explanations (e.g. *"System adapted Brute Force threshold to HIGH due to intense network traffic load"*).
*   **Dynamic Hardening:** Automatically adapts intrusion alert thresholds strictly based on rolling 10s network load buffers.
*   **Analyst Feedback Loop (HITL):** Allows SOC Analysts to mark threats as safe, instantly purging historical penalties and alert queues.

---

## 🏗️ Architecture

The platform runs on a modern stack:
*   **Backend:** Python via **FastAPI**, backed by a `scikit-learn` NSL-KDD Machine Learning Engine.
*   **Intercept Proxy:** **Mitmproxy** script to operate as an transparent intermediary logging node.
*   **Frontend:** Vite/React using **Lucide Icons** and **WebSockets** for zero-latency threat publishing.

---

## 🛠️ How to Run Locally

Follow these instructions to spin up the entire Intrusion Detection framework on your local machine.

### One-Command Windows Startup (Recommended)

From the project root, run:

```powershell
npm run dev
```

This command automatically:
1. Creates a Python 3.13 virtual environment in `.venv313` if needed
2. Installs backend dependencies
3. Installs frontend dependencies (including peer-compatibility handling)
4. Opens backend and frontend in separate PowerShell windows

If you only want to install dependencies without launching services:

```powershell
npm run setup
```

### Prerequisites
*   Node.js (`v18+` recommended)
*   Python (`3.9+` recommended)
*   Mitmproxy installed locally (`brew install mitmproxy` or `pip install mitmproxy`)

### Step 1: Start the Machine Learning Backend
Open a terminal, navigate to the backend directory, construct the virtual environment, and launch FastAPI:
```bash
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python -m uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

### Step 2: Start the Network Interceptor (MITM Proxy)
Open a *second* terminal, navigate to the backend directory again, and launch the Python Man-in-the-Middle network scanner. This script computes rolling statistical features and transmits them to the ML backend.
```bash
cd backend
source venv/bin/activate
mitmdump -s mitm.py
```
*(The proxy runs on port `8080` by default).*

### Step 3: Start the React Dashboard
Open a *third* terminal, navigate to the frontend folder, and launch the React UI:
```bash
cd frontend
npm install
npm run dev -- --port 5173
```
You can now open your browser to `http://localhost:5173` to view the SOC Dashboard.

---

## ⚔️ Simulating Attacks
To test the engine, you must route your network attacks *through* the interceptor proxy (`127.0.0.1:8080`). We have provided multiple testing scripts.

Wait for the frontend to finish loading, then execute one of the following:

**1. The Exhaustive Validation Suite (Tests 11 core ML & Signature features):**
```bash
source backend/venv/bin/activate
python exhaustive_test.py
```

**2. The Real-World Attack Router:**
This script points to a public, intentionally vulnerable web-app and routes the physical malicious traffic directly through your proxy.
```bash
source backend/venv/bin/activate
python real_attack.py
```

### 🔒 Confidentiality Note
This repository contains no confidential API keys or production certificates. The `model.joblib` is a standardized ML artifact trained on the benchmark NSL-KDD dataset framework.

## 🤝 Project Structure
*   `backend/app.py`: The Hybrid ML, Explainer, and CARS API server.
*   `backend/mitm.py`: The interceptor engine tracking network states and constructing data frames.
*   `frontend/src/App.jsx`: Main React application managing state, timelines, and WebSocket events.
*   `asset_inventory.json`: Matrix determining the mathematical target value of your infrastructure.

*Developed for Advanced Agentic AI Network Defense Validation.*
