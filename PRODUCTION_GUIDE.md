# Sentinel AI - Production Deployment Guide

Transitioning Sentinel AI from a local development environment (running via `npm run dev` and `uvicorn --reload`) to an Enterprise-grade Production system requires hardening the architecture, securing the communications, and scaling the infrastructure.

## 1. Architecture Overhaul (Docker & Kubernetes)
Currently, the system runs on raw processes in a MacOS terminal. In production, this must be containerized.
- **Dockerize Everything:** Create a `Dockerfile` for the React Frontend UI (using Nginx to serve the static build). Create a separate `Dockerfile` for the FastAPI backend (using Uvicorn with Gunicorn process managers) and the `mitmdump` proxy layer.
- **Kubernetes (K8s):** Deploy the containers using Kubernetes. This allows the backend ML processing to auto-scale if your network gets hit by a massive DDoS attack.

## 2. Proxy Implementation (Reverse Proxy & MITM)
Right now, you are manually running `mitmproxy` and pointing test scripts at it.
- **Transparent Proxying:** Configure `mitmproxy` or `mitmdump` to run in "Transparent Mode" on a dedicated Linux gateway server. Route all incoming traffic from the internet through this gateway *before* it hits your actual web application server.
- **SSL Stripping/Decryption:** Install the `mitmproxy-ca-cert.pem` into the trusted root store of your actual Application Servers. This allows Sentinel to decrypt incoming HTTPS traffic, inspect the payload for attacks via the ML Engine, and re-encrypt it before it reaches the backend web server.

## 3. Storage and Database (From In-Memory to Persistent)
Currently, all logs are transient (stored in React state) or held loosely in local storage.
- **Time-Series Database:** Connect the Python backend to a Time-Series Database like **InfluxDB** or **Elasticsearch**. Every time an attack is detected, write the JSON payload to the database.
- **SIEM Integration:** Connect your backend to a Security Information and Event Management (SIEM) tool like Splunk. This allows long-term threat hunting and compliance reporting.

## 4. WebSockets to Message Broker (Redis/Kafka)
FastAPI's built-in WebSockets are great for a single dashboard, but what if you have 5 security analysts looking at 5 different screens?
- **Redis Pub/Sub or Kafka:** Instead of having FastAPI maintain direct WebSocket connections to the frontend, have the ML Model push alerts to a Redis queue or Kafka topic. The frontend UI can then subscribe to that queue. This ensures zero dropped alerts during massive attack spikes.

## 5. Security & Authentication
- **Protect the Dashboard:** The React Dashboard currently has no login. You must implement robust JWT/OAuth2 authentication (e.g., Auth0 or Keycloak) so only authorized Security Operations Center (SOC) analysts can view the map.
- **API Security:** The FastAPI backend is open on port 8000. Use API Keys and rate limiting so an attacker cannot intentionally DDoS your Intrusion Detection System's API.

## 6. Frontend Build Optimization
- Stop using `npm run dev` (Vite's development server).
- Run `npm run build` in the frontend folder. This bundles your entire React application into a highly compressed, optimized set of static files.
- Serve that `dist` folder using a blistering fast web server like **NGINX** or upload it directly to a CDN like AWS CloudFront.
