# Architecting Sentinel IDS for Enterprise Production

This document outlines the final critical steps required to transition the Sentinel Artificial Intelligence Intrusion Detection System from a working architectural prototype into a production-hardened enterprise deployment.

## Phase 1: Operational Success Roadmap
1.  **True Machine Learning Integration**: Synthesized data proves the architecture; a bespoke network artifact (e.g., CICIDS2017) proves the security. The deep Autoencoder must learn the latent structure of *your* organization's specific baseline traffic. (See Phase 2).
2.  **Container Orchrestration**: Instead of managing independent node servers and python interpreters, the software must be executed universally. Run `docker-compose up -d --build` to deploy the robust FastAPI worker and Vite UI on identical network bridges.
3.  **Live Interception Node**: A router or local proxy must be designated as the active `mitmproxy` interceptor. It runs `mitmproxy -s backend/mitm.py --mode transparent` to blindly catch and forward raw HTTP metrics to the analytical backend.
4.  **SIEM Webhook Expansion**: To become an enterprise security nervous system, the `app.py` logging core requires an outbound `POST` request to push critical CARS alerts (Context-Aware Risk Score > 0.85) to external endpoints like Datadog, Slack webhooks, or Splunk instances.
5.  **Geographic UI Hardening**: The React dashboard's (`App.jsx`) spatial threat map requires integration with `react-simple-maps` and a native IP resolution database (MaxMind GeoLite2) to transform raw JSON IPs into explicit latitude/longitude vectors on the globe.

---

## Phase 2: Google Colab Model Training Procedure
The current configuration uses the `Colab_Model_Training.ipynb` file sitting in the project repository. Executing this accurately is the most crucial requirement for system efficacy.

### Step 1: Initialize the Environment
1.  Launch [Google Colab](https://colab.research.google.com/).
2.  Select **File > Upload Notebook** and select the local `Colab_Model_Training.ipynb` from this Antigravity project folder.
3.  In Colab, go to **Runtime > Change runtime type** and ensure the Hardware Accelerator is set to **T4 GPU** or **A100 GPU**. The Neural Network (Encoder/Decoder) mathematically requires parallel processing acceleration to execute efficiently.

### Step 2: Establish the Dataset
By default, the notebook generates synthetic tabular data matching our 3 core dimensions (`bytes_transferred`, `connection_duration`, `failed_logins`). 
1.  Add a new code block at the top of the notebook:
    ```python
    from google.colab import drive
    drive.mount('/content/drive')
    ```
2.  Replace the `load_dataset()` synthetic arrays with a `pd.read_csv()` pointing to your mounted dataset. (For example, download the **NSL-KDD** benchmark PCAP CSVs into your Google Drive). 
3.  Ensure your column mapping aligns exactly with the 3 inputs that the FastAPI backend (`app.py`) parses from `mitmproxy`.

### Step 3: Train the Hybrid Architecture
1.  Navigate to the **Runtime > Run All**.
2.  **The Autoencoder Phase**: Watch the epochs. The GPU will aggressively train the deep bottleneck layer *solely* against the `y=0` (Normal) traffic parameters. This teaches it what "benign" mathematics look like.
3.  **The Random Forest Phase**: The notebook will then extract the Mean Squared Error (MSE/Reconstruction Loss) derived by the bottleneck layer for *all* traffic, and feed it into the Scikit-Learn Random Forest ensemble. 

### Step 4: Export the Universal Artifact
1.  The final execution block invokes `joblib.dump()`. This freezes the Multi-Layer Perceptron (neural bounds), the ensemble tree nodes, and the Label features into a singular payload object.
2.  In the left-hand taskbar of Google Colab, open the **Files** directory interface (`📁`).
3.  Download `model.joblib`.
4.  Drag and drop the newly downloaded artifact into the local `/backend` folder of this Antigravity project, overwriting the old simulation artifact.
5.  The FastAPI inference backend hot-reloads instantly, parsing live traffic networks with genuine threat precision.
