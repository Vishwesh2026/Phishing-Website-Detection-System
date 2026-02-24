# 🛡️ Phishing Website Detection System — v3.0

> **Production-grade, Infrastructure-Aware ML API** for real-time phishing URL detection.  
> Built with FastAPI · scikit-learn · XGBoost · Docker · Chrome Extension

![Dashboard Preview](templates/index.html) *(See dashboard locally on port 8000)*

---

## 🏗️ Architecture & Core Components

This system uses a single** Deep XGBoost Model** trained on 111 structural and infrastructural features. It performs real-time external networking to validate domains before predicting.

```text
phishing-detection/
├── app/
│   ├── main.py                    ← FastAPI app factory + middleware
│   ├── config.py                  ← Pydantic Settings (env-driven)
│   ├── routers/
│   │   └── predict.py             ← /api/v1/analyze, /api/v1/metrics, /health
│   ├── services/
│   │   ├── model_service.py       ← Inference + drift guard + calibration
│   │   └── whois_service.py       ← RDAP WHOIS lookups
│   ├── schemas/
│   │   └── prediction_schema.py   ← Pydantic v2 schemas
│   └── utils/
│       └── deep_feature_extractor.py ← Extracts 111 features (Lexical + DNS + SSL)
├── models/
│   └── phishing_deep_v1.pkl       ← Active ML model (Calibrated XGBoost)
├── training/
│   └── train_deep.py              ← Model training & evaluation pipeline
├── experiments/                   
│   └── metrics.json               ← Latest evaluation metrics (shown on homepage)
├── templates/
│   └── index.html                 ← Visual Security Dashboard (Frontend)
├── chrome-extension/              ← Browser plugin (manifest.json, background.js)
├── Dockerfile                     ← Multi-stage production image
└── requirements.txt               ← Python dependencies
```

---

## 🚀 Complete Walkthrough & Quick Start Guide

Follow these exact steps to spin up the entire system from scratch, verify the API, and install the browser extension.

### Step 1: Install Dependencies
Create an isolated environment and install the required packages.
```bash
python -m venv venv

# Windows
venv\Scripts\activate
# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

### Step 2: Configure Environment
Set up your local environment file. 
```bash
# Windows
copy .env.example .env
# Linux / macOS
cp .env.example .env
```
*Note: The default `MODEL_VERSION=v1` inside `.env` is perfectly fine.*

### Step 3: Start the Backend Server
Launch the FastAPI application using Uvicorn.
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
You should see `Application startup complete` in your terminal. 

### Step 4: Verify the Dashboard & Metrics
1. Open your browser and navigate to: **`http://127.0.0.1:8000/`**
2. You will see the **SafeSurf Security Dashboard**.
3. Scroll down to see the **Model Performance** metrics populated dynamically from the latest `experiments/metrics.json` file.

### Step 5: Test the Inference API (CLI)
You can test the core analysis endpoint directly via `curl` or PowerShell. 

```bash
# Test a known safe site
curl -X POST http://127.0.0.1:8000/api/v1/analyze \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"https://www.google.com\"}"
```
*Expected Output:* A JSON payload with `prediction: "safe"` and a `confidence` score > 95%.

### Step 6: Install the Chrome Extension
Monitor URLs automatically as you browse the web.
1. Open Google Chrome and go to exactly **`chrome://extensions/`** in the URL bar.
2. Toggle **"Developer mode"** ON (top right corner).
3. Click the **"Load unpacked"** button (top left).
4. Select the `chrome-extension/` folder located inside this project directory.
5. The **SafeSurf shield icon** will appear in your Chrome toolbar. Pin it.
6. Visit a suspicious site—the extension will turn red and warn you!

---

## 🧪 Training a New Model

If you have an updated `dataset_full.csv` inside `/Dataset/` and want to retrain the XGBoost engine:

```bash
python -m training.train_deep
```

**What happens underneath:**
1. Loads 111 columns of data.
2. Trains an XGBoost classifier.
3. Applies Isotonic Calibration for probability realism.
4. Evaluates on a 20% holdout test set.
5. Overwrites `experiments/metrics.json` and `models/phishing_deep_v1.pkl`.  
*(The UI Dashboard automatically updates its metrics upon page refresh!)*

To hot-reload the newly trained model into the running server without restarting uvicorn:
```bash
curl -X POST http://127.0.0.1:8000/reload-model
```

---

## � API Reference

### `POST /api/v1/analyze`
The core inference endpoint. Retrieves external DNS, WHOIS, and SSL data concurrently via `asyncio`.

**Request:**
```json
{ "url": "https://secure-login.verify-account.xyz/auth" }
```

**Response:**
```json
{
  "url": "https://secure-login.verify-account.xyz/auth",
  "prediction": "phishing",
  "label": 1,
  "confidence": 0.9859,
  "risk_level": "HIGH",
  "infrastructure": {
    "tls_ssl_certificate": 0,
    "qty_nameservers": 1,
    "qty_redirects": 3,
    "qty_ip_resolved": 1
  },
  "domain_info": {
    "domain_age": 2,
    "whois_available": true,
    "is_new_domain": true
  },
  "degraded": false,
  "latency_ms": 3983.21,
  "model_version": "v1"
}
```

### `GET /api/v1/metrics`
Reads `experiments/metrics.json` safely. Used by the homepage UI to render model accuracy charts without polluting the inference endpoint.

### `GET /health`
```json
{ "status": "healthy", "model_loaded": true, "model_version": "v1" }
```

---

## 🐳 Docker Deployment

To deploy the API in an isolated container instance:

```bash
# Build the image
docker build -t phishing-detector .

# Run the container (mounting the models folder)
docker run -p 8000:8000 \
  -e APP_ENV=production \
  -v $(pwd)/models:/app/models \
  phishing-detector
```

---

## ⚙️ Advanced Configuration (`.env`)

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_ENV` | `development` or `production` | `development` |
| `MODEL_VERSION` | Version tag of the `.pkl` to load | `v1` |
| `PHISHING_THRESHOLD` | Confidence % required to flag as phishing | `0.5` |
| `MAX_CONCURRENT_REQUESTS`| Semaphore limit to prevent server denial of service | `50` |
| `ALLOWED_ORIGINS` | Comma-separated list for CORS middleware | `*` |
| `MAX_REQUEST_BODY_BYTES`| Prevents massive JSON payloads | `8192` |

---

## � Technical & Pin-to-Pin Documentation
For an exhaustive, step-by-step breakdown of how the ML model calculates probabilities, how Sentinels (-1) are handled, and the specific 111 features extracted, please read **[Documentation.md](./Documentation.md)**.
