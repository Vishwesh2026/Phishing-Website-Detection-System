# 🛡️ SafeSurf — Phishing Website Detection System v3.1

[![FastAPI](https://img.shields.io/badge/API-FastAPI-05998b.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com/)
[![XGBoost](https://img.shields.io/badge/ML-XGBoost-15a0cf.svg?style=flat&logo=xgboost)](https://xgboost.readthedocs.io/)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-3776ab.svg?style=flat&logo=python)](https://www.python.org/)
[![Docker](https://img.shields.io/badge/Deployment-Docker-2496ed.svg?style=flat&logo=docker)](https://www.docker.com/)

> **Production-grade, Infrastructure-Aware ML API** for real-time phishing URL detection.  
> Combines deterministic DNS Guard checks with a calibrated XGBoost ensemble.

---

## 🏗️ Architecture & Core Components

The system uses a **layered, deterministic + probabilistic detection pipeline**. Every URL is challenged at each gate before reaching the ML model.

```text
phishing-detection/
├── app/
│   ├── main.py                        ← FastAPI app factory + CORS + body-size middleware
│   ├── config.py                      ← Pydantic Settings (all values env-driven)
│   ├── routers/
│   │   └── predict.py                 ← /api/v1/analyze, /api/v1/metrics, /health
│   ├── services/
│   │   ├── model_service.py           ← Inference + drift guard + calibration
│   │   ├── dns_guard.py               ← Deterministic NXDOMAIN pre-check  ← NEW
│   │   └── whois_service.py           ← RDAP WHOIS lookups & DomainInfo
│   ├── schemas/
│   │   └── prediction_schema.py       ← Pydantic v2 schemas (incl. invalid state)
│   └── utils/
│       ├── deep_feature_extractor.py  ← 111 features: Lexical + DNS + SSL + WHOIS
│       └── url_normalizer.py          ← Canonical URL form (trailing slashes, case) ← NEW
├── models/
│   ├── phishing_deep_v1.pkl           ← Active production model (Calibrated XGBoost)
│   ├── deep_feature_cols.json         ← Canonical 111-feature list for production
│   ├── phishing_deep_clean_v1.pkl     ← Model trained on PhiUSIIL 200k dataset
│   └── deep_feature_cols_clean.json   ← Feature list for the clean model
├── training/
│   ├── generate_training_dataset.py   ← Phase 1: Extract features from 200k+ URLs  ← NEW
│   ├── train_deep_clean.py            ← Phase 2: Train XGBoost + IsotonicRegression ← NEW
│   ├── validate_clean_model.py        ← Phase 3: Sanity-check model on live domains  ← NEW
│   └── train_deep.py                  ← Original training script (existing dataset)
├── Dataset/
│   ├── PhiUSIIL_Phishing_URL_Dataset.csv   ← 235k-URL source dataset
│   └── generated_training_dataset_clean.csv ← Generated feature CSV for training
├── experiments/
│   ├── metrics.json                   ← Production model metrics (shown on homepage)
│   └── metrics_clean.json             ← Clean model metrics
├── templates/
│   └── index.html                     ← Visual Security Dashboard (Jinja2 + JS)
├── chrome-extension/                  ← Browser plugin (manifest.json, popup, background)
├── Dockerfile                         ← Multi-stage production image
└── requirements.txt                   ← Python dependencies
```

---

## 🔒 Detection Pipeline (Layered)

```
URL submitted
     │
     ▼ Step 1 — URL Canonicalization (url_normalizer.py)
     │  Normalize: lowercase scheme/host, remove default ports,
     │  strip fragments, collapse trailing slashes → consistent input
     │
     ▼ Step 2 — DNS Guard (dns_guard.py)                   ← DETERMINISTIC
     │  Resolve A record for the domain
     │  ├─ NXDOMAIN / NoAnswer → return "invalid" (HIGH risk) immediately
     │  └─ Timeout → allow ML pipeline to proceed (degraded mode)
     │
     ▼ Step 3 — Feature Extraction (deep_feature_extractor.py)
     │  Layer A: 97  lexical features (URL character counts, lengths, patterns)
     │  Layer B: 14  infrastructure features (DNS A/NS/MX, TTL, SSL, WHOIS timing)
     │           All run concurrently via asyncio.gather with 15s timeout
     │
     ▼ Step 4 — ML Inference (model_service.py)            ← PROBABILISTIC
     │  SimpleImputer replaces -1 sentinels with column medians
     │  XGBoost traverses its ensemble of 400 decision trees
     │  IsotonicRegression calibrates raw score → true probability
     │
     ▼ Step 5 — Risk Mapping & Response
        prob ≥ 0.85 → HIGH   |  prob ≥ 0.65 → MEDIUM  |  else → LOW
        Pydantic validates response shape and returns JSON
```

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
python -m venv venv
venv\Scripts\activate         # Windows
# source venv/bin/activate    # Linux/macOS
pip install -r requirements.txt
```

### 2. Configure Environment
```bash
copy .env.example .env        # Windows
# cp .env.example .env        # Linux/macOS
```
The default `MODEL_VERSION=clean_v1` is recommended for the most robust detection.

### 3. Start the Server
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Open **`http://127.0.0.1:8000`** to see the Security Dashboard.

### 4. Test the API
```powershell
# Safe site
Invoke-RestMethod -Method POST http://127.0.0.1:8000/api/v1/analyze `
  -ContentType application/json -Body '{"url":"https://google.com"}'

# Known phishing pattern
Invoke-RestMethod -Method POST http://127.0.0.1:8000/api/v1/analyze `
  -ContentType application/json -Body '{"url":"https://secure-paypal-verify.xyz/login"}'

# Non-existent domain (triggers DNS Guard)
Invoke-RestMethod -Method POST http://127.0.0.1:8000/api/v1/analyze `
  -ContentType application/json -Body '{"url":"https://this-domain-does-not-exist-abc123.com"}'
```

### 5. Install Chrome Extension
1. Open `chrome://extensions/`
2. Enable **Developer mode** (top right)
3. Click **Load unpacked** → select the `chrome-extension/` folder
4. Pin the SafeSurf shield icon in your toolbar

---

## 📊 API Reference

### `POST /api/v1/analyze`
The core inference endpoint. Runs canonicalization → DNS Guard → feature extraction → ML.

**Request:**
```json
{ "url": "https://secure-login.verify-account.xyz/auth" }
```

**Response — Phishing:**
```json
{
  "url": "https://secure-login.verify-account.xyz/auth",
  "prediction": "phishing",
  "label": 1,
  "confidence": 0.9859,
  "risk_level": "HIGH",
  "reason": null,
  "infrastructure": { "tls_ssl_certificate": 0, "qty_nameservers": 1, "qty_ip_resolved": 1 },
  "domain_info": { "domain_age": "2 days", "whois_available": true, "is_new_domain": true },
  "degraded": false,
  "latency_ms": 3241.5,
  "model_version": "clean_v1"
}
```

**Response — Non-existent Domain (DNS Guard):**
```json
{
  "url": "https://this-does-not-exist.xyz",
  "prediction": "invalid",
  "label": 1,
  "confidence": 1.0,
  "risk_level": "HIGH",
  "reason": "Domain does not resolve (NXDOMAIN)",
  "infrastructure": null,
  "domain_info": null,
  "degraded": false,
  "latency_ms": 148.2,
  "model_version": "clean_v1"
}
```

**Prediction values:** `"safe"` | `"phishing"` | `"invalid"` | `"unknown"`  
**Risk levels:** `"HIGH"` | `"MEDIUM"` | `"LOW"` | `"UNKNOWN"`

---

### `GET /health`
```json
{ "status": "healthy", "model_loaded": true, "model_version": "clean_v1" }
```

### `GET /api/v1/metrics`
Returns `experiments/metrics.json` — used by the homepage UI to render accuracy metrics.

### `POST /reload-model`
Hot-reloads the ML model file without restarting uvicorn. Call after replacing the `.pkl`.

---

## 🧠 Training a New Model (3-Phase Pipeline)

For large-scale retraining using the **PhiUSIIL 200k-URL dataset**:

### Phase 1 — Feature Dataset Generation (~10–15 min)
```bash
python -m training.generate_training_dataset
```
Runs `DeepFeatureExtractor` in **training mode**: lexical + lightweight DNS only  
(no WHOIS / SSL / HTTP — fast, stable, reproducible). Uses a **domain-level cache** and  
**40 parallel threads**. Saves checkpoints every 5,000 rows.

Output: `Dataset/generated_training_dataset_clean.csv`

### Phase 2 — Model Training (~5–10 min)
```bash
python -m training.train_deep_clean
```
- Stratified **70% train / 10% calibration / 20% test** split
- XGBoost (400 trees, depth=6) + `IsotonicRegression` calibration (prefit pattern —  
  avoids sklearn 1.7 / XGBoost 2.x `__sklearn_tags__` incompatibility)
- Prints full metrics; saves model + feature list

Output: `models/phishing_deep_clean_v1.pkl`, `experiments/metrics_clean.json`

### Phase 3 — Sanity Validation
```bash
python -m training.validate_clean_model
```
Tests google.com, wikipedia.org, github.com against the trained model using the full  
production extractor and asserts they are **not** classified as phishing.

### Training the Original Model (existing dataset)
```bash
python -m training.train_deep
```

### Hot-reload after training
```bash
curl -X POST http://127.0.0.1:8000/reload-model
```

---

## ⚙️ Configuration (`.env`)

| Variable | Description | Default |
|---|---|---|
| `APP_ENV` | `development` or `production` | `development` |
| `MODEL_VERSION` | Which `.pkl` to load (`phishing_deep_{VERSION}.pkl`) | `clean_v1` |
| `PHISHING_THRESHOLD` | Probability ≥ this triggers phishing | `0.5` |
| `MAX_CONCURRENT` | Semaphore — max concurrent analyses | `10` |
| `TIMEOUT_SECS` | Per-check infrastructure timeout (seconds) | `15.0` |
| `ALLOWED_ORIGINS` | Comma-separated CORS origins | `*` |
| `MAX_REQUEST_BODY_BYTES` | Max JSON payload size | `8192` |
| `LOG_LEVEL` | `DEBUG` / `INFO` / `WARNING` / `ERROR` | `INFO` |

---

## 🐳 Docker Deployment

```bash
# Build
docker build -t safesurf-phishing-detector .

# Run (mount models so you can update them without rebuilding)
docker run -p 8000:8000 \
  -e APP_ENV=production \
  -v $(pwd)/models:/app/models \
  safesurf-phishing-detector
```

---

## 📖 Technical Documentation

For an exhaustive breakdown of the 111 features, sentinel policy, calibration mechanics,  
failure modes, and security architecture, see **[Documentation.md](./Documentation.md)**.
