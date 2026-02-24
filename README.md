# 🛡️ Phishing Website Detection System — v2.0

> **Production-grade, SaaS-ready ML API** for real-time phishing URL detection.  
> Built with FastAPI · scikit-learn · XGBoost · Docker · Chrome Extension

---

## 🏗️ Architecture

```
phishing-detection/
├── app/
│   ├── main.py                    ← FastAPI app factory + middleware
│   ├── config.py                  ← Pydantic Settings (env-driven)
│   ├── routers/
│   │   └── predict.py             ← /api/v1/predict · /health · /reload-model
│   ├── services/
│   │   └── model_service.py       ← Inference + dependency injection
│   ├── schemas/
│   │   └── prediction_schema.py   ← Pydantic v2 request/response models
│   └── utils/
│       └── feature_engineering.py ← URLFeatureExtractor + build_pipeline()
├── models/
│   ├── phishing_v1.pkl            ← Current model (copy from legacy)
│   └── phishing_v2.pkl            ← Retrained model (from training/train.py)
├── training/
│   ├── train.py                   ← Multi-model benchmark + versioned saving
│   └── evaluate.py                ← Standalone evaluation + ASCII metrics
├── experiments/                   ← JSON logs per training run
├── Dataset/
│   └── phishing_site_urls.csv
├── chrome-extension/
│   ├── manifest.json              ← MV3 + storage permission
│   ├── background.js              ← Tab listener + API call + badge
│   ├── popup.html                 ← Dark UI with risk color coding
│   └── popup.js                  ← Confidence bar + risk display
├── Dockerfile                     ← Multi-stage production image
├── gunicorn_config.py
├── requirements.txt               ← Pinned versions
└── .env.example
```

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
```

### 2. Copy legacy model to versioned path
```bash
# Windows
copy phishing.pkl models\phishing_v1.pkl

# Linux / macOS
cp phishing.pkl models/phishing_v1.pkl
```

### 3. Configure environment
```bash
copy .env.example .env       # Windows
# Edit .env: set MODEL_VERSION=v1
```

### 4. Start the API
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Open: http://127.0.0.1:8000/docs

---

## 🔌 API Reference

### `POST /api/v1/predict`
```json
// Request
{ "url": "https://secure-login-verify.xyz/paypal?update=1" }

// Response
{
  "url": "https://secure-login-verify.xyz/paypal?update=1",
  "prediction": "phishing",
  "label": 1,
  "confidence": 0.9231,
  "risk_level": "HIGH",
  "model_version": "v1",
  "latency_ms": 14.3
}
```

### `GET /health`
```json
{ "status": "healthy", "model_loaded": true, "model_version": "v1", "app_env": "development" }
```

### `POST /reload-model`
Hot-reloads the model without server restart (useful after retraining).

---

## 🧪 Train a Better Model

```bash
# Benchmarks LR · Random Forest · Gradient Boosting · Linear SVM · XGBoost
python -m training.train

# Evaluate saved model
python -m training.evaluate --model models/phishing_v2.pkl

# Switch to new model — update .env
MODEL_VERSION=v2
# Then hit /reload-model or restart
```

---

## 🐳 Docker

```bash
# Build
docker build -t phishing-detector .

# Run
docker run -p 8000:8000 \
  -e MODEL_VERSION=v1 \
  -v $(pwd)/models:/app/models \
  phishing-detector
```

---

## 🔧 Chrome Extension Setup

1. Open `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select the `chrome-extension/` folder

The popup shows:
- ✅ **SAFE** (green) with confidence %
- ⚠️ **PHISHING** (red/orange/yellow) with risk level HIGH / MEDIUM / LOW
- Model version and latency

---

## ☁️ Deployment

### Render / Railway (Free Tier)
```bash
# render.yaml / railway.toml — set start command:
gunicorn app.main:app --config gunicorn_config.py

# Environment variables (set in dashboard):
MODEL_VERSION=v1
APP_ENV=production
LOG_LEVEL=INFO
```

### CI/CD (GitHub Actions — suggested)
```yaml
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker build -t phishing-detector .
      - run: docker push your-registry/phishing-detector
```

---

## 🔐 Security Notes

| Risk | Mitigation |
|------|-----------|
| Pickle arbitrary code execution | Export model with `skops` or ONNX in production |
| Large payload attacks | `MAX_REQUEST_BODY_BYTES=8192` limit middleware |
| Rate abuse | Add Nginx rate limiting or use Redis + `slowapi` |
| Open CORS | Set `ALLOWED_ORIGINS=https://yourapp.com` in production |

---

## 📊 Monitoring

- **Structured logs** — every request logged with method, path, status, latency
- **Confidence logging** — every prediction includes probability score
- **Prometheus** — uncomment `prometheus-fastapi-instrumentator` in `main.py`
- **Drift detection** — compare live confidence distributions vs training baseline

---

## 📋 Execution Order

1. `pip install -r requirements.txt`
2. `copy phishing.pkl models\phishing_v1.pkl` (or retrain with `python -m training.train`)
3. `copy .env.example .env` and set `MODEL_VERSION`
4. `uvicorn app.main:app --reload`
5. Test: `curl http://127.0.0.1:8000/health`
6. Load Chrome extension from `chrome-extension/`
