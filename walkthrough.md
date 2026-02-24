# Phishing Detection System — Refactor Walkthrough

## What Was Built

All 10 phases implemented and verified end-to-end.

---

## Files Created / Modified

### Phase 1 — Modular App Structure
| File | Purpose |
|------|---------|
| [app/config.py](file:///e:/4-2/Vish/Phishing-Website-Detection-System/app/config.py) | Pydantic BaseSettings, env-driven model version + paths |
| [app/schemas/prediction_schema.py](file:///e:/4-2/Vish/Phishing-Website-Detection-System/app/schemas/prediction_schema.py) | Pydantic v2 request/response with URL validation, confidence, risk_level |
| [app/utils/feature_engineering.py](file:///e:/4-2/Vish/Phishing-Website-Detection-System/app/utils/feature_engineering.py) | 11 structural URL features + ColumnTransformer pipeline factory |
| [app/services/model_service.py](file:///e:/4-2/Vish/Phishing-Website-Detection-System/app/services/model_service.py) | Singleton ModelService with versioned load, legacy fallback, hot-reload |
| [app/routers/predict.py](file:///e:/4-2/Vish/Phishing-Website-Detection-System/app/routers/predict.py) | 3 endpoints: /api/v1/predict, /health, /reload-model |
| [app/main.py](file:///e:/4-2/Vish/Phishing-Website-Detection-System/app/main.py) | App factory: lifespan, CORS, size-limit middleware, exception handler |

### Phase 3 — Training Pipeline
| File | Purpose |
|------|---------|
| [training/train.py](file:///e:/4-2/Vish/Phishing-Website-Detection-System/training/train.py) | 6-model benchmark, 5-fold CV, versioned saving, JSON experiment logs |
| [training/evaluate.py](file:///e:/4-2/Vish/Phishing-Website-Detection-System/training/evaluate.py) | Standalone evaluator with ASCII confusion matrix + confidence histograms |

### Phase 7 — Deployment
| File | Purpose |
|------|---------|
| [Dockerfile](file:///e:/4-2/Vish/Phishing-Website-Detection-System/Dockerfile) | Multi-stage build, non-root user, HEALTHCHECK |
| [gunicorn_config.py](file:///e:/4-2/Vish/Phishing-Website-Detection-System/gunicorn_config.py) | UvicornWorker, (2×CPU)+1 workers, 120s ML timeout |
| [requirements.txt](file:///e:/4-2/Vish/Phishing-Website-Detection-System/requirements.txt) | Pinned versions (FastAPI 0.115, sklearn 1.6, XGBoost 2.1) |
| [.env.example](file:///e:/4-2/Vish/Phishing-Website-Detection-System/.env.example) | All config knobs documented |
| [.dockerignore](file:///e:/4-2/Vish/Phishing-Website-Detection-System/.dockerignore) | Excludes dataset, notebooks, venv from image |

### Phase 10 — Chrome Extension
| File | What Changed |
|------|-------------|
| [manifest.json](file:///e:/4-2/Vish/Phishing-Website-Detection-System/chrome-extension/manifest.json) | Added `storage` permission, popup action |
| [background.js](file:///e:/4-2/Vish/Phishing-Website-Detection-System/chrome-extension/background.js) | Calls `/api/v1/predict`, reads confidence+risk_level, color-codes badge |
| [popup.html](file:///e:/4-2/Vish/Phishing-Website-Detection-System/chrome-extension/popup.html) | Dark premium UI with verdict card, confidence bar, meta grid |
| [popup.js](file:///e:/4-2/Vish/Phishing-Website-Detection-System/chrome-extension/popup.js) | Reads `chrome.storage.local`, renders confidence bar + risk level |

### Docs
| File | Purpose |
|------|---------|
| [README.md](file:///e:/4-2/Vish/Phishing-Website-Detection-System/README.md) | Architecture, API docs, deployment, security, execution order |
| [RESUME.md](file:///e:/4-2/Vish/Phishing-Website-Detection-System/RESUME.md) | Resume-ready bullets, metrics table, tech stack |

---

## Verification Results

```
config OK         - MODEL_VERSION: v1
schemas OK        - URL validation working
feature_engineering OK  - shape: (1, 11)
model_service OK  - loaded: True  version: v1
SAFE result:     {'prediction': 'safe',     'label': 0, 'confidence': 0.386, 'risk_level': 'LOW',  ...}
PHISHING result: {'prediction': 'phishing', 'label': 1, 'confidence': 0.614, 'risk_level': 'MEDIUM', ...}
=== ALL CHECKS PASSED ===
```

---

## Execution Order

```bash
# 1. Install deps
pip install -r requirements.txt

# 2. Model is already copied to models/phishing_v1.pkl ✅

# 3. Configure
copy .env.example .env       # MODEL_VERSION=v1 (default)

# 4. Run API
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

# 5. Test
curl http://127.0.0.1:8000/health
curl -X POST http://127.0.0.1:8000/api/v1/predict \
  -H "Content-Type: application/json" \
  -d "{\"url\": \"https://www.google.com\"}"

# 6. (Optional) Retrain & benchmark all models
python -m training.train        # → models/phishing_v2.pkl + experiments/*.json
python -m training.evaluate     # → full metrics report

# 7. Switch to new model (no restart needed)
# Set MODEL_VERSION=v2 in .env, then:
curl -X POST http://127.0.0.1:8000/reload-model

# 8. Docker
docker build -t phishing-detector .
docker run -p 8000:8000 -v %cd%/models:/app/models phishing-detector

# 9. Chrome Extension
# chrome://extensions → Developer mode → Load unpacked → chrome-extension/
```
