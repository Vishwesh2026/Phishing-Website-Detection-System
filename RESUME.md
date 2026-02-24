# 📄 Resume Project Description

## Phishing Website Detection System — ML-Powered SaaS API

**Role:** ML Engineer + Backend Architect  
**Stack:** Python · FastAPI · scikit-learn · XGBoost · Docker · Chrome Extension (MV3)

---

### Project Description (One-liner)

> Built a production-grade REST API and browser extension that detects phishing URLs in real-time using a custom ML pipeline combining TF-IDF, character n-grams, and 11 structural URL features — achieving **96%+ F1-score** on 550K+ URLs.

---

### Bullet Points for Resume

- **Designed modular SaaS architecture** for a URL phishing detection system using FastAPI with clean layering (routers → services → schemas → utils), dependency injection, and config-driven model versioning via Pydantic `BaseSettings`

- **Built an advanced ML feature pipeline** with `sklearn.pipeline.Pipeline` + `ColumnTransformer` combining word-level TF-IDF (30K features), character n-gram TF-IDF (3-5 grams, 20K features), and 11 hand-crafted structural URL features (Shannon entropy, IP detection, subdomain depth, suspicious keyword matching) via a custom `URLFeatureExtractor` transformer

- **Conducted multi-model benchmarking** across Logistic Regression, Random Forest, Gradient Boosting, Linear SVM, and XGBoost with 5-fold stratified cross-validation; selected best model by F1-score with all experiment results logged as JSON to `experiments/`

- **Implemented production hardening**: request-size limit middleware (8 KB cap), strict URL validation with `urllib.parse`, structured JSON request logging with latency tracking, global exception handler, CORS configuration, and graceful model degradation on startup failure

- **Containerised with Docker** using a multi-stage build (builder + slim runtime), non-root user security, HEALTHCHECK, and Gunicorn/UvicornWorker launch with CPU-proportional worker count

- **Upgraded Chrome extension** (Manifest V3) with confidence score display, risk-level color coding (HIGH/MEDIUM/LOW), animated progress bar, background service worker, and `chrome.storage.local` caching to avoid redundant API calls

- **Addressed ML production concerns**: model versioning (v1/v2 via env vars), hot-reload endpoint (`POST /reload-model`), class imbalance handling (`class_weight='balanced'`), deduplication to prevent data leakage, and guidance on migrating from `pickle` to `skops`/ONNX for safe model serialisation

---

### Key Metrics

| Metric | Value |
|--------|-------|
| Dataset Size | ~550,000 URLs |
| Best Model F1 | 96%+ |
| Inference Latency | ~10–30 ms |
| API Endpoints | 3 (`/predict`, `/health`, `/reload-model`) |
| Chrome Extension | Manifest V3, real-time badge + popup |
| Docker Image | Multi-stage slim, non-root |

---

### Tech Stack

`Python 3.11` · `FastAPI 0.115` · `Pydantic v2` · `scikit-learn 1.6` · `XGBoost 2.1` · `pandas` · `joblib` · `Docker` · `Gunicorn/Uvicorn` · `Chrome Extension MV3` · `GitHub Actions` (CI/CD suggestion)
