# Phishing Detection System — Project Walkthrough

This guide explains how to use, maintain, and retrain the phishing detection system.

---

## 🌓 1. Which Model to Use?

The system contains two distinct models in the `models/` directory. You can switch between them by changing `MODEL_VERSION` in your **`.env`** file.

### � `phishing_deep_clean_v1.pkl` (Primary / Recommended) 🚀
*   **Active in `.env` as:** `MODEL_VERSION=clean_v1`
*   **Best for:** High-accuracy detection and modern "deep-path" phishing URLs.
*   **Dataset:** PhiUSIIL Dataset (235,795 URLs).
*   **Why use it:** This is the most robust model. It was trained on 4x more data and utilizes the corrected label mapping. It is more resilient to complex URL patterns.

### � `phishing_deep_v1.pkl` (Original / Legacy)
*   **Active in `.env` as:** `MODEL_VERSION=v1`
*   **Best for:** General purpose detection on simpler datasets.
*   **Dataset:** Original project dataset (~50k URLs).
*   **Why use it:** Use this if you want to maintain behavior identical to the earlier stages of the project.

> **💡 How to check which model is active?**
> Visit the dashboard and scroll to **Model Performance**. The "Model File" field will explicitly show which `.pkl` is currently loaded.

---

## 🏃 2. Everyday Usage

### Start the API
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Access the dashboard at **`http://127.0.0.1:8000`**.

### Use the Chrome Extension
1. Go to `chrome://extensions`.
2. Enable "Developer mode".
3. "Load unpacked" and select the `chrome-extension/` folder.
4. Pin the SafeSurf icon. It will turn red when you visit a phishing site.

---

## 🔄 3. Maintenance & Retraining

If you want to update the model with new data, follow the **3-Phase Retraining Pipeline**:

### Phase 1: Refresh the training data
Run the feature extractor on your raw URL dataset.
```bash
python -m training.generate_training_dataset
```
*   **Action:** Extracts 111 features from `Dataset/PhiUSIIL_Phishing_URL_Dataset.csv`.
*   **Speed:** Uses 40 threads and domain caching.

### Phase 2: Train the XGBoost model
```bash
python -m training.train_deep_clean
```
*   **Action:** Trains an XGBoost classifier with Isotonic Calibration.
*   **Result:** Saves `models/phishing_deep_clean_v1.pkl` and updates metrics.

### Phase 3: Sanity Check
```bash
python -m training.validate_clean_model
```
*   **Action:** Runs the new model against high-traffic safe sites (google.com, wikipedia.org) to ensure no false positives.

---

## 🛠️ 4. Project Organization

| Directory | Purpose |
|---|---|
| `app/routers/` | API endpoints (`analyze`, `metrics`, `health`). |
| `app/services/` | Core logic: `dns_guard` (NXDOMAIN blocker), `model_service` (Inference). |
| `app/utils/` | `deep_feature_extractor`: 111 Lexical + Infra signals. |
| `chrome-extension/` | Browser security plugin files. |
| `models/` | Trained model bundles (`.pkl`) and feature lists. |
| `templates/` | **Dashboard UI:** The frontend you see on the homepage. |

---

## 🛡️ 5. How Detection Works (The 3 Layers)

1.  **DNS Guard (Deterministic):** Before the ML runs, it checks if the domain actually exists. If it returns NXDOMAIN, the URL is blocked immediately as "Invalid".
2.  **Feature Extraction:** 111 numeric signals are extracted (e.g., length of domain, number of slashes, SSL certificate validity, domain age).
3.  **ML Inference:** XGBoost analyzes the patterns. If the probability is > 85%, it flags it as **High Risk**.
## 🏁 6. Quick Verification

After setting up, verify your system by running these checks:

1. **Health Check:** `curl http://127.0.0.1:8000/health` → Should show `healthy`.
2. **Metrics:** `curl http://127.0.0.1:8000/api/v1/metrics` → Should show accuracy > 85%.
3. **Live Scan:** Submit `https://google.com` on the dashboard. It should return **SAFE** in < 2 seconds.
4. **DNS Guard Scan:** Submit `https://this-domain-does-not-exist-xyz123.com`. It should return **INVALID** immediately.
